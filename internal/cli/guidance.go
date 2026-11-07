package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/benakaben10/secret-mask/internal/guide"
	"github.com/benakaben10/secret-mask/internal/mask"
	"github.com/benakaben10/secret-mask/internal/vault"
)

var (
	devPath = regexp.MustCompile(`(?i)(?:^|/)(?:tests?|testdata|spec|__tests__|fixtures?|mocks?|examples?|samples?|demo)(?:/|$)|` +
		`(?:^|/)\.env\.(?:example|sample|template|test|dev|development|local)$|(?:^|/)docker-compose\.(?:dev|local|override|test)\.ya?ml$`)
	devHost = regexp.MustCompile(`(?i)\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal|[\w-]+\.local|example\.(?:com|org|net))\b`)
)

// reviewFindings helps an AI agent tell real credentials from local-dev or test values without seeing
// them: each finding comes with its line, the secret replaced by «redacted», a hint, and the exact ways the
// user can allowlist it. The agent does not allowlist anything itself; the user decides.
func reviewFindings(ctx context.Context, root, config, path string) (string, error) {
	findings, err := checkPath(ctx, root, path, config)
	if err != nil {
		return "", err
	}
	if len(findings) == 0 {
		return "No unmasked secrets: nothing to review.\n", nil
	}
	lines := map[string][]string{}
	for _, f := range findings {
		if _, ok := lines[f.File]; !ok {
			data, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.File)))
			lines[f.File] = strings.Split(string(data), "\n")
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d unmasked secret(s). Values are never shown. Decide with the user, one by one: a real credential is\n"+
		"masked; a value that is only for local development or tests may be allowlisted BY THE USER.\n\n", len(findings))
	for i, f := range findings {
		line := "«line not available»"
		if l := lines[f.File]; f.StartLine >= 1 && f.StartLine <= len(l) {
			line = l[f.StartLine-1]
			for _, g := range findings {
				if g.File == f.File && g.StartLine == f.StartLine && !strings.Contains(g.Secret, "\n") {
					line = strings.ReplaceAll(line, g.Secret, "«redacted»")
				}
			}
			if strings.Contains(f.Secret, "\n") {
				line = "«multi-line secret, not shown»"
			}
			if len(line) > 160 {
				line = line[:157] + "..."
			}
		}
		hint := "looks like a REAL credential: mask it"
		switch {
		case devPath.MatchString(f.File):
			hint = "may be a test/dev value (test, example or dev file); ask the user"
		case devHost.MatchString(line):
			hint = "may be a local-dev value (points to localhost / a local host); ask the user"
		}
		fmt.Fprintf(&b, "%d. %s:%d  rule %s\n   line: %s\n   hint: %s\n", i+1, f.File, f.StartLine, f.RuleID, strings.TrimSpace(line), hint)
		fmt.Fprintf(&b, "   allowlist just this finding: add to .gitleaksignore the line  %s:%s:%d\n", f.File, f.RuleID, f.StartLine)
	}
	b.WriteString(`
How to tell the user (they decide; do not edit .gitleaksignore or .gitleaks.toml yourself):
- Real credential (production, staging, shared service, personal token), or not sure: mask it.
      secret-mask mask ` + shellQuote(root) + `
- Value that only works locally and is safe for anyone to see (local Docker database, test fixture, example
  file), allowlist it, in one of these ways:
  1. One finding: add the "file:rule:line" shown above to .gitleaksignore in the project root. It stops
     matching if the line moves; add it again then.
  2. A whole dev/test file or folder, in .gitleaks.toml (paths are project-relative, use ^ to anchor):
         [[allowlists]]
         description = "local dev and test files"
         paths = ['''^docker-compose\.dev\.yml$''', '''^test/fixtures/''']
  3. Local URLs of one rule, wherever they are (the whole line is tested):
         [[allowlists]]
         description = "local dev database"
         targetRules = ["secret-mask-url-password"]
         regexTarget = "line"
         regexes = ['''@(?:localhost|127\.0\.0\.1|db)[:/]''']
  4. Known dev values (the user writes them; you never see them):
         [[allowlists]]
         description = "shared dev passwords"
         stopwords = ["devpass", "localdev"]
  Allowlisted values are never masked: agents can read them and they can be committed. Never allowlist a value
  that works anywhere but the developer's own machine. Check the result with: secret-mask check
`)
	return b.String(), nil
}

// nextSteps tells an AI agent where the project stands and exactly what to ask the user to run: mask before
// any work, restore ("unseal") when the work is done. Masking and restoring need the user's password, so
// the agent never runs them itself.
func nextSteps(ctx context.Context, root, config string) (string, error) {
	t := &target{dir: root, vault: filepath.Join(root, DefaultVault), guide: filepath.Join(root, guide.DefaultName)}
	findings, err := checkPath(ctx, root, root, config)
	if err != nil {
		return "", err
	}
	v, verr := vault.Read(t.vault)
	hasVault := verr == nil
	if verr != nil && !errors.Is(verr, os.ErrNotExist) {
		return "", verr
	}
	known := map[string]bool{}
	if hasVault {
		for _, e := range v.Manifest.Entries {
			known[e.ID] = true
		}
	}
	var b strings.Builder

	// Placeholders of a vault that is not here: neither masking nor restoring can work.
	var foreign *mask.ForeignError
	if err := mask.CheckForeign(root, t.skip(), func(id string) bool { return known[id] }); errors.As(err, &foreign) {
		fmt.Fprintf(&b, "STATE: masked with a vault that is not in %s (%d unknown placeholder(s)).\n", root, foreign.Tokens)
		b.WriteString("Do not edit the placeholders. Tell the user:\n")
		b.WriteString("  The project was masked with another vault. Copy that .secret-mask.vault into the project root\n")
		fmt.Fprintf(&b, "  (or pass it with --vault), then: secret-mask status %s\n", shellQuote(root))
		b.WriteString("Running `secret-mask mask` now would be refused (exit 5): a tree is never masked twice.\n")
		return b.String(), nil
	} else if err != nil {
		return "", err
	}

	if len(findings) > 0 {
		b.WriteString("STATE: NOT SAFE. Unmasked secrets in:\n")
		for _, f := range uniqueFiles(findings) {
			fmt.Fprintf(&b, "  %s\n", f)
		}
		b.WriteString("STOP: do not read these files and do not continue the task. Tell the user, word for word:\n\n")
		b.WriteString("  This project has unmasked secrets. Please mask them in your own terminal (it needs your password,\n")
		b.WriteString("  which I must never see):\n")
		fmt.Fprintf(&b, "      secret-mask mask %s\n", shellQuote(root))
		if hasVault {
			b.WriteString("  Use the same password as the last time: the new secrets join the existing vault.\n")
		} else {
			b.WriteString("  Choose a password of at least 8 characters and keep it: it is the only way to get the real values back.\n")
		}
		b.WriteString("  (Non-interactive: SECRET_MASK_PASSWORD=... secret-mask mask ...)\n")
		b.WriteString("  Tell me when it is done.\n\n")
		b.WriteString("When the user confirms, call next_steps (or check_secrets) again and continue only when it reports SAFE.\n")
		b.WriteString("If some of them may be local-dev or test values rather than real credentials, call review_findings: it shows\n" +
			"each line with the value redacted and how the user can allowlist it instead. The user decides.\n")
		return b.String(), nil
	}

	if !hasVault {
		b.WriteString("STATE: SAFE, nothing to mask: no secret detected and no vault.\n")
		b.WriteString("If the project holds a kind of secret the rules miss, find a rule with list_rules or add one (test_rule, then add_rule).\n")
		return b.String(), nil
	}

	text, serr := statusText(t)
	var missing *mask.MissingError
	if errors.As(serr, &missing) {
		b.WriteString("STATE: masked, but placeholders are MISSING: restore would refuse.\n")
		b.WriteString(text)
		b.WriteString(serr.Error() + "\n")
		b.WriteString("Put every missing placeholder back exactly where it was (same characters and quoting), then call next_steps again.\n")
		b.WriteString("Only if they cannot be recovered, tell the user that `secret-mask restore --force " + shellQuote(root) +
			"` restores the rest and leaves the missing values in the vault.\n")
		return b.String(), nil
	}
	if serr != nil {
		return "", serr
	}
	b.WriteString("STATE: SAFE. The project is masked; work on it and keep every __SECRET_MASK_<16 hex>__ placeholder byte-for-byte.\n")
	b.WriteString(text)
	b.WriteString("\nWhen the task is finished, call masking_status (missing must be 0), then tell the user how to unseal it:\n\n")
	b.WriteString("  Your work is ready. To put the real secrets back (\"unseal\"), run in your terminal, with your password:\n")
	fmt.Fprintf(&b, "      secret-mask status %s           # check: missing must be 0\n", shellQuote(root))
	fmt.Fprintf(&b, "      secret-mask restore --dry-run %s  # preview\n", shellQuote(root))
	fmt.Fprintf(&b, "      secret-mask restore %s          # put the real values back\n", shellQuote(root))
	fmt.Fprintf(&b, "      secret-mask restore --clean %s  # ...and delete the vault and the AI guide\n", shellQuote(root))
	b.WriteString("  After restoring, the files hold real secrets again: mask before the next AI session, and commit only\n")
	b.WriteString("  masked files (`secret-mask protect` adds a pre-commit hook that enforces it).\n\n")
	b.WriteString("Never restore or ask for the password yourself.\n")
	return b.String(), nil
}
