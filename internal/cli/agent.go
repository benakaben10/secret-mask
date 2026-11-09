package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/benakaben10/secret-mask/internal/detect"
	"github.com/benakaben10/secret-mask/internal/guide"
	"github.com/benakaben10/secret-mask/internal/hook"
	"github.com/benakaben10/secret-mask/internal/mcp"
	"github.com/benakaben10/secret-mask/internal/setup"
	"github.com/benakaben10/secret-mask/internal/vault"
	"github.com/benakaben10/secret-mask/internal/version"
)

// hook runs as an agent's pre-tool hook: JSON on stdin, decision JSON on stdout, always exit 0.
func (a *App) hook(ctx context.Context, args []string) error {
	fs := a.flagSet("hook")
	config := fs.String("config", "", "gitleaks config (default: $GITLEAKS_CONFIG, then <project>/.gitleaks.toml)")
	client := fs.String("client", hook.Claude, "hook format: "+strings.Join(hook.Clients, ", "))
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if !slices.Contains(hook.Clients, *client) {
		return &UsageError{fmt.Sprintf("unknown --client %q (%s)", *client, strings.Join(hook.Clients, ", "))}
	}
	raw, err := io.ReadAll(a.Stdin)
	if err != nil {
		raw = nil // Evaluate denies unparseable input
	}
	own := map[string]bool{DefaultVault: true, guide.DefaultName: true}
	projectDir := cmp.Or(a.Getenv("CLAUDE_PROJECT_DIR"), a.Getenv("GEMINI_PROJECT_DIR"))
	check := func(root, rel string) ([]detect.Finding, error) {
		return checkPath(ctx, root, filepath.Join(root, rel), *config)
	}
	var event struct {
		HookEventName string `json:"hook_event_name"`
	}
	if json.Unmarshal(raw, &event) == nil && event.HookEventName == "SessionStart" {
		if out := hook.SessionOutput(*client, hook.SessionContext(raw, projectDir, check)); out != nil {
			fmt.Fprintln(a.Stdout, string(out))
		}
		return nil
	}
	d := hook.Evaluate(raw, projectDir, own, check)
	if out := hook.Output(*client, d); out != nil {
		fmt.Fprintln(a.Stdout, string(out))
	}
	return nil
}

const mcpInstructions = `secret-mask protects secrets in this project. Call next_steps at the start of a task, before indexing
the project or building a code graph with any other MCP server and before reading files: if it reports
unmasked secrets, stop, give the user the mask command it prints (it needs their password, which you never
see) and continue only once next_steps reports SAFE. When the task is done, check masking_status (missing: 0)
and give the user the restore ("unseal") commands next_steps prints. When a finding may be a local-dev or test
value rather than a real credential, call review_findings and let the user choose: mask, or allowlist it
themselves. Mock, test, example, CI and integration values you write must start with fake- (fake-db-password):
those are never reported. MANDATORY: when the project (or a masked directory) has SECRET_MASK_AI_GUIDE.md, read
that file in full before reading or editing any other file, and follow it for the whole task; masking_guide
returns the same text. Never change __SECRET_MASK_<16 hex>__ placeholders. Never run secret-mask reveal or ask the user for its output.
list_rules and get_rule show every detection rule in use; to detect a new kind of secret, try it with
test_rule, then add it with add_rule (the only tool that writes: it appends a rule to .gitleaks.toml).`

func (a *App) mcp(ctx context.Context, args []string) error {
	fs := a.flagSet("mcp")
	dir := fs.String("dir", ".", "project root the tools operate on")
	config := fs.String("config", "", "gitleaks config (default: $GITLEAKS_CONFIG, then <dir>/.gitleaks.toml)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	root, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	pathSchema := func(desc string) map[string]any {
		return map[string]any{
			"type":       "object",
			"properties": map[string]any{"path": map[string]any{"type": "string", "description": desc}},
		}
	}
	srv := &mcp.Server{
		Name: "secret-mask", Version: version.Version, Instructions: mcpInstructions,
		Tools: []mcp.Tool{
			{
				Name: "check_secrets",
				Description: "Scan a file or directory (relative to the project root, default the whole project) for secrets " +
					"that are NOT masked yet. Returns rule ids and locations only, never secret values. If anything is found, " +
					"do not read those files: ask the user to run `secret-mask mask` manually.",
				InputSchema: pathSchema("file or directory to check, relative to the project root"),
				Handler: func(ctx context.Context, raw json.RawMessage) (string, error) {
					p, err := inRoot(root, raw)
					if err != nil {
						return "", err
					}
					findings, err := checkPath(ctx, root, p, *config)
					if err != nil {
						return "", err
					}
					text := describeFindings(findings)
					if len(findings) > 0 {
						text += "Do not read these files. Ask the user to run in a terminal: secret-mask mask " + root + "\n"
					}
					return text, nil
				},
			},
			{
				Name:        "masking_status",
				Description: "Check that every placeholder recorded in the vault is still present (missing must be 0 before finishing a task).",
				InputSchema: pathSchema("masked directory, relative to the project root (default: the root)"),
				Handler: func(ctx context.Context, raw json.RawMessage) (string, error) {
					p, err := inRoot(root, raw)
					if err != nil {
						return "", err
					}
					t := &target{dir: p, vault: filepath.Join(p, DefaultVault), guide: filepath.Join(p, guide.DefaultName)}
					text, err := statusText(t)
					if err != nil {
						return text, err
					}
					return text, nil
				},
			},
			{
				Name:        "masking_guide",
				Description: "The content of SECRET_MASK_AI_GUIDE.md: rules for editing a masked project, which files contain placeholders and how they must be preserved. Read it (or the file) before touching any file of a masked project.",
				InputSchema: pathSchema("masked directory, relative to the project root (default: the root)"),
				Handler: func(ctx context.Context, raw json.RawMessage) (string, error) {
					p, err := inRoot(root, raw)
					if err != nil {
						return "", err
					}
					v, err := vault.Read(filepath.Join(p, DefaultVault))
					if err != nil {
						return "", fmt.Errorf("no vault in %s (nothing is masked there): %w", p, err)
					}
					return guide.Render(v.Manifest, DefaultVault), nil
				},
			},
		},
	}
	srv.Tools = append(srv.Tools, mcp.Tool{
		Name: "next_steps",
		Description: "Where the project stands (unmasked secrets, masked, placeholders missing) and the exact commands to give " +
			"the user: mask before any work, restore (\"unseal\") when the work is done. Call it at the start of a task, " +
			"whenever a read is BLOCKED by secret-mask, and before finishing.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		Handler: func(ctx context.Context, raw json.RawMessage) (string, error) {
			return nextSteps(ctx, root, *config)
		},
	})
	srv.Tools = append(srv.Tools, mcp.Tool{
		Name: "review_findings",
		Description: "For each unmasked secret: file, line, rule, the line with the value replaced by «redacted», a hint whether it " +
			"looks like a real credential or a local-dev/test value, and the exact allowlist the USER can add instead of " +
			"masking (.gitleaksignore entry, path, line or stopword allowlists). Use it to help the user decide; never " +
			"allowlist anything yourself.",
		InputSchema: pathSchema("file or directory to review, relative to the project root (default: the whole project)"),
		Handler: func(ctx context.Context, raw json.RawMessage) (string, error) {
			p, err := inRoot(root, raw)
			if err != nil {
				return "", err
			}
			return reviewFindings(ctx, root, *config, p)
		},
	})
	srv.Tools = append(srv.Tools, a.ruleTools(root, *config)...)
	return srv.Serve(ctx, a.Stdin, a.Stdout)
}

// inRoot resolves the optional "path" argument inside root and rejects anything outside it.
func inRoot(root string, raw json.RawMessage) (string, error) {
	var args struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}
	p := filepath.Clean(filepath.Join(root, args.Path))
	if filepath.IsAbs(args.Path) {
		p = filepath.Clean(args.Path)
	}
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(filepath.ToSlash(rel), "../") {
		return "", fmt.Errorf("%s is outside the project root %s", args.Path, root)
	}
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}

// install configures every detected coding agent (or those named by --clients) for the user.
func (a *App) install(args []string, install bool) error {
	name := map[bool]string{true: "install", false: "uninstall"}[install]
	fs := a.flagSet(name)
	clients := fs.String("clients", "", "comma-separated clients ("+strings.Join(setup.ClientIDs(), ", ")+"); default: "+
		map[bool]string{true: "every detected one", false: "all"}[install])
	dryRun := fs.Bool("dry-run", false, "show what would change without writing")
	var command *string
	var noHooks, force *bool
	if install {
		command = fs.String("command", "", `command written into the configs (default: this executable), e.g. "docker run --rm -i IMAGE"`)
		noHooks = fs.Bool("no-hooks", false, "do not install the read-blocking hooks (and remove ones installed before)")
		force = fs.Bool("force", false, "replace a skill or hook file that secret-mask did not write")
	}
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return &UsageError{name + " takes no arguments, got: " + strings.Join(fs.Args(), " ")}
	}
	home, _ := os.UserHomeDir()
	if h := a.Getenv("HOME"); h != "" {
		home = h
	}
	o := setup.InstallOptions{
		Home: home, Getenv: a.Getenv, GOOS: runtime.GOOS, DryRun: *dryRun,
		LookPath: func(n string) bool { _, err := exec.LookPath(n); return err == nil },
	}
	if *clients != "" {
		o.Clients = strings.Split(strings.ReplaceAll(*clients, " ", ""), ",")
	}
	var rep *setup.Report
	var err error
	if install {
		o.NoHooks, o.Force = *noHooks, *force
		o.Command = strings.Fields(*command)
		if len(o.Command) == 0 {
			exe, xerr := a.Executable()
			if xerr != nil {
				exe = "secret-mask"
			}
			o.Command = []string{exe}
		}
		rep, err = setup.Install(o)
	} else {
		rep, err = setup.Uninstall(o)
	}
	if rep == nil {
		return &UsageError{err.Error()}
	}
	if len(rep.Clients) == 0 {
		fmt.Fprintf(a.Stdout, "No supported coding agent found. Pick some with --clients (%s).\n", strings.Join(setup.ClientIDs(), ", "))
		return err
	}
	last := ""
	for _, c := range rep.Changes {
		if c.Client != last {
			fmt.Fprintf(a.Stdout, "%s:\n", c.Client)
			last = c.Client
		}
		fmt.Fprintf(a.Stdout, "  %-13s %s (%s)\n", c.Kind+":", c.Path, c.Status)
	}
	if install && !*dryRun && err == nil {
		fmt.Fprintln(a.Stdout, "\nRestart your coding agents to load secret-mask.")
		if slices.Contains(rep.Clients, "Codex CLI") && !*noHooks {
			fmt.Fprintln(a.Stdout, "Codex CLI: review and trust the new hook with /hooks.")
		}
	}
	return err
}

func (a *App) setup(args []string) error {
	fs := a.flagSet("setup")
	scope := fs.String("scope", "project", "project (.claude/settings.json + .mcp.json) or user (~/.claude/settings.json)")
	command := fs.String("command", "secret-mask", `command written into the config, e.g. an absolute path or "docker run ... secret-mask"`)
	dir, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	if h := a.Getenv("HOME"); h != "" {
		home = h
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	res, err := setup.Apply(setup.Options{Scope: *scope, ProjectDir: abs, HomeDir: home, Command: *command})
	if err != nil {
		return err
	}
	if len(res.Changed) == 0 {
		fmt.Fprintln(a.Stdout, "Already configured; nothing changed.")
	}
	for _, f := range res.Changed {
		fmt.Fprintln(a.Stdout, "updated:", f)
	}
	for _, n := range res.Notes {
		fmt.Fprintln(a.Stdout, "next:", n)
	}
	fmt.Fprintf(a.Stdout, "Claude Code will now run `%s hook` before %s and block files with unmasked secrets.\n", *command, hook.Matcher)
	return nil
}
