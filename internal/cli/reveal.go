package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/benakaben10/secret-mask/internal/guide"
	"github.com/benakaben10/secret-mask/internal/mask"
	"github.com/benakaben10/secret-mask/internal/vault"
)

// agentEnv are variables coding agents set in the commands they run.
var agentEnv = []string{"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED", "GEMINI_CLI", "CURSOR_AGENT"}

func isCharDevice(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// reveal prints the real value behind every placeholder with where it is. It is for the user only: it needs
// an interactive terminal, always asks for the password there (the environment variable is not used), and
// refuses to run inside a coding agent. No MCP tool exposes it, and the agent hooks block it.
func (a *App) reveal(args []string) error {
	fs := a.flagSet("reveal")
	vaultPath := fs.String("vault", "", "vault file (default <dir>/"+DefaultVault+")")
	id := fs.String("id", "", "only this placeholder (the 16 hex digits, or the whole __SECRET_MASK_…__ token)")
	file := fs.String("file", "", "only placeholders in this file (relative to dir)")
	dir, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	for _, v := range agentEnv {
		if a.Getenv(v) != "" {
			return fmt.Errorf("reveal refuses to run inside a coding agent ($%s is set): it prints real secrets; run it in your own terminal", v)
		}
	}
	if a.IsTerminal == nil || !a.IsTerminal() {
		return fmt.Errorf("reveal prints real secrets, so it only runs in an interactive terminal (not piped, not from a script or an agent)")
	}
	if *vaultPath == "" {
		*vaultPath = filepath.Join(dir, DefaultVault)
	}
	v, err := vault.Read(*vaultPath)
	if err != nil {
		return err
	}
	pw, err := a.ReadPassword(false)
	if err != nil {
		return err
	}
	p, err := vault.Open(v, pw)
	if err != nil {
		return fmt.Errorf("%s: %w", *vaultPath, err)
	}
	s := mask.FromVault(v.Manifest, p)
	want := strings.TrimSuffix(strings.TrimPrefix(*id, mask.Prefix), "__")
	rules := map[string]string{}
	for _, e := range v.Manifest.Entries {
		rules[e.ID] = e.RuleID
	}
	skip := map[string]bool{}
	for _, f := range []string{*vaultPath, filepath.Join(dir, guide.DefaultName)} {
		if rel, err := filepath.Rel(dir, f); err == nil {
			skip[filepath.ToSlash(rel)] = true
		}
	}
	hits, err := mask.Scan(dir, skip)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.Stderr, "These are the REAL secrets. Do not paste them into an AI chat, a ticket or a commit.")
	present := map[string]bool{}
	shown := 0
	for _, h := range hits {
		if *file != "" && h.Rel != filepath.ToSlash(filepath.Clean(*file)) {
			continue
		}
		for n, line := range strings.Split(h.Content, "\n") {
			for _, tok := range mask.Pattern.FindAllString(line, -1) {
				pid := mask.IDOf(tok)
				present[pid] = true
				if want != "" && pid != want {
					continue
				}
				value, ok := s.Value(pid)
				if !ok {
					fmt.Fprintf(a.Stdout, "%s:%d  %s  (not in this vault)\n", h.Rel, n+1, tok)
					continue
				}
				fmt.Fprintf(a.Stdout, "%s:%d  %s  %s  %s\n", h.Rel, n+1, rules[pid], tok, showValue(value))
				shown++
			}
		}
	}
	for _, pid := range s.IDs() {
		if present[pid] || (want != "" && pid != want) || *file != "" {
			continue
		}
		value, _ := s.Value(pid)
		fmt.Fprintf(a.Stdout, "(missing)  %s  %s  %s  masked in: %s\n", rules[pid], mask.Placeholder(pid), showValue(value),
			strings.Join(s.Files(pid), ", "))
		shown++
	}
	if shown == 0 {
		fmt.Fprintln(a.Stdout, "No matching placeholder.")
	}
	return nil
}

// showValue prints a multi-line value (a private key) indented under its location.
func showValue(v string) string {
	if !strings.Contains(v, "\n") {
		return v
	}
	lines := strings.Split(strings.TrimRight(v, "\n"), "\n")
	return "\n      " + strings.Join(slices.Clip(lines), "\n      ")
}
