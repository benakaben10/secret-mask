package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/benakaben10/secret-mask/internal/detect"
	"github.com/benakaben10/secret-mask/internal/guide"
	"github.com/benakaben10/secret-mask/internal/hook"
	"github.com/benakaben10/secret-mask/internal/mcp"
	"github.com/benakaben10/secret-mask/internal/setup"
	"github.com/benakaben10/secret-mask/internal/vault"
	"github.com/benakaben10/secret-mask/internal/version"
)

// hook runs as a Claude Code PreToolUse hook: JSON on stdin, decision JSON on stdout, always exit 0.
func (a *App) hook(ctx context.Context, args []string) error {
	fs := a.flagSet("hook")
	config := fs.String("config", "", "gitleaks config (default: $GITLEAKS_CONFIG, then <project>/.gitleaks.toml)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	raw, err := io.ReadAll(a.Stdin)
	if err != nil {
		raw = nil // Evaluate denies unparseable input
	}
	own := map[string]bool{DefaultVault: true, guide.DefaultName: true}
	d := hook.Evaluate(raw, a.Getenv("CLAUDE_PROJECT_DIR"), own, func(root, rel string) ([]detect.Finding, error) {
		return checkPath(ctx, root, filepath.Join(root, rel), *config)
	})
	if out := hook.Output(d); out != nil {
		fmt.Fprintln(a.Stdout, string(out))
	}
	return nil
}

const mcpInstructions = `secret-mask protects secrets in this project. Before reading config files, call check_secrets.
If it reports unmasked secrets, stop and ask the user to run "secret-mask mask" themselves (it needs
their password). Never change __SECRET_MASK_<16 hex>__ placeholders; see masking_guide.`

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
				Description: "Rules for editing a masked project: which files contain placeholders and how they must be preserved.",
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
