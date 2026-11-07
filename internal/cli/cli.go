// Package cli implements the secret-mask command line.
package cli

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/benakaben10/secret-mask/internal/detect"
	"github.com/benakaben10/secret-mask/internal/fsutil"
	"github.com/benakaben10/secret-mask/internal/guide"
	"github.com/benakaben10/secret-mask/internal/mask"
	"github.com/benakaben10/secret-mask/internal/vault"
	"github.com/benakaben10/secret-mask/internal/version"
)

const (
	DefaultVault       = ".secret-mask.vault"
	DefaultPasswordEnv = "SECRET_MASK_PASSWORD"
	MinPasswordLen     = 8
)

// Exit codes.
const (
	ExitOK      = 0
	ExitError   = 1
	ExitUsage   = 2
	ExitMissing = 3 // placeholders missing or altered
	ExitFound   = 4 // `check` found unmasked secrets
	ExitForeign = 5 // `mask` refused: the tree is already masked with another vault
)

const usage = `secret-mask %s — mask secrets (detected with embedded gitleaks %s) and restore them with a password.

Usage:
  secret-mask mask    [flags] [dir]    replace detected secrets with placeholders, encrypt the originals into a vault
  secret-mask restore [flags] [dir]    put the original values back (needs the password)
  secret-mask status  [flags] [dir]    check that every placeholder is still present (no password)
  secret-mask reveal  [flags] [dir]    show the real value behind each placeholder and where it is (your own
                                       terminal only: never for AI agents)
  secret-mask check   [flags] [path]   fail (exit 4) if path contains unmasked secrets (no password)
  secret-mask install   [flags]        set up every detected coding agent (Claude Code, Codex, Gemini, Cursor,
                                       VS Code, Copilot CLI): MCP server, read-blocking hook, skill, instructions
  secret-mask uninstall [flags]        remove what install wrote
  secret-mask rules   [flags] [dir]    list the detection rules in use (--id ID for one rule in full, --json)
  secret-mask protect [flags] [dir]    install a git pre-commit hook in the repository containing dir:
                                       --mode block (default) refuses commits with unmasked secrets,
                                       --mode mask masks them and re-stages; --remove uninstalls it
  secret-mask pre-commit [--mode M]    the pre-commit check itself (scans the staged content)
  secret-mask setup   [flags] [dir]    install the Claude Code read hook and MCP server for one project
  secret-mask hook    [--client C]     agent pre-tool hook (reads the hook JSON on stdin)
  secret-mask mcp     [flags]          MCP server on stdio (read-only tools)
  secret-mask upgrade [--version TAG]  how to upgrade this installation to a new release
  secret-mask completion [bash|zsh]    print the shell completion script; --install adds it to ~/.bashrc or
                                       ~/.zshrc, --uninstall removes it
  secret-mask version

Password: --ask prompts on the terminal; otherwise it is read from $%s (or the variable named by
--password-env), and prompted on the terminal when that variable is empty.
Run "secret-mask <command> -h" for the flags of a command.
`

// App runs the CLI. Its fields are the process environment, swappable in tests.
type App struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	ReadPassword   func(confirm bool) (string, error)
	Executable     func() (string, error)
	IsTerminal     func() bool // stdin and stdout are an interactive terminal
}

// New returns an App wired to the real process environment.
func New() *App {
	return &App{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Getenv: os.Getenv, ReadPassword: PromptPassword, Executable: os.Executable,
		IsTerminal: func() bool { return isCharDevice(os.Stdin) && isCharDevice(os.Stdout) },
	}
}

// Run executes args (without the program name) and returns the exit code.
func (a *App) Run(args []string) int {
	if len(args) == 0 {
		a.usage(a.Stderr)
		return ExitUsage
	}
	ctx := context.Background()
	var err error
	switch args[0] {
	case "mask":
		err = a.mask(ctx, args[1:])
	case "restore":
		err = a.restore(args[1:])
	case "status":
		err = a.status(args[1:])
	case "check":
		err = a.check(ctx, args[1:])
	case "install":
		err = a.install(args[1:], true)
	case "uninstall":
		err = a.install(args[1:], false)
	case "rules":
		err = a.rules(args[1:])
	case "upgrade":
		err = a.upgrade(args[1:])
	case "completion":
		err = a.completion(args[1:])
	case "reveal":
		err = a.reveal(args[1:])
	case "protect":
		err = a.protect(args[1:])
	case "pre-commit":
		err = a.preCommit(ctx, args[1:])
	case "setup":
		err = a.setup(args[1:])
	case "hook":
		err = a.hook(ctx, args[1:])
	case "mcp":
		err = a.mcp(ctx, args[1:])
	case "version", "--version":
		fmt.Fprintf(a.Stdout, "secret-mask %s (gitleaks %s)\n", version.Version, GitleaksVersion())
	case "help", "-h", "--help":
		a.usage(a.Stdout)
	default:
		fmt.Fprintf(a.Stderr, "unknown command %q\n\n", args[0])
		a.usage(a.Stderr)
		return ExitUsage
	}
	return a.exitCode(err)
}

func (a *App) usage(w io.Writer) {
	fmt.Fprintf(w, usage, version.Version, GitleaksVersion(), DefaultPasswordEnv)
}

func (a *App) exitCode(err error) int {
	var missing *mask.MissingError
	var uerr *UsageError
	var found *FoundError
	var foreign *mask.ForeignError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return ExitOK
	case errors.As(err, &uerr):
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitUsage
	case errors.As(err, &missing):
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitMissing
	case errors.As(err, &found):
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitFound
	case errors.As(err, &foreign):
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitForeign
	default:
		fmt.Fprintln(a.Stderr, "error:", err)
		return ExitError
	}
}

// GitleaksVersion is the embedded gitleaks module version.
func GitleaksVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/zricethezav/gitleaks/v8" {
				return d.Version
			}
		}
	}
	return "unknown"
}

// UsageError is a bad invocation (exit code 2).
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

// FoundError reports unmasked secrets (exit code 4).
type FoundError struct{ N int }

func (e *FoundError) Error() string {
	return fmt.Sprintf("%d unmasked secret(s); run `secret-mask mask` before sharing these files", e.N)
}

// target holds the flags every directory command shares.
type target struct {
	dir, vault, guide, passwordEnv, config string
	ask                                    bool
}

func (t *target) register(fs *flag.FlagSet) {
	fs.StringVar(&t.vault, "vault", "", "vault file (default <dir>/"+DefaultVault+")")
	fs.StringVar(&t.guide, "guide", "", "AI guide file (default <dir>/"+guide.DefaultName+")")
	fs.StringVar(&t.passwordEnv, "password-env", DefaultPasswordEnv, "environment variable that holds the password")
	fs.BoolVar(&t.ask, "ask", false, "prompt for the password on the terminal, ignoring the environment variable")
}

func (t *target) registerConfig(fs *flag.FlagSet) {
	fs.StringVar(&t.config, "config", "", "gitleaks config (default: $GITLEAKS_CONFIG, then <dir>/.gitleaks.toml, then built-in rules)")
}

// parse accepts flags before or after the single positional argument (default ".").
func (t *target) parse(fs *flag.FlagSet, args []string) error {
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	t.dir = pos
	if st, err := os.Stat(t.dir); err != nil || !st.IsDir() {
		return &UsageError{t.dir + " is not a directory"}
	}
	if t.vault == "" {
		t.vault = filepath.Join(t.dir, DefaultVault)
	}
	if t.guide == "" {
		t.guide = filepath.Join(t.dir, guide.DefaultName)
	}
	return nil
}

// parseFlags turns flag errors (other than -h) into usage errors.
func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil && !errors.Is(err, flag.ErrHelp) {
		return &UsageError{err.Error()}
	} else if err != nil {
		return err
	}
	return nil
}

func parseInterspersed(fs *flag.FlagSet, args []string) (string, error) {
	var positional []string
	for {
		if err := parseFlags(fs, args); err != nil {
			return "", err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	switch len(positional) {
	case 0:
		return ".", nil
	case 1:
		return positional[0], nil
	default:
		return "", &UsageError{"expected at most one path, got: " + strings.Join(positional, " ")}
	}
}

// skip returns the tool's own files as dir-relative paths so they are never masked, scanned or restored.
func (t *target) skip() map[string]bool {
	s := map[string]bool{}
	for _, p := range []string{t.vault, t.guide} {
		if rel, err := filepath.Rel(t.dir, p); err == nil {
			s[filepath.ToSlash(rel)] = true
		}
	}
	return s
}

// password returns the password: prompted with --ask, else from the environment, else prompted.
// confirm asks twice (used when creating a vault).
func (a *App) password(t *target, confirm bool) (string, error) {
	if !t.ask {
		if v := a.Getenv(t.passwordEnv); v != "" {
			return v, nil
		}
	}
	return a.ReadPassword(confirm)
}

func (a *App) flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	return fs
}

func (a *App) mask(ctx context.Context, args []string) error {
	fs := a.flagSet("mask")
	var t target
	t.register(fs)
	t.registerConfig(fs)
	report := fs.String("report", "", "use an unredacted gitleaks JSON report instead of scanning")
	dryRun := fs.Bool("dry-run", false, "show what would be masked without changing files")
	if err := t.parse(fs, args); err != nil {
		return err
	}

	var findings []detect.Finding
	var err error
	if *report != "" {
		findings, err = detect.LoadReport(*report, t.dir)
	} else {
		findings, err = detect.Scan(ctx, detect.Options{Root: t.dir, Config: t.config})
	}
	if err != nil {
		return err
	}
	_, err = a.maskFindings(&t, mask.Unmasked(findings, t.skip()), *dryRun)
	return err
}

// maskFindings masks findings in t.dir into t.vault (created or extended) and writes the AI guide. It
// returns the masked files (nil for a dry run or when nothing was masked).
func (a *App) maskFindings(t *target, findings []detect.Finding, dryRun bool) (map[string]int, error) {
	// Refuse before asking for a password if the tree was masked with another vault; the manifest
	// lists the known ids in plaintext. mask.Mask checks again against the decrypted vault.
	existing, err := vault.Read(t.vault)
	known := map[string]bool{}
	if err == nil {
		for _, e := range existing.Manifest.Entries {
			known[e.ID] = true
		}
	}
	if ferr := mask.CheckForeign(t.dir, t.skip(), func(id string) bool { return known[id] }); ferr != nil {
		return nil, ferr
	}

	s := mask.NewState()
	var pw string
	switch {
	case err == nil:
		// Add to the existing vault; same password, same placeholders for known values.
		if pw, err = a.password(t, false); err != nil {
			return nil, err
		}
		p, err := vault.Open(existing, pw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.vault, err)
		}
		s = mask.FromVault(existing.Manifest, p)
	case errors.Is(err, os.ErrNotExist):
		if len(findings) == 0 {
			fmt.Fprintln(a.Stdout, "No secrets found; nothing to mask.")
			return nil, nil
		}
		if pw, err = a.password(t, true); err != nil {
			return nil, err
		}
		if len(pw) < MinPasswordLen {
			return nil, &UsageError{fmt.Sprintf("password must be at least %d characters", MinPasswordLen)}
		}
	default:
		return nil, err
	}

	res, err := mask.Mask(t.dir, findings, s, mask.Options{Skip: t.skip(), DryRun: dryRun})
	if err != nil {
		return nil, err
	}
	for _, r := range res.Skipped {
		fmt.Fprintln(a.Stdout, "skipped:", r)
	}
	verb := "Masked"
	if dryRun {
		verb = "Would mask"
	}
	fmt.Fprintf(a.Stdout, "%s %d occurrence(s) in %d file(s); the vault holds %d secret(s).\n", verb, res.Masked, len(res.Files), s.Len())
	a.printFiles(res.Files)
	if dryRun || res.Masked == 0 {
		return nil, nil
	}

	m := s.Manifest()
	v, err := vault.Seal(pw, m, s.Payload())
	if err != nil {
		return nil, err
	}
	if err := vault.Write(t.vault, v); err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(t.guide, []byte(guide.Render(m, filepath.Base(t.vault))), 0o644); err != nil {
		return nil, err
	}
	fmt.Fprintf(a.Stdout, "Vault:    %s\nAI guide: %s\nRestore:  secret-mask restore %s\n", t.vault, t.guide, t.dir)
	return res.Files, nil
}

func (a *App) restore(args []string) error {
	fs := a.flagSet("restore")
	var t target
	t.register(fs)
	force := fs.Bool("force", false, "restore the placeholders that are present even if some are missing")
	dryRun := fs.Bool("dry-run", false, "show what would be restored without changing files")
	clean := fs.Bool("clean", false, "delete the vault and the AI guide after a complete restore")
	if err := t.parse(fs, args); err != nil {
		return err
	}
	v, err := vault.Read(t.vault)
	if err != nil {
		return err
	}
	pw, err := a.password(&t, false)
	if err != nil {
		return err
	}
	p, err := vault.Open(v, pw)
	if err != nil {
		return fmt.Errorf("%s: %w", t.vault, err)
	}
	s := mask.FromVault(v.Manifest, p)
	res, err := mask.Restore(t.dir, s, mask.Options{Skip: t.skip(), Force: *force, DryRun: *dryRun})
	if err != nil {
		return fmt.Errorf("%w\nnothing was restored; put the exact placeholders back, or use --force", err)
	}
	verb := "Restored"
	if *dryRun {
		verb = "Would restore"
	}
	fmt.Fprintf(a.Stdout, "%s %d placeholder(s) in %d file(s).\n", verb, res.Restored, len(res.Files))
	a.printFiles(res.Files)
	if len(res.Identical) > 0 {
		fmt.Fprintf(a.Stdout, "Identical to the original: %d file(s).\n", len(res.Identical))
	}
	for _, f := range res.Edited {
		fmt.Fprintln(a.Stdout, "edited since masking (secrets restored, other edits kept):", f)
	}
	for _, tok := range res.Unknown {
		fmt.Fprintln(a.Stdout, "warning: placeholder not in this vault, left as is:", tok)
	}
	for _, id := range res.Missing {
		fmt.Fprintln(a.Stdout, "warning: placeholder missing, value NOT restored:", mask.Placeholder(id))
	}
	if *clean && !*dryRun && len(res.Missing) == 0 {
		for _, p := range []string{t.vault, t.guide} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		fmt.Fprintln(a.Stdout, "Removed the vault and the AI guide.")
	}
	return nil
}

func (a *App) status(args []string) error {
	fs := a.flagSet("status")
	var t target
	t.register(fs)
	if err := t.parse(fs, args); err != nil {
		return err
	}
	text, err := statusText(&t)
	fmt.Fprint(a.Stdout, text)
	return err
}

// statusText reports placeholder integrity; the error is a *mask.MissingError when some are gone.
func statusText(t *target) (string, error) {
	v, err := vault.Read(t.vault)
	if err != nil {
		return "", err
	}
	hits, err := mask.Scan(t.dir, t.skip())
	if err != nil {
		return "", err
	}
	present := map[string]bool{}
	for _, h := range hits {
		for _, id := range h.IDs() {
			present[id] = true
		}
	}
	files := map[string][]string{}
	var missing []string
	for _, e := range v.Manifest.Entries {
		files[e.ID] = e.Files
		if !present[e.ID] {
			missing = append(missing, e.ID)
		}
	}
	text := fmt.Sprintf("vault: %s (updated %s)\nsecrets: %d\nfiles with placeholders: %d\nmissing: %d\n",
		t.vault, v.Manifest.Updated, len(v.Manifest.Entries), len(hits), len(missing))
	if len(missing) > 0 {
		return text, mask.NewMissingError(missing, func(id string) []string { return files[id] })
	}
	return text, nil
}

func (a *App) check(ctx context.Context, args []string) error {
	fs := a.flagSet("check")
	var t target
	t.registerConfig(fs)
	root := fs.String("root", "", "project root for .gitleaks.toml/.gitleaksignore (default: path if a directory, else its parent)")
	path, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	findings, err := checkPath(ctx, *root, path, t.config)
	if err != nil {
		return err
	}
	fmt.Fprint(a.Stdout, describeFindings(findings))
	if len(findings) > 0 {
		return &FoundError{N: len(findings)}
	}
	return nil
}

// checkPath scans path for unmasked secrets, ignoring the tool's own files.
func checkPath(ctx context.Context, root, path, config string) ([]detect.Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if root == "" {
		root = path
		if !info.IsDir() {
			root = filepath.Dir(path)
		}
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || strings.HasPrefix(filepath.ToSlash(rel), "../") || rel == ".." {
		return nil, &UsageError{path + " is outside root " + root}
	}
	findings, err := detect.Scan(ctx, detect.Options{Root: root, Target: rel, Config: config})
	if err != nil {
		return nil, err
	}
	findings = mask.Unmasked(findings, ownFiles(findings))
	slices.SortFunc(findings, func(a, b detect.Finding) int {
		return cmp.Or(strings.Compare(a.File, b.File), cmp.Compare(a.StartLine, b.StartLine), strings.Compare(a.RuleID, b.RuleID))
	})
	return findings, nil
}

// ownFiles marks findings in secret-mask's own files (in any directory) for skipping.
func ownFiles(findings []detect.Finding) map[string]bool {
	skip := map[string]bool{}
	for _, f := range findings {
		if base := filepath.Base(f.File); base == DefaultVault || base == guide.DefaultName {
			skip[f.File] = true
		}
	}
	return skip
}

// describeFindings lists findings without secret values.
func describeFindings(findings []detect.Finding) string {
	if len(findings) == 0 {
		return "No unmasked secrets.\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d unmasked secret(s):\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(&b, "  %s:%d  %s\n", f.File, f.StartLine, f.RuleID)
	}
	return b.String()
}

func (a *App) printFiles(files map[string]int) {
	for _, f := range slices.Sorted(maps.Keys(files)) {
		fmt.Fprintf(a.Stdout, "  %-60s %d\n", f, files[f])
	}
}
