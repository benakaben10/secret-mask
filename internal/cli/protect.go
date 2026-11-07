package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/benakaben10/secret-mask/internal/detect"
	"github.com/benakaben10/secret-mask/internal/gitrepo"
	"github.com/benakaben10/secret-mask/internal/guide"
	"github.com/benakaben10/secret-mask/internal/mask"
)

// protect installs (or removes) the git pre-commit hook of the repository containing dir.
func (a *App) protect(args []string) error {
	fs := a.flagSet("protect")
	mode := fs.String("mode", "block", "block: refuse commits that stage unmasked secrets; mask: mask them and re-stage the files")
	command := fs.String("command", "", "command the hook runs (default: this executable)")
	remove := fs.Bool("remove", false, "remove the secret-mask pre-commit hook")
	dir, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if _, ok := gitrepo.Modes[*mode]; !ok {
		return &UsageError{fmt.Sprintf("unknown --mode %q (block or mask)", *mode)}
	}
	repo, err := gitrepo.Find(dir)
	if errors.Is(err, gitrepo.ErrNotRepo) {
		return &UsageError{fmt.Sprintf("%v; run `git init` first or pass the repository directory", err)}
	}
	if err != nil {
		return err
	}
	if *remove {
		path, changed, err := repo.RemoveHook()
		if err != nil {
			return err
		}
		if changed {
			fmt.Fprintf(a.Stdout, "Removed the secret-mask pre-commit hook of %s (%s).\n", repo.Root, path)
		} else {
			fmt.Fprintf(a.Stdout, "%s has no secret-mask pre-commit hook; nothing changed.\n", repo.Root)
		}
		return nil
	}

	cmdLine := *command
	if cmdLine == "" {
		exe, err := a.Executable()
		if err != nil {
			exe = "secret-mask"
		}
		cmdLine = shellQuote(exe)
	}
	path, changed, err := repo.InstallHook(cmdLine, *mode)
	if err != nil {
		return err
	}
	if changed {
		fmt.Fprintf(a.Stdout, "Protected %s: pre-commit hook %s (mode %s).\n", repo.Root, path, *mode)
	} else {
		fmt.Fprintf(a.Stdout, "%s is already protected (mode %s); nothing changed.\n", repo.Root, *mode)
	}
	fmt.Fprintf(a.Stdout, "On every commit, %s.\n", gitrepo.Modes[*mode])
	if *mode == "mask" {
		fmt.Fprintf(a.Stdout, "The vault %s is not staged for you: commit it or keep it safe, it is the only way to restore.\n", DefaultVault)
	}
	return nil
}

// preCommit runs from the git pre-commit hook: it scans the staged content (not the work tree) and blocks
// the commit, or masks and re-stages, when unmasked secrets are found. Any error blocks the commit.
func (a *App) preCommit(ctx context.Context, args []string) error {
	fs := a.flagSet("pre-commit")
	mode := fs.String("mode", "block", "block or mask")
	config := fs.String("config", "", "gitleaks config (default: $GITLEAKS_CONFIG, then <repo>/.gitleaks.toml)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if _, ok := gitrepo.Modes[*mode]; !ok {
		return &UsageError{fmt.Sprintf("unknown --mode %q (block or mask)", *mode)}
	}
	repo, err := gitrepo.Find(".")
	if err != nil {
		return err
	}
	t := &target{
		dir: repo.Root, vault: filepath.Join(repo.Root, DefaultVault), guide: filepath.Join(repo.Root, guide.DefaultName),
		passwordEnv: DefaultPasswordEnv,
	}
	staged, findings, err := a.stagedFindings(ctx, repo, t, *config)
	if err != nil {
		return fmt.Errorf("secret-mask could not scan the staged files, commit blocked: %w", err)
	}
	if len(findings) == 0 {
		return nil
	}
	if *mode == "block" {
		a.blockCommit(t, findings)
		return &FoundError{len(findings)}
	}

	// Masking rewrites the work-tree file and stages it again, which is only right when the work tree
	// holds exactly what is staged; otherwise `git add` would also stage changes the user left out.
	var partial []string
	for _, f := range uniqueFiles(findings) {
		disk, err := os.ReadFile(filepath.Join(repo.Root, filepath.FromSlash(f)))
		if err != nil || string(disk) != string(staged[f]) {
			partial = append(partial, f)
		}
	}
	if len(partial) > 0 {
		a.blockCommit(t, findings)
		fmt.Fprintf(a.Stderr, "Not masked automatically: the work tree differs from what is staged in %s.\n", strings.Join(partial, ", "))
		return &FoundError{len(findings)}
	}
	fmt.Fprintf(a.Stderr, "secret-mask: %d unmasked secret(s) staged; masking them before the commit.\n", len(findings))
	masked, err := a.maskFindings(t, findings, false)
	if err != nil {
		return fmt.Errorf("commit blocked: %w", err)
	}
	if err := repo.Add(slices.Sorted(maps.Keys(masked))); err != nil {
		return fmt.Errorf("commit blocked: %w", err)
	}
	// Check what will really be committed; e.g. an encoded secret cannot be masked literally.
	if _, findings, err = a.stagedFindings(ctx, repo, t, *config); err != nil {
		return fmt.Errorf("secret-mask could not scan the staged files, commit blocked: %w", err)
	}
	if len(findings) > 0 {
		a.blockCommit(t, findings)
		return &FoundError{len(findings)}
	}
	fmt.Fprintf(a.Stderr, "secret-mask: masked and re-staged %d file(s). %s is not staged: commit it or keep it safe.\n", len(masked), DefaultVault)
	return nil
}

// stagedFindings scans the staged content of the repository. It writes the staged files into a private
// temporary directory, so the paths and line numbers in the findings are those of the index.
func (a *App) stagedFindings(ctx context.Context, repo *gitrepo.Repo, t *target, config string) (map[string][]byte, []detect.Finding, error) {
	files, err := repo.Staged()
	if err != nil || len(files) == 0 {
		return nil, nil, err
	}
	tmp, err := os.MkdirTemp("", "secret-mask-staged-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmp)
	staged := map[string][]byte{}
	for _, f := range files {
		if !filepath.IsLocal(filepath.FromSlash(f.Path)) {
			return nil, nil, fmt.Errorf("unexpected staged path %q", f.Path)
		}
		p := filepath.Join(tmp, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(p, f.Data, 0o600); err != nil {
			return nil, nil, err
		}
		staged[f.Path] = f.Data
	}
	// The scan root is the temporary copy, so the repository's own config and ignore file are passed on.
	if config == "" && a.Getenv("GITLEAKS_CONFIG") == "" {
		if p := filepath.Join(repo.Root, ".gitleaks.toml"); fileExists(p) {
			config = p
		}
	}
	if ignore := filepath.Join(repo.Root, ".gitleaksignore"); fileExists(ignore) && staged[".gitleaksignore"] == nil {
		data, err := os.ReadFile(ignore)
		if err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(filepath.Join(tmp, ".gitleaksignore"), data, 0o600); err != nil {
			return nil, nil, err
		}
	}
	findings, err := detect.Scan(ctx, detect.Options{Root: tmp, Config: config})
	if err != nil {
		return nil, nil, err
	}
	findings = slices.DeleteFunc(mask.Unmasked(findings, t.skip()), func(f detect.Finding) bool { return staged[f.File] == nil })
	slices.SortFunc(findings, func(a, b detect.Finding) int {
		return cmp.Or(strings.Compare(a.File, b.File), cmp.Compare(a.StartLine, b.StartLine), strings.Compare(a.RuleID, b.RuleID))
	})
	return staged, findings, nil
}

func (a *App) blockCommit(t *target, findings []detect.Finding) {
	fmt.Fprintf(a.Stderr, "secret-mask: commit blocked, %d unmasked secret(s) in staged files:\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(a.Stderr, "  %s:%d  %s\n", f.File, f.StartLine, f.RuleID)
	}
	fmt.Fprintf(a.Stderr, "Mask them, stage the result and commit again:\n  secret-mask mask %s && git add %s\n",
		shellQuote(t.dir), strings.Join(mapSlice(uniqueFiles(findings), shellQuote), " "))
	fmt.Fprintln(a.Stderr, "(To commit anyway, at your own risk: git commit --no-verify)")
}

func uniqueFiles(findings []detect.Finding) []string {
	var files []string
	for _, f := range findings {
		if !slices.Contains(files, f.File) {
			files = append(files, f.File)
		}
	}
	return files
}

func mapSlice(in []string, fn func(string) string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = fn(s)
	}
	return out
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// shellQuote quotes s for a POSIX shell when it holds anything but plain path characters.
func shellQuote(s string) string {
	safe := s != ""
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_@%+=:,./\\-", c)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
