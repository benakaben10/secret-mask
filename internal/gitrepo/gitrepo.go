// Package gitrepo reads what is staged in a git repository and manages the secret-mask block in its
// pre-commit hook. It runs the git executable.
package gitrepo

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/benakaben10/secret-mask/internal/fsutil"
)

// Repo is a git work tree.
type Repo struct {
	Root     string // top-level directory of the work tree
	HooksDir string // where git looks for hooks (honors core.hooksPath)
}

// ErrNotRepo means the directory is not inside a git work tree.
var ErrNotRepo = errors.New("not a git repository")

// Find returns the repository that contains dir.
func Find(dir string) (*Repo, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if _, err := exec.LookPath("git"); err != nil {
		return nil, errors.New("git is not installed")
	}
	out, err := git(abs, nil, "rev-parse", "--show-toplevel", "--git-path", "hooks")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", abs, ErrNotRepo)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != 2 || lines[0] == "" {
		// A bare repository has no top level; it has no commits made from a work tree either.
		return nil, fmt.Errorf("%s: %w (or a bare one)", abs, ErrNotRepo)
	}
	hooks := lines[1]
	if !filepath.IsAbs(hooks) {
		hooks = filepath.Join(abs, hooks) // --git-path is relative to the directory git ran in
	}
	return &Repo{Root: filepath.Clean(lines[0]), HooksDir: filepath.Clean(hooks)}, nil
}

// File is a staged regular file.
type File struct {
	Path string // slash-separated, relative to Root
	Data []byte // staged content (the index), not the work tree
}

// Staged returns the staged content of every added, copied, modified or type-changed regular file.
// Symlinks and submodules are skipped: they hold no file content of their own.
func (r *Repo) Staged() ([]File, error) {
	out, err := git(r.Root, nil, "diff", "--cached", "--raw", "-z", "--no-abbrev", "--no-renames", "--no-ext-diff", "--diff-filter=d")
	if err != nil {
		return nil, err
	}
	// Records are ":<old mode> <new mode> <old sha> <new sha> <status>\0<path>\0".
	fields := strings.Split(string(out), "\x00")
	var files []File
	var shas []string
	for i := 0; i+1 < len(fields); i += 2 {
		meta := strings.Fields(strings.TrimPrefix(fields[i], ":"))
		if len(meta) != 5 {
			return nil, fmt.Errorf("unexpected git diff output %q", fields[i])
		}
		if mode := meta[1]; mode != "100644" && mode != "100755" {
			continue
		}
		files = append(files, File{Path: fields[i+1]})
		shas = append(shas, meta[3])
	}
	if len(files) == 0 {
		return nil, nil
	}
	blobs, err := r.blobs(shas)
	if err != nil {
		return nil, err
	}
	for i := range files {
		files[i].Data = blobs[i]
	}
	return files, nil
}

// blobs reads objects with one `git cat-file --batch`.
func (r *Repo) blobs(shas []string) ([][]byte, error) {
	out, err := git(r.Root, strings.NewReader(strings.Join(shas, "\n")+"\n"), "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	rd := bufio.NewReader(bytes.NewReader(out))
	blobs := make([][]byte, len(shas))
	for i, sha := range shas {
		header, err := rd.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("git cat-file: %w", err)
		}
		h := strings.Fields(header)
		if len(h) != 3 || h[0] != sha || h[1] != "blob" {
			return nil, fmt.Errorf("git cat-file: unexpected header %q", header)
		}
		size, err := strconv.Atoi(h[2])
		if err != nil {
			return nil, fmt.Errorf("git cat-file: %w", err)
		}
		blobs[i] = make([]byte, size+1) // content + "\n"
		if _, err := io.ReadFull(rd, blobs[i]); err != nil {
			return nil, fmt.Errorf("git cat-file: %w", err)
		}
		blobs[i] = blobs[i][:size]
	}
	return blobs, nil
}

// Add stages the work-tree content of paths (relative to Root).
func (r *Repo) Add(paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	_, err := git(r.Root, nil, append([]string{"add", "--"}, paths...)...)
	return err
}

func git(dir string, stdin io.Reader, args ...string) ([]byte, error) {
	// #nosec G204 -- always the git executable, with arguments built in this package; no shell is involved.
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Stdin = stdin
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// ── pre-commit hook ──────────────────────────────────────────────────────

const (
	blockStart = "# >>> secret-mask >>>"
	blockEnd   = "# <<< secret-mask <<<"
)

var shellShebang = regexp.MustCompile(`^#!\s*(/usr/bin/env\s+)?\S*/?(sh|bash|zsh|dash|ksh)\b`)

// Modes of the pre-commit hook.
var Modes = map[string]string{
	"block": "staged files with unmasked secrets stop the commit",
	"mask":  "staged files with unmasked secrets are masked (password from $SECRET_MASK_PASSWORD or the terminal) and re-staged",
}

// InstallHook writes the secret-mask block into the pre-commit hook, replacing an earlier one. command
// is the shell command line that runs secret-mask; its failure (including "command not found") blocks
// the commit. An existing hook keeps its content: the block goes right after its shebang so it runs
// first. A hook that is not a shell script is left alone. It returns the hook path and whether it changed.
func (r *Repo) InstallHook(command, mode string) (string, bool, error) {
	line := command + " pre-commit --mode " + mode + " || exit 1"
	block := blockStart + "\n" +
		"# Added by `secret-mask protect`; remove it with `secret-mask protect --remove`.\n" +
		"# Mode " + mode + ": " + Modes[mode] + ".\n" +
		line + "\n" + blockEnd + "\n"
	path := filepath.Join(r.HooksDir, "pre-commit")
	old, err := os.ReadFile(filepath.Clean(path))
	var content string
	switch {
	case errors.Is(err, os.ErrNotExist):
		content = "#!/bin/sh\n" + block
	case err != nil:
		return path, false, err
	default:
		before, after, found := cutBlock(string(old))
		switch {
		case found:
			content = before + block + after
		case shellShebang.MatchString(string(old)):
			shebang, rest, _ := strings.Cut(string(old), "\n")
			content = shebang + "\n" + block + rest
		default:
			return path, false, fmt.Errorf("%s is not a shell script; make it run this command yourself:\n  %s", path, line)
		}
	}
	changed := content != string(old)
	if changed {
		if err := os.MkdirAll(r.HooksDir, 0o750); err != nil {
			return path, false, err
		}
		if err := fsutil.WriteFileAtomic(path, []byte(content), 0o755); err != nil {
			return path, false, err
		}
	}
	// git ignores a hook that is not executable.
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o111 != 0o111 {
		changed = true
		if err := os.Chmod(path, st.Mode().Perm()|0o111); err != nil {
			return path, false, err
		}
	}
	return path, changed, nil
}

// RemoveHook cuts the secret-mask block out of the pre-commit hook, deleting the hook when nothing but
// a shebang is left.
func (r *Repo) RemoveHook() (string, bool, error) {
	path := filepath.Join(r.HooksDir, "pre-commit")
	old, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return path, false, nil
	}
	if err != nil {
		return path, false, err
	}
	before, after, found := cutBlock(string(old))
	if !found {
		return path, false, nil
	}
	rest := before + after
	if body := strings.TrimSpace(rest); body == "" || (shellShebang.MatchString(body) && !strings.Contains(body, "\n")) {
		return path, true, os.Remove(path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return path, false, err
	}
	return path, true, fsutil.WriteFileAtomic(path, []byte(rest), st.Mode().Perm())
}

// HookMode returns the mode of the installed secret-mask block, or "" when there is none.
func (r *Repo) HookMode() string {
	old, err := os.ReadFile(filepath.Join(r.HooksDir, "pre-commit"))
	if err != nil {
		return ""
	}
	_, _, found := cutBlock(string(old))
	if !found {
		return ""
	}
	if m := regexp.MustCompile(`pre-commit --mode (\w+)`).FindStringSubmatch(string(old)); m != nil {
		return m[1]
	}
	return ""
}

func cutBlock(s string) (before, after string, found bool) {
	i := strings.Index(s, blockStart)
	if i < 0 {
		return s, "", false
	}
	j := strings.Index(s[i:], blockEnd)
	if j < 0 {
		return s, "", false
	}
	k := i + j + len(blockEnd)
	if k < len(s) && s[k] == '\n' {
		k++
	}
	return s[:i], s[k:], true
}
