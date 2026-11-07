package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitRepo returns a harness whose dir is a fresh git repository with files written (not staged).
func gitRepo(t *testing.T, files map[string]string) *harness {
	t.Helper()
	h := newHarness(t, files)
	gitIn(t, h.dir, "init", "-q")
	return h
}

// realDir is dir as git reports it (macOS temp dirs live behind the /var symlink).
func realDir(t *testing.T, dir string) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func hookPath(h *harness) string { return filepath.Join(h.dir, ".git", "hooks", "pre-commit") }

func TestProtectInstallsHook(t *testing.T) {
	h := gitRepo(t, map[string]string{"src/main.go": "package main\n"})
	if code := h.run("protect", filepath.Join(h.dir, "src")); code != ExitOK {
		t.Fatalf("protect exit %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "Protected "+realDir(t, h.dir)) {
		t.Errorf("output: %s", h.stdout.String())
	}
	st, err := os.Stat(hookPath(h))
	if err != nil || st.Mode().Perm()&0o111 == 0 {
		t.Fatalf("hook missing or not executable: %v %v", st, err)
	}
	hook := h.read(".git/hooks/pre-commit")
	if !strings.HasPrefix(hook, "#!/bin/sh\n# >>> secret-mask >>>") || !strings.Contains(hook, "/usr/local/bin/secret-mask pre-commit --mode block || exit 1") {
		t.Errorf("hook:\n%s", hook)
	}
	if code := h.run("protect", h.dir); code != ExitOK || !strings.Contains(h.stdout.String(), "already protected") {
		t.Errorf("second protect: %s", h.stdout.String())
	}
	if code := h.run("protect", "--mode", "mask", h.dir); code != ExitOK {
		t.Fatal("protect --mode mask")
	}
	hook = h.read(".git/hooks/pre-commit")
	if strings.Count(hook, "# >>> secret-mask >>>") != 1 || !strings.Contains(hook, "--mode mask") || strings.Contains(hook, "--mode block") {
		t.Errorf("mode not replaced:\n%s", hook)
	}
	if code := h.run("protect", "--remove", h.dir); code != ExitOK {
		t.Fatal("remove")
	}
	if _, err := os.Stat(hookPath(h)); !os.IsNotExist(err) {
		t.Error("a hook that only held secret-mask should be deleted")
	}
	if code := h.run("protect", "--remove", h.dir); code != ExitOK || !strings.Contains(h.stdout.String(), "nothing changed") {
		t.Errorf("second remove: %s", h.stdout.String())
	}

	if code := h.run("protect", "--mode", "warn", h.dir); code != ExitUsage {
		t.Errorf("bad mode exit %d", code)
	}
	if code := h.run("protect", t.TempDir()); code != ExitUsage || !strings.Contains(h.stderr.String(), "not a git repository") {
		t.Errorf("no repo: exit %d %s", code, h.stderr.String())
	}
}

func TestProtectKeepsExistingHook(t *testing.T) {
	h := gitRepo(t, nil)
	own := "#!/usr/bin/env bash\nset -e\nmake lint\n"
	os.WriteFile(hookPath(h), []byte(own), 0o755)
	if code := h.run("protect", h.dir); code != ExitOK {
		t.Fatalf("protect exit %d: %s", code, h.stderr.String())
	}
	hook := h.read(".git/hooks/pre-commit")
	if !strings.HasPrefix(hook, "#!/usr/bin/env bash\n# >>> secret-mask >>>") || !strings.HasSuffix(hook, "# <<< secret-mask <<<\nset -e\nmake lint\n") {
		t.Errorf("hook:\n%s", hook)
	}
	h.run("protect", "--remove", h.dir)
	if got := h.read(".git/hooks/pre-commit"); got != own {
		t.Errorf("remove did not restore the user's hook:\n%s", got)
	}

	os.WriteFile(hookPath(h), []byte("#!/usr/bin/env python3\nprint('hi')\n"), 0o755)
	if code := h.run("protect", h.dir); code != ExitError || !strings.Contains(h.stderr.String(), "not a shell script") {
		t.Errorf("python hook: exit %d %s", code, h.stderr.String())
	}
}

func TestPreCommitBlockScansTheIndex(t *testing.T) {
	h := gitRepo(t, map[string]string{".env": "AWS_ACCESS_KEY_ID=" + awsKey + "\n", "README.md": "docs\n"})
	t.Chdir(h.dir)

	gitIn(t, h.dir, "add", "README.md")
	if code := h.run("pre-commit"); code != ExitOK {
		t.Errorf("unstaged secret must not block: exit %d %s", code, h.stderr.String())
	}
	gitIn(t, h.dir, "add", ".env")
	if code := h.run("pre-commit"); code != ExitFound {
		t.Fatalf("staged secret: exit %d %s", code, h.stderr.String())
	}
	errOut := h.stderr.String()
	for _, want := range []string{"commit blocked", ".env:1  aws-access-token", "secret-mask mask " + realDir(t, h.dir), "--no-verify"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr missing %q:\n%s", want, errOut)
		}
	}
	if strings.Contains(errOut, awsKey) {
		t.Error("the secret value is printed")
	}

	// What counts is the index: a clean staged version passes even if the work tree leaks again…
	h.write(".env", "PORT=8080\n")
	gitIn(t, h.dir, "add", ".env")
	h.write(".env", "PORT=8080\nAWS_ACCESS_KEY_ID="+awsKey+"\n")
	if code := h.run("pre-commit"); code != ExitOK {
		t.Errorf("clean index: exit %d %s", code, h.stderr.String())
	}
	// …and a leaky staged version is blocked even after the work tree was cleaned.
	gitIn(t, h.dir, "add", ".env")
	h.write(".env", "PORT=8080\n")
	if code := h.run("pre-commit"); code != ExitFound {
		t.Errorf("leaky index: exit %d", code)
	}
}

func TestPreCommitMask(t *testing.T) {
	h := gitRepo(t, map[string]string{
		".env":         "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"deploy/ci.sh": "export GITHUB_TOKEN=" + githubToken + "\n",
	})
	t.Chdir(h.dir)
	gitIn(t, h.dir, "add", ".")
	if code := h.run("pre-commit", "--mode", "mask"); code != ExitOK {
		t.Fatalf("mask mode: exit %d\n%s%s", code, h.stdout.String(), h.stderr.String())
	}
	for _, f := range []string{".env", "deploy/ci.sh"} {
		index := gitIn(t, h.dir, "show", ":"+f)
		if strings.Contains(index, awsKey) || strings.Contains(index, githubToken) || !strings.Contains(index, "__SECRET_MASK_") {
			t.Errorf("staged %s = %q", f, index)
		}
		if h.read(f) != index {
			t.Errorf("%s: work tree and index differ", f)
		}
	}
	if _, err := os.Stat(filepath.Join(h.dir, DefaultVault)); err != nil {
		t.Error("no vault written")
	}
	if code := h.run("pre-commit", "--mode", "mask"); code != ExitOK {
		t.Errorf("nothing left to mask: exit %d", code)
	}
	if code := h.run("restore", h.dir); code != ExitOK || !strings.Contains(h.read(".env"), awsKey) {
		t.Errorf("restore after a masked commit: exit %d", code)
	}
}

func TestPreCommitMaskRefusals(t *testing.T) {
	h := gitRepo(t, map[string]string{".env": "AWS_ACCESS_KEY_ID=" + awsKey + "\n"})
	t.Chdir(h.dir)

	// Partly staged: masking the work tree and re-adding it would stage the unstaged change too.
	gitIn(t, h.dir, "add", ".env")
	h.write(".env", "AWS_ACCESS_KEY_ID="+awsKey+"\nDEBUG=1\n")
	if code := h.run("pre-commit", "--mode", "mask"); code != ExitFound || !strings.Contains(h.stderr.String(), "differs from what is staged in .env") {
		t.Fatalf("partly staged: exit %d %s", code, h.stderr.String())
	}
	if !strings.Contains(h.read(".env"), awsKey) {
		t.Error("partly staged file was masked")
	}

	// Without a password the commit is blocked, nothing is written.
	gitIn(t, h.dir, "add", ".env")
	delete(h.env, DefaultPasswordEnv)
	if code := h.run("pre-commit", "--mode", "mask"); code == ExitOK || !strings.Contains(h.read(".env"), awsKey) {
		t.Errorf("no password: exit %d", code)
	}

	// Already masked with a vault that is gone: never mask a second time.
	h.env[DefaultPasswordEnv] = pw
	if code := h.run("mask", h.dir); code != ExitOK {
		t.Fatal("mask")
	}
	os.Remove(filepath.Join(h.dir, DefaultVault))
	h.write("new.env", "GITHUB_TOKEN="+githubToken+"\n")
	gitIn(t, h.dir, "add", ".")
	if code := h.run("pre-commit", "--mode", "mask"); code != ExitForeign {
		t.Errorf("foreign placeholders: exit %d %s", code, h.stderr.String())
	}
	if !strings.Contains(h.read("new.env"), githubToken) {
		t.Error("new.env was masked under a second vault")
	}
}
