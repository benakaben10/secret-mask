package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The completion table must list exactly the flags each command accepts.
func TestCompletionMatchesFlags(t *testing.T) {
	h := newHarness(t, nil)
	for _, c := range completionCommands() {
		if c.name == "version" || c.name == "help" {
			continue
		}
		h.run(c.name, "-h")
		var real []string
		for _, line := range strings.Split(h.stderr.String(), "\n") {
			if f := strings.Fields(line); len(f) > 0 && strings.HasPrefix(line, "  -") {
				real = append(real, strings.TrimPrefix(f[0], "-"))
			}
		}
		var listed []string
		for _, f := range c.flags {
			listed = append(listed, f.name)
		}
		slices.Sort(real)
		slices.Sort(listed)
		if !slices.Equal(real, listed) {
			t.Errorf("%s: flags %v, completion lists %v", c.name, real, listed)
		}
	}
	h.run("help")
	for _, c := range completionCommands() {
		if c.name != "help" && !strings.Contains(h.stdout.String(), "secret-mask "+c.name) {
			t.Errorf("%s is completed but not in the usage", c.name)
		}
	}
}

func TestCompletionScripts(t *testing.T) {
	h := newHarness(t, nil)
	for _, shell := range completionShells {
		if code := h.run("completion", shell); code != ExitOK {
			t.Fatalf("%s: exit %d", shell, code)
		}
		script := h.stdout.String()
		for _, want := range []string{"protect", "--clients", "claude codex gemini", "block mask"} {
			if !strings.Contains(script, want) {
				t.Errorf("%s script lacks %q", shell, want)
			}
		}
		if _, err := exec.LookPath(shell); err != nil {
			continue // the syntax check needs the shell; e2e covers it in the container
		}
		f := filepath.Join(t.TempDir(), "c."+shell)
		os.WriteFile(f, []byte(script), 0o644)
		if out, err := exec.Command(shell, "-n", f).CombinedOutput(); err != nil {
			t.Errorf("%s -n: %v\n%s", shell, err, out)
		}
	}
	if code := h.run("completion", "fish"); code != ExitUsage {
		t.Errorf("fish: exit %d", code)
	}
}

func TestCompletionInstall(t *testing.T) {
	h := newHarness(t, nil)
	home := t.TempDir()
	h.env["HOME"] = home
	rc := filepath.Join(home, ".zshrc")
	os.WriteFile(rc, []byte("export EDITOR=vim\n"), 0o644)
	if code := h.run("completion", "--install", "zsh"); code != ExitOK || !strings.Contains(h.stdout.String(), "(updated)") {
		t.Fatalf("install: %d %s%s", code, h.stdout.String(), h.stderr.String())
	}
	data, _ := os.ReadFile(rc)
	if !strings.HasPrefix(string(data), "export EDITOR=vim\n\n# >>> secret-mask completion >>>") ||
		!strings.Contains(string(data), `eval "$(/usr/local/bin/secret-mask completion zsh)"`) || !strings.Contains(string(data), "compinit") {
		t.Errorf(".zshrc:\n%s", data)
	}
	if h.run("completion", "--install", "zsh"); !strings.Contains(h.stdout.String(), "(unchanged)") {
		t.Errorf("second install: %s", h.stdout.String())
	}
	h.run("completion", "--uninstall", "zsh")
	if data, _ := os.ReadFile(rc); string(data) != "export EDITOR=vim\n" {
		t.Errorf("after uninstall:\n%s", data)
	}
	h.env["SHELL"] = "/bin/bash"
	if code := h.run("completion", "--install"); code != ExitOK {
		t.Fatal("bash from $SHELL")
	}
	if data, _ := os.ReadFile(filepath.Join(home, ".bashrc")); !strings.Contains(string(data), "completion bash") {
		t.Errorf(".bashrc:\n%s", data)
	}
}
