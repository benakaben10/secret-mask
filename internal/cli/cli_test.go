package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/benakaben10/secret-mask/internal/guide"
	"github.com/benakaben10/secret-mask/internal/mask"
	"github.com/benakaben10/secret-mask/internal/version"
)

const pw = "test-password-1"

type harness struct {
	t              *testing.T
	dir            string
	env            map[string]string
	prompted       []bool // confirm flag of each ReadPassword call
	promptAnswer   string
	stdin          string
	stdout, stderr bytes.Buffer
}

func newHarness(t *testing.T, files map[string]string) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir(), env: map[string]string{DefaultPasswordEnv: pw}}
	for rel, content := range files {
		path := filepath.Join(h.dir, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *harness) run(args ...string) int {
	h.stdout.Reset()
	h.stderr.Reset()
	app := &App{
		Stdin:  strings.NewReader(h.stdin),
		Stdout: &h.stdout,
		Stderr: &h.stderr,
		Getenv: func(k string) string { return h.env[k] },
		ReadPassword: func(confirm bool) (string, error) {
			h.prompted = append(h.prompted, confirm)
			if h.promptAnswer == "" {
				return "", errors.New("no terminal")
			}
			return h.promptAnswer, nil
		},
		Executable: func() (string, error) { return "/usr/local/bin/secret-mask", nil },
	}
	return app.Run(args)
}

func (h *harness) read(rel string) string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.dir, filepath.FromSlash(rel)))
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

func (h *harness) write(rel, content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, filepath.FromSlash(rel)), []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// report writes an unredacted gitleaks report outside the scanned dir.
func (h *harness) report(findings ...[2]string) string {
	h.t.Helper()
	var entries []map[string]any
	for _, f := range findings {
		entries = append(entries, map[string]any{"RuleID": "test-rule", "File": f[0], "Secret": f[1], "StartLine": 1})
	}
	if entries == nil {
		entries = []map[string]any{}
	}
	data, _ := json.Marshal(entries)
	path := filepath.Join(h.t.TempDir(), "report.json")
	os.WriteFile(path, data, 0o600)
	return path
}

var files = map[string]string{
	".env":            "DB_PASSWORD=Admin@123\nPORT=8080\n",
	"k8s/secret.yaml": "kind: Secret\nstringData:\n  TOKEN: tok-" + "9f8e7d6c5b4a\n",
}

func (h *harness) maskAll(extra ...string) int {
	rep := h.report([2]string{".env", "Admin@123"}, [2]string{"k8s/secret.yaml", "tok-" + "9f8e7d6c5b4a"})
	return h.run(append([]string{"mask", "--report", rep, h.dir}, extra...)...)
}

func TestMaskStatusRestore(t *testing.T) {
	h := newHarness(t, files)

	if code := h.maskAll(); code != ExitOK {
		t.Fatalf("mask exit %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "Masked 2 occurrence(s) in 2 file(s)") {
		t.Errorf("mask output: %s", h.stdout.String())
	}
	for rel, orig := range files {
		got := h.read(rel)
		if got == orig || !mask.Pattern.MatchString(got) {
			t.Errorf("%s not masked: %q", rel, got)
		}
	}
	vaultData := h.read(DefaultVault)
	if strings.Contains(vaultData, "Admin@123") || strings.Contains(vaultData, "tok-"+"9f8e7d6c5b4a") {
		t.Fatal("vault contains plaintext secrets")
	}
	g := h.read(guide.DefaultName)
	if !strings.Contains(g, "| `.env` | 1 |") || strings.Contains(g, "Admin@123") {
		t.Errorf("guide:\n%s", g)
	}

	if code := h.run("status", h.dir); code != ExitOK || !strings.Contains(h.stdout.String(), "missing: 0") {
		t.Errorf("status exit %d: %s%s", code, h.stdout.String(), h.stderr.String())
	}

	if code := h.run("restore", h.dir); code != ExitOK {
		t.Fatalf("restore exit %d: %s", code, h.stderr.String())
	}
	for rel, orig := range files {
		if got := h.read(rel); got != orig {
			t.Errorf("%s after restore = %q, want %q", rel, got, orig)
		}
	}
	if !strings.Contains(h.stdout.String(), "Identical to the original: 2 file(s)") {
		t.Errorf("restore output: %s", h.stdout.String())
	}
	if _, err := os.Stat(filepath.Join(h.dir, DefaultVault)); err != nil {
		t.Error("vault removed without --clean")
	}
}

func TestRestoreWrongPassword(t *testing.T) {
	h := newHarness(t, files)
	h.maskAll()
	masked := h.read(".env")
	h.env[DefaultPasswordEnv] = "not-the-password"
	if code := h.run("restore", h.dir); code != ExitError || !strings.Contains(h.stderr.String(), "wrong password") {
		t.Errorf("exit %d, stderr %s", code, h.stderr.String())
	}
	if h.read(".env") != masked {
		t.Error("files changed with a wrong password")
	}
}

func TestMissingPlaceholder(t *testing.T) {
	h := newHarness(t, files)
	h.maskAll()
	h.write("k8s/secret.yaml", "kind: Secret\nstringData:\n  TOKEN: changeme\n")
	masked := h.read(".env")

	if code := h.run("status", h.dir); code != ExitMissing || !strings.Contains(h.stdout.String(), "missing: 1") {
		t.Errorf("status exit %d: %s", code, h.stdout.String())
	}
	if code := h.run("restore", h.dir); code != ExitMissing || !strings.Contains(h.stderr.String(), "nothing was restored") {
		t.Errorf("restore exit %d: %s", code, h.stderr.String())
	}
	if h.read(".env") != masked {
		t.Error("restore wrote files although a placeholder is missing")
	}
	if code := h.run("restore", "--force", h.dir); code != ExitOK {
		t.Fatalf("restore --force exit %d: %s", code, h.stderr.String())
	}
	if h.read(".env") != files[".env"] || !strings.Contains(h.stdout.String(), "value NOT restored") {
		t.Errorf("--force: .env=%q out=%s", h.read(".env"), h.stdout.String())
	}
}

func TestRestoreClean(t *testing.T) {
	h := newHarness(t, files)
	h.maskAll()
	if code := h.run("restore", "--clean", h.dir); code != ExitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	for _, f := range []string{DefaultVault, guide.DefaultName} {
		if _, err := os.Stat(filepath.Join(h.dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s not removed by --clean", f)
		}
	}
}

func TestDryRuns(t *testing.T) {
	h := newHarness(t, files)
	if code := h.maskAll("--dry-run"); code != ExitOK || !strings.Contains(h.stdout.String(), "Would mask 2") {
		t.Fatalf("mask --dry-run exit %d: %s", code, h.stdout.String())
	}
	if h.read(".env") != files[".env"] {
		t.Error("mask --dry-run changed files")
	}
	if _, err := os.Stat(filepath.Join(h.dir, DefaultVault)); !errors.Is(err, os.ErrNotExist) {
		t.Error("mask --dry-run wrote a vault")
	}
	h.maskAll()
	masked := h.read(".env")
	if code := h.run("restore", "--dry-run", h.dir); code != ExitOK || !strings.Contains(h.stdout.String(), "Would restore 2") {
		t.Fatalf("restore --dry-run exit %d: %s", code, h.stdout.String())
	}
	if h.read(".env") != masked {
		t.Error("restore --dry-run changed files")
	}
}

func TestMaskAgainAddsToVault(t *testing.T) {
	h := newHarness(t, files)
	h.maskAll()
	h.write("new.env", "API_KEY=key-"+"1234567890\n")
	rep := h.report([2]string{"new.env", "key-" + "1234567890"})
	if code := h.run("mask", "--report", rep, h.dir); code != ExitOK {
		t.Fatalf("second mask exit %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "the vault holds 3 secret(s)") {
		t.Errorf("second mask output: %s", h.stdout.String())
	}
	h.env[DefaultPasswordEnv] = "a-different-password"
	if code := h.run("mask", "--report", rep, h.dir); code != ExitError {
		t.Errorf("mask with a different password on an existing vault: exit %d", code)
	}
	h.env[DefaultPasswordEnv] = pw
	if code := h.run("restore", h.dir); code != ExitOK {
		t.Fatalf("restore exit %d: %s", code, h.stderr.String())
	}
	if h.read("new.env") != "API_KEY=key-"+"1234567890\n" || h.read(".env") != files[".env"] {
		t.Error("restore after two masks is not exact")
	}
}

func TestPasswordSources(t *testing.T) {
	t.Run("custom env var", func(t *testing.T) {
		h := newHarness(t, files)
		h.env = map[string]string{"MY_PW": pw}
		if code := h.maskAll("--password-env", "MY_PW"); code != ExitOK {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		if len(h.prompted) != 0 {
			t.Error("prompted although the env var is set")
		}
	})
	t.Run("prompt when env empty, confirm on new vault", func(t *testing.T) {
		h := newHarness(t, files)
		h.env = map[string]string{}
		h.promptAnswer = pw
		if code := h.maskAll(); code != ExitOK {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		if len(h.prompted) != 1 || !h.prompted[0] {
			t.Errorf("prompts = %v, want one with confirm", h.prompted)
		}
		if code := h.run("restore", h.dir); code != ExitOK {
			t.Fatalf("restore exit %d", code)
		}
		if len(h.prompted) != 2 || h.prompted[1] {
			t.Errorf("prompts = %v, want restore without confirm", h.prompted)
		}
	})
	t.Run("--ask ignores env", func(t *testing.T) {
		h := newHarness(t, files)
		h.maskAll()
		h.env[DefaultPasswordEnv] = "wrong-but-ignored"
		h.promptAnswer = pw
		if code := h.run("restore", "--ask", h.dir); code != ExitOK {
			t.Fatalf("restore --ask exit %d: %s", code, h.stderr.String())
		}
		if len(h.prompted) != 1 {
			t.Errorf("--ask did not prompt: %v", h.prompted)
		}
	})
	t.Run("no env and no terminal", func(t *testing.T) {
		h := newHarness(t, files)
		h.env = map[string]string{}
		if code := h.maskAll(); code != ExitError || !strings.Contains(h.stderr.String(), "no terminal") {
			t.Errorf("exit %d: %s", code, h.stderr.String())
		}
	})
	t.Run("short password", func(t *testing.T) {
		h := newHarness(t, files)
		h.env[DefaultPasswordEnv] = "short"
		if code := h.maskAll(); code != ExitUsage || !strings.Contains(h.stderr.String(), "at least 8") {
			t.Errorf("exit %d: %s", code, h.stderr.String())
		}
		if h.read(".env") != files[".env"] {
			t.Error("files masked with a rejected password")
		}
	})
}

func TestCustomVaultAndGuidePaths(t *testing.T) {
	h := newHarness(t, files)
	out := t.TempDir()
	v, g := filepath.Join(out, "my.vault"), filepath.Join(out, "AI.md")
	if code := h.maskAll("--vault", v, "--guide", g); code != ExitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	for _, p := range []string{v, g} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s not written: %v", p, err)
		}
	}
	if code := h.run("restore", "--vault", v, h.dir); code != ExitOK {
		t.Fatalf("restore exit %d: %s", code, h.stderr.String())
	}
	if h.read(".env") != files[".env"] {
		t.Error("restore with --vault failed")
	}
}

func TestToolFilesAreNeverMasked(t *testing.T) {
	h := newHarness(t, files)
	h.maskAll()
	// A report that (wrongly) flags the vault and guide must not touch them.
	rep := h.report([2]string{DefaultVault, "format"}, [2]string{guide.DefaultName, "Secret"})
	before := h.read(DefaultVault)
	if code := h.run("mask", "--report", rep, h.dir); code != ExitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if h.read(DefaultVault) != before {
		t.Error("vault was modified by masking")
	}
}

func TestNoFindings(t *testing.T) {
	h := newHarness(t, files)
	if code := h.run("mask", "--report", h.report(), h.dir); code != ExitOK || !strings.Contains(h.stdout.String(), "No secrets found") {
		t.Errorf("exit %d: %s", code, h.stdout.String())
	}
	if _, err := os.Stat(filepath.Join(h.dir, DefaultVault)); !errors.Is(err, os.ErrNotExist) {
		t.Error("vault written with no findings")
	}
}

func TestUsageErrors(t *testing.T) {
	h := newHarness(t, files)
	tests := []struct {
		args []string
		code int
		msg  string
	}{
		{nil, ExitUsage, "Usage:"},
		{[]string{"bogus"}, ExitUsage, `unknown command "bogus"`},
		{[]string{"mask", filepath.Join(h.dir, "nope")}, ExitUsage, "is not a directory"},
		{[]string{"mask", h.dir, h.dir}, ExitUsage, "at most one path"},
		{[]string{"mask", "--no-such-flag"}, ExitUsage, "flag provided but not defined"},
		{[]string{"restore", h.dir}, ExitError, "no such file"},
		{[]string{"status", h.dir}, ExitError, "no such file"},
		{[]string{"mask", "--report", filepath.Join(h.dir, "missing.json"), h.dir}, ExitError, "no such file"},
	}
	for _, tt := range tests {
		code := h.run(tt.args...)
		out := h.stdout.String() + h.stderr.String()
		if code != tt.code || !strings.Contains(out, tt.msg) {
			t.Errorf("%v: exit %d (want %d), output %q (want %q)", tt.args, code, tt.code, out, tt.msg)
		}
	}
}

func TestFlagsAfterDirectory(t *testing.T) {
	h := newHarness(t, files)
	rep := h.report([2]string{".env", "Admin@123"})
	if code := h.run("mask", h.dir, "--report", rep); code != ExitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if h.read(".env") == files[".env"] {
		t.Error("flags after the directory were ignored")
	}
}

func TestHelpAndVersion(t *testing.T) {
	h := newHarness(t, nil)
	for _, args := range [][]string{{"help"}, {"--help"}, {"-h"}} {
		if code := h.run(args...); code != ExitOK || !strings.Contains(h.stdout.String(), "Usage:") {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	if code := h.run("mask", "-h"); code != ExitOK || !strings.Contains(h.stderr.String(), "-ask") {
		t.Errorf("mask -h: exit %d, %s", code, h.stderr.String())
	}
	if code := h.run("version"); code != ExitOK || !strings.HasPrefix(h.stdout.String(), "secret-mask "+version.Version+" (gitleaks ") {
		t.Errorf("version: exit %d, %q", code, h.stdout.String())
	}
}

func TestDefaultDirIsCwd(t *testing.T) {
	h := newHarness(t, files)
	t.Chdir(h.dir)
	rep := h.report([2]string{".env", "Admin@123"})
	if code := h.run("mask", "--report", rep); code != ExitOK {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if code := h.run("restore"); code != ExitOK {
		t.Fatalf("restore exit %d: %s", code, h.stderr.String())
	}
	if h.read(".env") != files[".env"] {
		t.Error("restore in cwd failed")
	}
}

func TestNew(t *testing.T) {
	a := New()
	if a.Stdin != os.Stdin || a.Stdout != os.Stdout || a.Stderr != os.Stderr || a.Getenv == nil || a.ReadPassword == nil || a.Executable == nil {
		t.Errorf("New() = %+v", a)
	}
}
