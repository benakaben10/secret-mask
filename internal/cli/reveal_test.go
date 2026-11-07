package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestRevealIsForTheUserOnly(t *testing.T) {
	h := newHarness(t, files)
	if code := h.maskAll(); code != ExitOK {
		t.Fatal("mask")
	}
	// Not a terminal (an agent's shell, a pipe, a script).
	if code := h.run("reveal", h.dir); code != ExitError || !strings.Contains(h.stderr.String(), "interactive terminal") {
		t.Errorf("no terminal: exit %d %s", code, h.stderr.String())
	}
	h.terminal = true
	h.env["CLAUDECODE"] = "1"
	if code := h.run("reveal", h.dir); code != ExitError || !strings.Contains(h.stderr.String(), "inside a coding agent") {
		t.Errorf("inside an agent: exit %d %s", code, h.stderr.String())
	}
	delete(h.env, "CLAUDECODE")
	// $SECRET_MASK_PASSWORD is set in the harness, but reveal always asks on the terminal.
	h.prompted = nil
	if code := h.run("reveal", h.dir); code != ExitError || len(h.prompted) != 1 {
		t.Errorf("must prompt, not use the env var: exit %d prompted %v", code, h.prompted)
	}
	h.promptAnswer = "wrong-password"
	if code := h.run("reveal", h.dir); code != ExitError || strings.Contains(h.stdout.String(), "Admin@123") {
		t.Errorf("wrong password: exit %d %s", code, h.stdout.String())
	}
}

func TestRevealShowsValuesAndLocations(t *testing.T) {
	h := newHarness(t, files)
	if code := h.maskAll(); code != ExitOK {
		t.Fatal("mask")
	}
	h.terminal, h.promptAnswer = true, pw
	if code := h.run("reveal", h.dir); code != ExitOK {
		t.Fatalf("reveal: exit %d %s", code, h.stderr.String())
	}
	out := h.stdout.String()
	line := regexp.MustCompile(`(?m)^\.env:1  test-rule  (__SECRET_MASK_[0-9a-f]{16}__)  Admin@123$`)
	m := line.FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "k8s/secret.yaml:3  test-rule  ") || !strings.Contains(out, "tok-"+"9f8e7d6c5b4a") {
		t.Fatalf("output:\n%s", out)
	}
	if !strings.Contains(h.stderr.String(), "REAL secrets") {
		t.Error("no warning")
	}

	// Filters.
	h.run("reveal", "--id", m[1], h.dir)
	if strings.Count(h.stdout.String(), "\n") != 1 || !strings.Contains(h.stdout.String(), "Admin@123") {
		t.Errorf("--id: %s", h.stdout.String())
	}
	h.run("reveal", "--file", "k8s/secret.yaml", h.dir)
	if strings.Contains(h.stdout.String(), "Admin@123") || !strings.Contains(h.stdout.String(), "k8s/secret.yaml:3") {
		t.Errorf("--file: %s", h.stdout.String())
	}

	// A placeholder that went missing is listed with the files it was masked in.
	os.WriteFile(filepath.Join(h.dir, ".env"), []byte("PORT=8080\n"), 0o644)
	h.run("reveal", h.dir)
	if !strings.Contains(h.stdout.String(), "(missing)  test-rule  "+m[1]+"  Admin@123  masked in: .env") {
		t.Errorf("missing: %s", h.stdout.String())
	}
}
