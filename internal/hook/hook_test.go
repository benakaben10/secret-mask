package hook

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/benakaben10/secret-mask/internal/detect"
)

type call struct{ root, target string }

// fake returns a Checker that reports findings for files named in leaky and records its calls.
func fake(leaky map[string]bool, err error, calls *[]call) Checker {
	return func(root, target string) ([]detect.Finding, error) {
		*calls = append(*calls, call{root, target})
		if err != nil {
			return nil, err
		}
		if leaky[filepath.Base(target)] || (target == "." && len(leaky) > 0) {
			return []detect.Finding{{RuleID: "aws-access-token", File: target, StartLine: 2, Secret: "never-shown"}}, nil
		}
		return nil, nil
	}
}

func input(tool string, toolInput map[string]any, cwd string) []byte {
	b, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": toolInput, "cwd": cwd,
	})
	return b
}

func project(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range []string{"leak.env", "clean.txt", ".secret-mask.vault"} {
		os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644)
	}
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	return dir
}

var own = map[string]bool{".secret-mask.vault": true}

func TestReadLeakyFileIsDenied(t *testing.T) {
	dir := project(t)
	var calls []call
	d := Evaluate(input("Read", map[string]any{"file_path": filepath.Join(dir, "leak.env")}, dir), dir, own, fake(map[string]bool{"leak.env": true}, nil, &calls))
	if d.Allow {
		t.Fatal("read of a file with an unmasked secret was allowed")
	}
	for _, want := range []string{"BLOCKED by secret-mask", "leak.env: line 2 (aws-access-token)", "secret-mask mask " + dir, "ask the user"} {
		if !strings.Contains(d.Reason, want) {
			t.Errorf("reason missing %q:\n%s", want, d.Reason)
		}
	}
	if strings.Contains(d.Reason, "never-shown") {
		t.Error("reason leaks the secret value")
	}
	if len(calls) != 1 || calls[0].root != dir || calls[0].target != "leak.env" {
		t.Errorf("checker calls = %+v", calls)
	}
}

func TestAllowed(t *testing.T) {
	dir := project(t)
	tests := []struct {
		name  string
		raw   []byte
		calls int
	}{
		{"clean file", input("Read", map[string]any{"file_path": filepath.Join(dir, "clean.txt")}, dir), 1},
		{"relative path from cwd", input("Read", map[string]any{"file_path": "clean.txt"}, dir), 1},
		{"vault itself", input("Read", map[string]any{"file_path": filepath.Join(dir, ".secret-mask.vault")}, dir), 0},
		{"missing file", input("Read", map[string]any{"file_path": filepath.Join(dir, "nope")}, dir), 0},
		{"tool without a path", input("Bash", map[string]any{"command": "ls"}, dir), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []call
			d := Evaluate(tt.raw, dir, own, fake(map[string]bool{"leak.env": true}, nil, &calls))
			if !d.Allow {
				t.Errorf("denied: %s", d.Reason)
			}
			if len(calls) != tt.calls {
				t.Errorf("checker called %d times, want %d", len(calls), tt.calls)
			}
		})
	}
}

func TestGrepScansDirectory(t *testing.T) {
	dir := project(t)
	var calls []call
	d := Evaluate(input("Grep", map[string]any{"pattern": "x"}, dir), "", own, fake(map[string]bool{"leak.env": true}, nil, &calls))
	if d.Allow || len(calls) != 1 || calls[0].target != "." {
		t.Errorf("grep without path: allow=%v calls=%+v", d.Allow, calls)
	}
	calls = nil
	d = Evaluate(input("Grep", map[string]any{"pattern": "x", "path": "sub"}, dir), dir, own, fake(nil, nil, &calls))
	if !d.Allow || len(calls) != 1 || calls[0].target != "sub" {
		t.Errorf("grep in clean subdir: allow=%v calls=%+v", d.Allow, calls)
	}
}

func TestNotebookPath(t *testing.T) {
	dir := project(t)
	var calls []call
	d := Evaluate(input("NotebookRead", map[string]any{"notebook_path": filepath.Join(dir, "leak.env")}, dir), dir, own, fake(map[string]bool{"leak.env": true}, nil, &calls))
	if d.Allow {
		t.Error("notebook read with a secret was allowed")
	}
}

func TestOutsideProjectIsScannedOnItsOwn(t *testing.T) {
	dir, other := project(t), project(t)
	var calls []call
	Evaluate(input("Read", map[string]any{"file_path": filepath.Join(other, "leak.env")}, dir), dir, own, fake(nil, nil, &calls))
	if len(calls) != 1 || calls[0].root != other || calls[0].target != "leak.env" {
		t.Errorf("outside file: calls = %+v", calls)
	}
	calls = nil
	Evaluate(input("Grep", map[string]any{"path": other}, dir), dir, own, fake(nil, nil, &calls))
	if len(calls) != 1 || calls[0].root != other || calls[0].target != "." {
		t.Errorf("outside dir: calls = %+v", calls)
	}
}

func TestFailsClosed(t *testing.T) {
	dir := project(t)
	var calls []call
	d := Evaluate([]byte("{not json"), dir, own, fake(nil, nil, &calls))
	if d.Allow || !strings.Contains(d.Reason, "could not parse") {
		t.Errorf("bad input: %+v", d)
	}
	d = Evaluate(input("Read", map[string]any{"file_path": filepath.Join(dir, "clean.txt")}, dir), dir, own, fake(nil, errors.New("boom"), &calls))
	if d.Allow || !strings.Contains(d.Reason, "could not scan") || !strings.Contains(d.Reason, "boom") {
		t.Errorf("scan error: %+v", d)
	}
}

func TestOutput(t *testing.T) {
	if Output(Decision{Allow: true}) != nil {
		t.Error("allow must produce no output")
	}
	var got struct {
		HookSpecificOutput struct {
			HookEventName, PermissionDecision, PermissionDecisionReason string
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(Output(Decision{Reason: "why"}), &got); err != nil {
		t.Fatal(err)
	}
	h := got.HookSpecificOutput
	if h.HookEventName != "PreToolUse" || h.PermissionDecision != "deny" || h.PermissionDecisionReason != "why" {
		t.Errorf("output = %+v", h)
	}
}
