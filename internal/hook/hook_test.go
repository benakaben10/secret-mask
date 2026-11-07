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
	if Output(Claude, Decision{Allow: true}) != nil {
		t.Error("allow must produce no output")
	}
	var got struct {
		HookSpecificOutput struct {
			HookEventName, PermissionDecision, PermissionDecisionReason string
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(Output(Claude, Decision{Reason: "why"}), &got); err != nil {
		t.Fatal(err)
	}
	h := got.HookSpecificOutput
	if h.HookEventName != "PreToolUse" || h.PermissionDecision != "deny" || h.PermissionDecisionReason != "why" {
		t.Errorf("output = %+v", h)
	}
}

func TestShellCommands(t *testing.T) {
	dir := project(t)
	os.WriteFile(filepath.Join(dir, "sub", "leak.env"), []byte("x"), 0o644)
	leaky := map[string]bool{"leak.env": true}
	tests := []struct {
		name    string
		command any
		allow   bool
		targets []string
	}{
		{"cat a leaky file", "cat leak.env", false, []string{"leak.env"}},
		{"redirect without spaces", "wc -l<leak.env", false, []string{"leak.env"}},
		{"quoted path", `sed -n 1p "sub/leak.env"`, false, []string{"sub/leak.env"}},
		{"flag value", "tool --input=leak.env", false, []string{"leak.env"}},
		{"glob", "head *.env", false, []string{"leak.env"}},
		{"argv from Codex", []any{"bash", "-lc", "cat clean.txt && cat leak.env"}, false, []string{"clean.txt", "leak.env"}},
		{"clean file", "cat clean.txt", true, []string{"clean.txt"}},
		{"listing a directory is not reading it", "ls sub", true, nil},
		{"recursive grep with no path scans cwd", "grep -rn password", false, []string{"."}},
		{"rg in a directory scans it", "rg password sub", true, []string{"sub"}},
		{"plain grep on stdin", "ps aux | grep node", true, nil},
		{"variables are not expanded", "cat $FILE", true, nil},
		{"no paths", "go version", true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []call
			d := Evaluate(input("Bash", map[string]any{"command": tt.command}, dir), dir, own, fake(leaky, nil, &calls))
			if d.Allow != tt.allow {
				t.Errorf("allow = %v: %s", d.Allow, d.Reason)
			}
			var got []string
			for _, c := range calls {
				got = append(got, c.target)
			}
			if strings.Join(got, ",") != strings.Join(tt.targets, ",") {
				t.Errorf("scanned %v, want %v", got, tt.targets)
			}
		})
	}
}

func TestClientPayloads(t *testing.T) {
	dir := project(t)
	leaky := map[string]bool{"leak.env": true}
	leak := filepath.Join(dir, "leak.env")
	cursorRead, _ := json.Marshal(map[string]any{"hook_event_name": "beforeReadFile", "file_path": leak, "workspace_roots": []string{dir}})
	cursorShell, _ := json.Marshal(map[string]any{"hook_event_name": "beforeShellExecution", "command": "cat leak.env", "cwd": dir})
	tests := []struct {
		name string
		raw  []byte
	}{
		{"gemini read_file", input("read_file", map[string]any{"file_path": leak}, dir)},
		{"gemini read_file (absolute_path)", input("read_file", map[string]any{"absolute_path": leak}, dir)},
		{"gemini read_many_files", input("read_many_files", map[string]any{"paths": []any{"clean.txt", "leak.env"}}, dir)},
		{"gemini search without path", input("search_file_content", map[string]any{"pattern": "x"}, dir)},
		{"gemini shell in a directory", input("run_shell_command", map[string]any{"command": "cat leak.env", "directory": "."}, dir)},
		{"copilot read_file", input("read_file", map[string]any{"filePath": leak}, dir)},
		{"cursor beforeReadFile", cursorRead},
		{"cursor beforeShellExecution", cursorShell},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []call
			if d := Evaluate(tt.raw, "", own, fake(leaky, nil, &calls)); d.Allow {
				t.Errorf("allowed, calls %+v", calls)
			}
		})
	}
}

func TestClientOutputs(t *testing.T) {
	deny := Decision{Reason: "why"}
	var gem map[string]string
	json.Unmarshal(Output(Gemini, deny), &gem)
	if gem["decision"] != "deny" || gem["reason"] != "why" || Output(Gemini, Decision{Allow: true}) != nil {
		t.Errorf("gemini = %v", gem)
	}
	var cur map[string]string
	json.Unmarshal(Output(Cursor, deny), &cur)
	if cur["permission"] != "deny" || cur["agent_message"] != "why" {
		t.Errorf("cursor deny = %v", cur)
	}
	if string(Output(Cursor, Decision{Allow: true})) != `{"permission":"allow"}` {
		t.Errorf("cursor allow = %s", Output(Cursor, Decision{Allow: true}))
	}
	for _, c := range []string{Codex, Copilot} {
		if !strings.Contains(string(Output(c, deny)), `"permissionDecision":"deny"`) {
			t.Errorf("%s uses the Claude Code format: %s", c, Output(c, deny))
		}
	}
}

func TestMCPToolCalls(t *testing.T) {
	dir := project(t)
	leaky := map[string]bool{"leak.env": true}
	tests := []struct {
		name    string
		raw     []byte
		allow   bool
		targets []string
	}{
		{"indexer without a path scans the project", input("mcp__codebase-memory-mcp__index_repository", map[string]any{}, dir), false, []string{"."}},
		{"indexer with repo_path", input("mcp__codebase-memory-mcp__index_repository", map[string]any{"repo_path": dir}, dir), false, []string{"."}},
		{"file argument", input("mcp__fs__read_text_file", map[string]any{"path": "leak.env"}, dir), false, []string{"leak.env"}},
		{"query tools are not indexers", input("mcp__codebase-memory-mcp__search_graph", map[string]any{"query": "x"}, dir), true, nil},
		{"status tools are not indexers", input("mcp__codebase-memory-mcp__index_status", map[string]any{}, dir), true, nil},
		{"secret-mask's own tools", input("mcp__secret-mask__check_secrets", map[string]any{"path": "leak.env"}, dir), true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []call
			d := Evaluate(tt.raw, dir, own, fake(leaky, nil, &calls))
			if d.Allow != tt.allow {
				t.Errorf("allow = %v: %s", d.Allow, d.Reason)
			}
			var got []string
			for _, c := range calls {
				got = append(got, c.target)
			}
			if strings.Join(got, ",") != strings.Join(tt.targets, ",") {
				t.Errorf("scanned %v, want %v", got, tt.targets)
			}
		})
	}
	// Cursor sends MCP arguments as a JSON string.
	raw, _ := json.Marshal(map[string]any{"hook_event_name": "beforeMCPExecution", "tool_name": "index_repository",
		"tool_input": `{"repo_path":"` + dir + `"}`, "workspace_roots": []string{dir}})
	var calls []call
	if d := Evaluate(raw, "", own, fake(leaky, nil, &calls)); d.Allow {
		t.Errorf("cursor MCP indexer allowed, calls %+v", calls)
	}
}

func TestRevealIsBlocked(t *testing.T) {
	dir := project(t)
	cursorShell, _ := json.Marshal(map[string]any{"hook_event_name": "beforeShellExecution", "command": "secret-mask reveal .", "cwd": dir})
	for name, raw := range map[string][]byte{
		"bash":   input("Bash", map[string]any{"command": "cd app && /usr/local/bin/secret-mask reveal --id x ."}, dir),
		"argv":   input("Bash", map[string]any{"command": []any{"bash", "-lc", "secret-mask reveal"}}, dir),
		"cursor": cursorShell,
	} {
		var calls []call
		d := Evaluate(raw, dir, own, fake(nil, nil, &calls))
		if d.Allow || !strings.Contains(d.Reason, "user's own terminal") {
			t.Errorf("%s: %+v", name, d)
		}
	}
	var calls []call
	if d := Evaluate(input("Bash", map[string]any{"command": "secret-mask status ."}, dir), dir, own, fake(nil, nil, &calls)); !d.Allow {
		t.Errorf("status blocked: %s", d.Reason)
	}
}

func TestSessionContext(t *testing.T) {
	dir := project(t)
	raw, _ := json.Marshal(map[string]any{"hook_event_name": "SessionStart", "cwd": dir})
	var calls []call
	ctx := SessionContext(raw, "", fake(map[string]bool{"leak.env": true}, nil, &calls))
	for _, want := range []string{"BEFORE anything else", "indexing", "secret-mask mask " + dir, "next_steps"} {
		if !strings.Contains(ctx, want) {
			t.Errorf("context missing %q: %s", want, ctx)
		}
	}
	if !strings.Contains(string(SessionOutput(Claude, ctx)), `"hookEventName":"SessionStart"`) || SessionOutput(Claude, "") != nil {
		t.Error("session output")
	}
	if got := SessionContext(raw, "", fake(nil, nil, &calls)); got != "" {
		t.Errorf("clean project: %q", got)
	}
}
