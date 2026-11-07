package cli

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Secrets are assembled at run time so this source file never contains a detectable secret.
var (
	awsKey      = "AKIA" + "QYLPMN5HHHFPZAM2"
	githubToken = "ghp_" + "8Rk2Lm9Qx7Vt3Zb5Nc1Hd4Jf6Gs0Pw2Ya8Ue"
)

func leakyProject() map[string]string {
	return map[string]string{
		".env":           "AWS_ACCESS_KEY_ID=" + awsKey + "\nPORT=8080\n",
		"deploy/ci.sh":   "export GITHUB_TOKEN=" + githubToken + "\n",
		"docs/README.md": "Just docs.\n",
		"src/main.go":    "package main\n",
	}
}

// TestRealScanMaskRestore runs the embedded gitleaks end to end.
func TestRealScanMaskRestore(t *testing.T) {
	project := leakyProject()
	h := newHarness(t, project)

	if code := h.run("check", h.dir); code != ExitFound || !strings.Contains(h.stdout.String(), "2 unmasked secret(s)") {
		t.Fatalf("check before mask: exit %d\n%s", code, h.stdout.String())
	}
	if strings.Contains(h.stdout.String(), awsKey) {
		t.Fatal("check output leaks a secret")
	}
	if code := h.run("mask", h.dir); code != ExitOK {
		t.Fatalf("mask exit %d: %s%s", code, h.stdout.String(), h.stderr.String())
	}
	for rel := range project {
		c := h.read(rel)
		if strings.Contains(c, awsKey) || strings.Contains(c, githubToken) {
			t.Errorf("%s still has a secret", rel)
		}
	}
	if code := h.run("check", h.dir); code != ExitOK || !strings.Contains(h.stdout.String(), "No unmasked secrets") {
		t.Errorf("check after mask: exit %d\n%s%s", code, h.stdout.String(), h.stderr.String())
	}
	if code := h.run("mask", h.dir); code != ExitOK || !strings.Contains(h.stdout.String(), "Masked 0") {
		t.Errorf("re-mask: exit %d %s", code, h.stdout.String())
	}
	if code := h.run("restore", h.dir); code != ExitOK {
		t.Fatalf("restore exit %d: %s", code, h.stderr.String())
	}
	for rel, want := range project {
		if got := h.read(rel); got != want {
			t.Errorf("%s after restore = %q, want %q", rel, got, want)
		}
	}
}

func TestCheckSingleFileAndErrors(t *testing.T) {
	h := newHarness(t, leakyProject())
	if code := h.run("check", filepath.Join(h.dir, "docs", "README.md")); code != ExitOK {
		t.Errorf("clean file: exit %d %s", code, h.stderr.String())
	}
	if code := h.run("check", "--root", h.dir, filepath.Join(h.dir, ".env")); code != ExitFound {
		t.Errorf("leaky file: exit %d", code)
	}
	if code := h.run("check", filepath.Join(h.dir, "missing")); code != ExitError {
		t.Errorf("missing path: exit %d", code)
	}
	if code := h.run("check", "--root", filepath.Join(h.dir, "docs"), filepath.Join(h.dir, ".env")); code != ExitUsage {
		t.Errorf("path outside root: exit %d", code)
	}
}

type hookOut struct {
	HookSpecificOutput struct {
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

func (h *harness) hookRead(file string) (allowed bool, reason string) {
	h.t.Helper()
	in, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "tool_name": "Read", "cwd": h.dir,
		"tool_input": map[string]any{"file_path": file},
	})
	h.stdin = string(in)
	if code := h.run("hook"); code != ExitOK {
		h.t.Fatalf("hook exit %d: %s", code, h.stderr.String())
	}
	out := strings.TrimSpace(h.stdout.String())
	if out == "" {
		return true, ""
	}
	var o hookOut
	if err := json.Unmarshal([]byte(out), &o); err != nil {
		h.t.Fatalf("hook output is not JSON: %q", out)
	}
	return o.HookSpecificOutput.PermissionDecision != "deny", o.HookSpecificOutput.PermissionDecisionReason
}

func TestHookBlocksUntilMasked(t *testing.T) {
	h := newHarness(t, leakyProject())
	h.env["CLAUDE_PROJECT_DIR"] = h.dir

	ok, reason := h.hookRead(filepath.Join(h.dir, ".env"))
	if ok || !strings.Contains(reason, "secret-mask mask "+h.dir) || strings.Contains(reason, awsKey) {
		t.Fatalf("leaky read: allowed=%v reason=%q", ok, reason)
	}
	if ok, _ := h.hookRead(filepath.Join(h.dir, "docs", "README.md")); !ok {
		t.Error("clean read blocked")
	}

	if code := h.run("mask", h.dir); code != ExitOK {
		t.Fatalf("mask exit %d", code)
	}
	if ok, reason := h.hookRead(filepath.Join(h.dir, ".env")); !ok {
		t.Errorf("masked file still blocked: %s", reason)
	}
	if ok, _ := h.hookRead(filepath.Join(h.dir, DefaultVault)); !ok {
		t.Error("vault read blocked")
	}
}

func TestHookBadInputDenies(t *testing.T) {
	h := newHarness(t, nil)
	h.stdin = "garbage"
	if code := h.run("hook"); code != ExitOK || !strings.Contains(h.stdout.String(), `"deny"`) {
		t.Errorf("exit %d, out %q", code, h.stdout.String())
	}
}

func TestMCPServer(t *testing.T) {
	h := newHarness(t, leakyProject())
	lines := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_secrets","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"check_secrets","arguments":{"path":"docs"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"check_secrets","arguments":{"path":"../.."}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"masking_status","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"masking_guide","arguments":{}}}`,
	}
	resps := h.mcpExchange(lines)
	if len(resps) != 7 {
		t.Fatalf("got %d responses", len(resps))
	}
	var names []string
	for _, tool := range resps[1]["result"].(map[string]any)["tools"].([]any) {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "check_secrets,masking_status,masking_guide" {
		t.Errorf("tools = %v (mask/restore must not be exposed)", names)
	}
	text, isErr := toolText(resps[2])
	if isErr || !strings.Contains(text, "2 unmasked secret(s)") || !strings.Contains(text, "secret-mask mask") || strings.Contains(text, awsKey) {
		t.Errorf("check_secrets(all) = %q", text)
	}
	if text, _ := toolText(resps[3]); !strings.Contains(text, "No unmasked secrets") {
		t.Errorf("check_secrets(docs) = %q", text)
	}
	if text, isErr := toolText(resps[4]); !isErr || !strings.Contains(text, "outside the project root") {
		t.Errorf("path escape = %q", text)
	}
	if _, isErr := toolText(resps[5]); !isErr {
		t.Error("masking_status without a vault should be an error result")
	}

	if code := h.run("mask", h.dir); code != ExitOK {
		t.Fatal("mask failed")
	}
	resps = h.mcpExchange(lines[6:])
	if text, isErr := toolText(resps[0]); isErr || !strings.Contains(text, "missing: 0") {
		t.Errorf("masking_status after mask = %q", text)
	}
	if text, isErr := toolText(resps[1]); isErr || !strings.Contains(text, "rules for AI assistants") {
		t.Errorf("masking_guide = %q", text)
	}
}

func (h *harness) mcpExchange(lines []string) []map[string]any {
	h.t.Helper()
	h.stdin = strings.Join(lines, "\n") + "\n"
	if code := h.run("mcp", "--dir", h.dir); code != ExitOK {
		h.t.Fatalf("mcp exit %d: %s", code, h.stderr.String())
	}
	var resps []map[string]any
	sc := bufio.NewScanner(strings.NewReader(h.stdout.String()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			h.t.Fatalf("stdout must carry only JSON-RPC: %q", sc.Text())
		}
		resps = append(resps, m)
	}
	return resps
}

func toolText(resp map[string]any) (string, bool) {
	r, _ := resp["result"].(map[string]any)
	content, _ := r["content"].([]any)
	if len(content) == 0 {
		return "", true
	}
	return content[0].(map[string]any)["text"].(string), r["isError"] == true
}

func TestSetupCommand(t *testing.T) {
	h := newHarness(t, nil)
	h.env["HOME"] = t.TempDir()
	if code := h.run("setup", h.dir); code != ExitOK {
		t.Fatalf("setup exit %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "updated:") {
		t.Errorf("setup output: %s", h.stdout.String())
	}
	for _, f := range []string{".mcp.json", filepath.Join(".claude", "settings.json")} {
		if _, err := os.Stat(filepath.Join(h.dir, f)); err != nil {
			t.Errorf("%s not written", f)
		}
	}
	if code := h.run("setup", h.dir); code != ExitOK || !strings.Contains(h.stdout.String(), "nothing changed") {
		t.Errorf("second setup: %s", h.stdout.String())
	}
	if code := h.run("setup", "--scope", "user", h.dir); code != ExitOK || !strings.Contains(h.stdout.String(), "claude mcp add --scope user") {
		t.Errorf("user scope: %s", h.stdout.String())
	}
	if code := h.run("setup", "--scope", "bogus", h.dir); code != ExitError {
		t.Errorf("bad scope exit %d", code)
	}
}

func TestInstallUninstallCommands(t *testing.T) {
	h := newHarness(t, nil)
	home := t.TempDir()
	h.env["HOME"] = home
	if code := h.run("install", "--clients", "claude,codex", "--dry-run"); code != ExitOK || !strings.Contains(h.stdout.String(), "would be created") {
		t.Fatalf("dry run: exit %d\n%s%s", code, h.stdout.String(), h.stderr.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".claude.json")); !os.IsNotExist(err) {
		t.Error("dry run wrote files")
	}
	if code := h.run("install", "--clients", "claude,codex"); code != ExitOK {
		t.Fatalf("install exit %d: %s", code, h.stderr.String())
	}
	out := h.stdout.String()
	for _, want := range []string{"Claude Code:", "Codex CLI:", "/hooks", filepath.Join(home, ".codex", "config.toml")} {
		if !strings.Contains(out, want) {
			t.Errorf("install output missing %q:\n%s", want, out)
		}
	}
	settings, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if !strings.Contains(string(settings), `"/usr/local/bin/secret-mask hook"`) {
		t.Errorf("hook uses the executable path: %s", settings)
	}
	if code := h.run("uninstall", "--clients", "claude,codex"); code != ExitOK || !strings.Contains(h.stdout.String(), "(removed)") {
		t.Fatalf("uninstall exit %d\n%s", code, h.stdout.String())
	}
	if entries, _ := os.ReadDir(filepath.Join(home, ".claude")); len(entries) != 1 { // skills/ stays, empty
		t.Errorf("left in ~/.claude: %v", entries)
	}
	if code := h.run("install", "--clients", "emacs"); code != ExitUsage {
		t.Errorf("unknown client exit %d", code)
	}
	if code := h.run("install", "extra"); code != ExitUsage {
		t.Errorf("positional argument exit %d", code)
	}
}

func TestHookClients(t *testing.T) {
	h := newHarness(t, leakyProject())
	in, _ := json.Marshal(map[string]any{
		"hook_event_name": "BeforeTool", "tool_name": "read_file", "cwd": h.dir,
		"tool_input": map[string]any{"absolute_path": filepath.Join(h.dir, ".env")},
	})
	h.stdin = string(in)
	if code := h.run("hook", "--client", "gemini"); code != ExitOK || !strings.Contains(h.stdout.String(), `"decision":"deny"`) {
		t.Errorf("gemini: exit %d %s", code, h.stdout.String())
	}
	in, _ = json.Marshal(map[string]any{"hook_event_name": "beforeShellExecution", "command": "cat deploy/ci.sh", "cwd": h.dir})
	h.stdin = string(in)
	if code := h.run("hook", "--client", "cursor"); code != ExitOK || !strings.Contains(h.stdout.String(), `"permission":"deny"`) || strings.Contains(h.stdout.String(), githubToken) {
		t.Errorf("cursor: exit %d %s", code, h.stdout.String())
	}
	if code := h.run("hook", "--client", "emacs"); code != ExitUsage {
		t.Errorf("unknown client exit %d", code)
	}
}
