package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return m
}

func hookCommands(settings map[string]any) []string {
	var cmds []string
	pre, _ := settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	for _, e := range pre {
		for _, h := range e.(map[string]any)["hooks"].([]any) {
			cmds = append(cmds, h.(map[string]any)["command"].(string))
		}
	}
	return cmds
}

func TestProjectScopeFresh(t *testing.T) {
	dir := t.TempDir()
	res, err := Apply(Options{ProjectDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(dir, ".claude", "settings.json")
	mcp := filepath.Join(dir, ".mcp.json")
	if !reflect.DeepEqual(res.Changed, []string{mcp, settings}) {
		t.Errorf("Changed = %v", res.Changed)
	}
	s := readJSON(t, settings)
	if got := hookCommands(s); !reflect.DeepEqual(got, []string{"secret-mask hook"}) {
		t.Errorf("hook commands = %v", got)
	}
	entry := s["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	if entry["matcher"] != "Read|Grep|NotebookRead|Bash|mcp__.*" {
		t.Errorf("matcher = %v", entry["matcher"])
	}
	server := readJSON(t, mcp)["mcpServers"].(map[string]any)[ServerName].(map[string]any)
	if server["command"] != "secret-mask" || !reflect.DeepEqual(server["args"], []any{"mcp"}) || server["type"] != "stdio" {
		t.Errorf("mcp server = %v", server)
	}
}

func TestPreservesExistingAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".claude"), 0o755)
	os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte(`{
  "permissions": {"allow": ["Bash(ls:*)"]},
  "hooks": {
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "other-hook"}]}],
    "PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "fmt"}]}]
  }
}`), 0o644)
	os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(`{"mcpServers": {"other": {"command": "x"}}}`), 0o644)

	if _, err := Apply(Options{ProjectDir: dir, Command: "/opt/bin/secret-mask"}); err != nil {
		t.Fatal(err)
	}
	s := readJSON(t, filepath.Join(dir, ".claude", "settings.json"))
	if s["permissions"] == nil || s["hooks"].(map[string]any)["PostToolUse"] == nil {
		t.Error("existing settings were dropped")
	}
	if got := hookCommands(s); !reflect.DeepEqual(got, []string{"other-hook", "/opt/bin/secret-mask hook"}) {
		t.Errorf("hook commands = %v", got)
	}
	servers := readJSON(t, filepath.Join(dir, ".mcp.json"))["mcpServers"].(map[string]any)
	if servers["other"] == nil || servers[ServerName].(map[string]any)["command"] != "/opt/bin/secret-mask" {
		t.Errorf("mcp servers = %v", servers)
	}

	res, err := Apply(Options{ProjectDir: dir, Command: "/opt/bin/secret-mask"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changed) != 0 {
		t.Errorf("second run changed %v", res.Changed)
	}
	if got := hookCommands(readJSON(t, filepath.Join(dir, ".claude", "settings.json"))); len(got) != 2 {
		t.Errorf("hook duplicated: %v", got)
	}

	// A different command updates the MCP server and adds the new hook command.
	res, _ = Apply(Options{ProjectDir: dir})
	if len(res.Changed) != 2 {
		t.Errorf("changing the command should update both files: %v", res.Changed)
	}
}

func TestDockerCommand(t *testing.T) {
	dir := t.TempDir()
	cmd := "docker run --rm -i -v " + dir + ":" + dir + " -w " + dir + " secret-mask:dev"
	if _, err := Apply(Options{ProjectDir: dir, Command: cmd}); err != nil {
		t.Fatal(err)
	}
	if got := hookCommands(readJSON(t, filepath.Join(dir, ".claude", "settings.json"))); !reflect.DeepEqual(got, []string{cmd + " hook"}) {
		t.Errorf("hook = %v", got)
	}
	server := readJSON(t, filepath.Join(dir, ".mcp.json"))["mcpServers"].(map[string]any)[ServerName].(map[string]any)
	wantArgs := []any{"run", "--rm", "-i", "-v", dir + ":" + dir, "-w", dir, "secret-mask:dev", "mcp"}
	if server["command"] != "docker" || !reflect.DeepEqual(server["args"], wantArgs) {
		t.Errorf("mcp server = %v", server)
	}
}

func TestUserScope(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	res, err := Apply(Options{Scope: "user", HomeDir: home, ProjectDir: project})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Changed, []string{filepath.Join(home, ".claude", "settings.json")}) {
		t.Errorf("Changed = %v", res.Changed)
	}
	if len(res.Notes) != 1 || !strings.Contains(res.Notes[0], "claude mcp add --scope user secret-mask -- secret-mask mcp") {
		t.Errorf("Notes = %v", res.Notes)
	}
	if _, err := os.Stat(filepath.Join(project, ".mcp.json")); !os.IsNotExist(err) {
		t.Error("user scope wrote a project .mcp.json")
	}
}

func TestErrors(t *testing.T) {
	if _, err := Apply(Options{Scope: "global", ProjectDir: t.TempDir()}); err == nil {
		t.Error("unknown scope accepted")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte("{broken"), 0o644)
	if _, err := Apply(Options{ProjectDir: dir}); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("broken JSON: %v", err)
	}
	dir = t.TempDir()
	os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte("null"), 0o644)
	if _, err := Apply(Options{ProjectDir: dir}); err != nil {
		t.Errorf("JSON null should be treated as empty: %v", err)
	}
}
