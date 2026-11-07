package setup

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func opts(home string, clients ...string) InstallOptions {
	return InstallOptions{
		Home: home, GOOS: "linux", Clients: clients, Command: []string{"/opt/bin/secret-mask"},
		Getenv: func(string) string { return "" },
	}
}

func mustInstall(t *testing.T, o InstallOptions) *Report {
	t.Helper()
	rep, err := Install(o)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func statuses(rep *Report) map[string]string {
	m := map[string]string{}
	for _, c := range rep.Changes {
		m[c.Kind+" "+c.Path] = c.Status
	}
	return m
}

func readText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// snapshot returns every file under dir with its content.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			files[rel] = readText(t, p)
		}
		return nil
	})
	return files
}

func allHookCommands(doc map[string]any) []string {
	var cmds []string
	hooks, _ := doc["hooks"].(map[string]any)
	for _, v := range hooks {
		for _, e := range v.([]any) {
			m := e.(map[string]any)
			if c, ok := m["command"].(string); ok {
				cmds = append(cmds, c)
			}
			if inner, ok := m["hooks"].([]any); ok {
				for _, h := range inner {
					cmds = append(cmds, h.(map[string]any)["command"].(string))
				}
			}
		}
	}
	return cmds
}

func TestInstallEveryClient(t *testing.T) {
	home := t.TempDir()
	rep := mustInstall(t, opts(home, ClientIDs()...))
	if len(rep.Clients) != 6 {
		t.Errorf("clients = %v", rep.Clients)
	}
	for _, c := range rep.Changes {
		if c.Status != "created" && c.Status != "updated" {
			t.Errorf("%s %s: %s", c.Kind, c.Path, c.Status)
		}
	}

	// Claude Code
	server := readJSON(t, filepath.Join(home, ".claude.json"))["mcpServers"].(map[string]any)[ServerName].(map[string]any)
	if server["command"] != "/opt/bin/secret-mask" || !reflect.DeepEqual(server["args"], []any{"mcp"}) || server["type"] != "stdio" {
		t.Errorf("claude mcp = %v", server)
	}
	settings := readJSON(t, filepath.Join(home, ".claude", "settings.json"))
	if got := hookCommands(settings); !reflect.DeepEqual(got, []string{"/opt/bin/secret-mask hook"}) {
		t.Errorf("claude hooks = %v", got)
	}
	if readText(t, filepath.Join(home, ".claude", "skills", "secret-mask", "SKILL.md")) != Skill {
		t.Error("claude skill")
	}

	// Codex CLI
	toml := readText(t, filepath.Join(home, ".codex", "config.toml"))
	for _, want := range []string{tomlStart, "[mcp_servers.secret-mask]", `command = "/opt/bin/secret-mask"`, `args = ["mcp"]`, tomlEnd} {
		if !strings.Contains(toml, want) {
			t.Errorf("config.toml missing %q:\n%s", want, toml)
		}
	}
	codexHooks := readJSON(t, filepath.Join(home, ".codex", "hooks.json"))
	pre := codexHooks["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	if pre["matcher"] != "Bash" || !reflect.DeepEqual(allHookCommands(codexHooks), []string{"/opt/bin/secret-mask hook --client codex"}) {
		t.Errorf("codex hooks = %v", codexHooks)
	}
	if !strings.Contains(readText(t, filepath.Join(home, ".codex", "AGENTS.md")), "## Secrets (secret-mask)") {
		t.Error("codex AGENTS.md")
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "secret-mask", "SKILL.md")); err != nil {
		t.Error("codex skill")
	}

	// Gemini CLI: MCP and hook share settings.json.
	gem := readJSON(t, filepath.Join(home, ".gemini", "settings.json"))
	if gem["mcpServers"].(map[string]any)[ServerName] == nil {
		t.Error("gemini mcp")
	}
	before := gem["hooks"].(map[string]any)["BeforeTool"].([]any)[0].(map[string]any)
	inner := before["hooks"].([]any)[0].(map[string]any)
	if before["matcher"] != geminiMatcher || inner["command"] != "/opt/bin/secret-mask hook --client gemini" || inner["timeout"] != float64(120000) {
		t.Errorf("gemini hook = %v", before)
	}
	if !strings.Contains(readText(t, filepath.Join(home, ".gemini", "GEMINI.md")), mdStart) {
		t.Error("GEMINI.md")
	}

	// Cursor
	cursor := readJSON(t, filepath.Join(home, ".cursor", "hooks.json"))
	if cursor["version"] != float64(1) || len(cursor["hooks"].(map[string]any)) != 2 {
		t.Errorf("cursor hooks = %v", cursor)
	}
	if readJSON(t, filepath.Join(home, ".cursor", "mcp.json"))["mcpServers"] == nil {
		t.Error("cursor mcp")
	}

	// VS Code and Copilot CLI share ~/.copilot.
	vscode := readJSON(t, filepath.Join(home, ".config", "Code", "User", "mcp.json"))["servers"].(map[string]any)[ServerName].(map[string]any)
	if vscode["type"] != "stdio" {
		t.Errorf("vscode mcp = %v", vscode)
	}
	manifest := readJSON(t, filepath.Join(home, ".copilot", "hooks", "secret-mask.json"))
	entry := manifest["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	if entry["bash"] != "/opt/bin/secret-mask hook --client copilot" || entry["matcher"] != nil {
		t.Errorf("copilot hook = %v", entry)
	}
	cli := readJSON(t, filepath.Join(home, ".copilot", "mcp-config.json"))["mcpServers"].(map[string]any)[ServerName].(map[string]any)
	if cli["type"] != "local" {
		t.Errorf("copilot cli mcp = %v", cli)
	}
	n := 0
	for _, c := range rep.Changes {
		if strings.HasSuffix(c.Path, filepath.Join("hooks", "secret-mask.json")) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the shared copilot hook is reported %d times", n)
	}

	// Idempotent.
	for _, c := range mustInstall(t, opts(home, ClientIDs()...)).Changes {
		if c.Status != "unchanged" {
			t.Errorf("second install: %s %s: %s", c.Kind, c.Path, c.Status)
		}
	}
}

func TestUninstallRestoresUserFiles(t *testing.T) {
	home := t.TempDir()
	user := map[string]string{
		".claude.json":                    `{"numStartups": 3, "mcpServers": {"other": {"command": "x"}}}`,
		".claude/settings.json":           `{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "mine"}]}]}}`,
		".codex/config.toml":              "model = \"o3\"\n\n[mcp_servers.other]\ncommand = \"x\"\n",
		".codex/AGENTS.md":                "# My rules\n\nBe brief.\n",
		".gemini/settings.json":           `{"theme": "dark"}`,
		".cursor/hooks.json":              `{"version": 1, "hooks": {"beforeReadFile": [{"command": "mine"}]}}`,
		".config/Code/User/settings.json": `{}`,
	}
	for rel, content := range user {
		p := filepath.Join(home, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	orig := snapshot(t, home)

	o := opts(home)
	o.LookPath = func(string) bool { return false }
	rep := mustInstall(t, o) // detection: every client but the Copilot CLI has a config dir
	if strings.Join(rep.Clients, ",") != "Claude Code,Codex CLI,Gemini CLI,Cursor,VS Code (Copilot)" {
		t.Errorf("detected %v", rep.Clients)
	}
	if got := allHookCommands(readJSON(t, filepath.Join(home, ".cursor", "hooks.json"))); len(got) != 3 || got[0] != "mine" && got[1] != "mine" {
		t.Errorf("cursor hooks = %v", got)
	}
	agents := readText(t, filepath.Join(home, ".codex", "AGENTS.md"))
	if !strings.HasPrefix(agents, "# My rules\n\nBe brief.\n\n"+mdStart) {
		t.Errorf("AGENTS.md = %q", agents)
	}

	// A second install with another binary path replaces the hooks instead of adding more.
	o.Command = []string{"/new/secret-mask"}
	mustInstall(t, o)
	if got := hookCommands(readJSON(t, filepath.Join(home, ".claude", "settings.json"))); !reflect.DeepEqual(got, []string{"mine", "/new/secret-mask hook"}) {
		t.Errorf("claude hooks after reinstall = %v", got)
	}
	if strings.Count(readText(t, filepath.Join(home, ".codex", "config.toml")), tomlStart) != 1 {
		t.Error("codex block duplicated")
	}

	if _, err := Uninstall(opts(home)); err != nil {
		t.Fatal(err)
	}
	after := snapshot(t, home)
	for rel, want := range orig {
		got, ok := after[rel]
		if !ok {
			t.Errorf("%s was deleted", rel)
			continue
		}
		if !jsonOrTextEqual(t, want, got) {
			t.Errorf("%s after uninstall:\n%s\nwant:\n%s", rel, got, want)
		}
	}
	for rel := range after {
		if _, ok := orig[rel]; !ok {
			t.Errorf("uninstall left %s", rel)
		}
	}
	for _, d := range []string{".claude/skills/secret-mask", ".cursor/skills/secret-mask"} {
		if _, err := os.Stat(filepath.Join(home, d)); !os.IsNotExist(err) {
			t.Errorf("%s not removed", d)
		}
	}
}

func jsonOrTextEqual(t *testing.T, a, b string) bool {
	if a == b {
		return true
	}
	dir := t.TempDir()
	pa, pb := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	os.WriteFile(pa, []byte(a), 0o644)
	os.WriteFile(pb, []byte(b), 0o644)
	return reflect.DeepEqual(readJSON(t, pa), readJSON(t, pb))
}

func TestNoHooksAndDryRun(t *testing.T) {
	home := t.TempDir()
	o := opts(home, "claude", "vscode")
	o.DryRun = true
	rep := mustInstall(t, o)
	if len(snapshot(t, home)) != 0 {
		t.Error("dry run wrote files")
	}
	for _, c := range rep.Changes {
		if c.Status != "would be created" {
			t.Errorf("dry run status %s: %s", c.Path, c.Status)
		}
	}

	mustInstall(t, opts(home, "claude", "vscode"))
	o = opts(home, "claude", "vscode")
	o.NoHooks = true
	st := statuses(mustInstall(t, o))
	// Both hook files only held secret-mask's hook, so they are removed.
	if st["hook "+filepath.Join(home, ".claude", "settings.json")] != "removed" || st["hook "+filepath.Join(home, ".copilot", "hooks", "secret-mask.json")] != "removed" {
		t.Errorf("--no-hooks: %v", st)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude.json")); err != nil {
		t.Error("--no-hooks must keep the MCP server")
	}
}

func TestForeignFilesAreLeftAlone(t *testing.T) {
	home := t.TempDir()
	skill := filepath.Join(home, ".claude", "skills", "secret-mask", "SKILL.md")
	os.MkdirAll(filepath.Dir(skill), 0o755)
	os.WriteFile(skill, []byte("my own skill\n"), 0o644)
	toml := filepath.Join(home, ".codex", "config.toml")
	os.MkdirAll(filepath.Dir(toml), 0o755)
	os.WriteFile(toml, []byte("[mcp_servers.secret-mask]\ncommand = \"custom\"\n"), 0o644)

	st := statuses(mustInstall(t, opts(home, "claude", "codex")))
	if !strings.HasPrefix(st["skill "+skill], "skipped") || !strings.HasPrefix(st["mcp "+toml], "skipped") {
		t.Errorf("statuses = %v", st)
	}
	if readText(t, skill) != "my own skill\n" || !strings.HasPrefix(readText(t, toml), "[mcp_servers.secret-mask]\ncommand = \"custom\"") {
		t.Error("foreign file changed")
	}
	if _, err := Uninstall(opts(home, "claude")); err != nil || readText(t, skill) != "my own skill\n" {
		t.Errorf("uninstall touched a foreign skill: %v", err)
	}

	o := opts(home, "claude")
	o.Force = true
	mustInstall(t, o)
	if readText(t, skill) != Skill {
		t.Error("--force did not replace the skill")
	}
}

func TestInstallErrors(t *testing.T) {
	home := t.TempDir()
	if _, err := Install(opts(home, "emacs")); err == nil || !strings.Contains(err.Error(), "unknown client") {
		t.Errorf("unknown client: %v", err)
	}
	p := filepath.Join(home, ".cursor", "mcp.json")
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, []byte("{ // comment\n}"), 0o644)
	rep, err := Install(opts(home, "cursor"))
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("JSONC: %v", err)
	}
	// The other files of the client are still written.
	if st := statuses(rep); st["hook "+filepath.Join(home, ".cursor", "hooks.json")] != "created" {
		t.Errorf("statuses = %v", st)
	}
}

func TestHookCommandQuoting(t *testing.T) {
	e := &agentEnv{InstallOptions{Command: []string{"/Applications/My Tools/secret-mask"}}}
	cmd := e.hookCommand("codex")
	if cmd != "'/Applications/My Tools/secret-mask' hook --client codex" || !isOurHook(cmd) {
		t.Errorf("command = %q", cmd)
	}
	e = &agentEnv{InstallOptions{Command: strings.Fields("docker run --rm -i ghcr.io/x/secret-mask:latest")}}
	if !isOurHook(e.hookCommand("")) {
		t.Error("docker hook not recognized")
	}
	for _, c := range []string{"secret-mask hook --other", "other-tool hook", "secret-mask mcp"} {
		if isOurHook(c) {
			t.Errorf("%q recognized as ours", c)
		}
	}
}

func TestPluginSkillMatches(t *testing.T) {
	plugin := readText(t, filepath.Join("..", "..", "plugin", "skills", "secret-mask", "SKILL.md"))
	if plugin != Skill {
		t.Error("plugin/skills/secret-mask/SKILL.md differs from internal/setup/skill/SKILL.md; copy it")
	}
}

func TestUpgradeRefreshesOwnedFiles(t *testing.T) {
	home := t.TempDir()
	skill := filepath.Join(home, ".claude", "skills", "secret-mask", "SKILL.md")
	os.MkdirAll(filepath.Dir(skill), 0o755)
	// What an older release wrote: still marked as managed, different text.
	os.WriteFile(skill, []byte("---\nname: secret-mask\n---\n<!-- "+skillMark+" -->\nold rules\n"), 0o644)
	st := statuses(mustInstall(t, opts(home, "claude")))
	if st["skill "+skill] != "updated" || readText(t, skill) != Skill {
		t.Errorf("old skill not refreshed: %v", st)
	}
}
