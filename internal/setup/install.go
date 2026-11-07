package setup

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/benakaben10/secret-mask/internal/fsutil"
	"github.com/benakaben10/secret-mask/internal/hook"
)

// Skill is the SKILL.md installed for agents that load skills (also shipped in the Claude Code plugin).
//
//go:embed skill/SKILL.md
var Skill string

// Instructions is the managed block written into an agent's global instructions (AGENTS.md, GEMINI.md).
const Instructions = `## Secrets (secret-mask)

Secrets in projects on this machine may be masked by secret-mask. Placeholders look like
` + "`__SECRET_MASK_<16 hex>__`" + `.

- Start of a task: call the secret-mask MCP tool ` + "`next_steps`" + ` (or run ` + "`secret-mask check <project>`" + `).
- Unmasked secrets (or a read BLOCKED by secret-mask): stop, do not read those files any other way, and ask the
  user to run ` + "`secret-mask mask <project>`" + ` in their terminal. It needs their password: never ask for it or for
  secret values. Continue only after they confirm and ` + "`next_steps`" + ` reports SAFE.
- A finding that may be a local-dev or test value: call ` + "`review_findings`" + ` (lines with values redacted) and let the
  user choose between masking it and allowlisting it themselves (.gitleaksignore / .gitleaks.toml); never do it yourself.
- Keep every placeholder byte-for-byte, quoting included. Moving it together with its setting is fine;
  replacing, re-encoding or inventing one is not.
- End of a task: ` + "`masking_status`" + ` must report missing: 0, then tell the user how to unseal:
  ` + "`secret-mask restore <project>`" + ` (` + "`--dry-run`" + ` to preview, ` + "`--clean`" + ` to also delete the vault).
- Never run ` + "`secret-mask mask`" + ` or ` + "`restore`" + ` yourself. ` + "`list_rules`" + ` shows the detection rules; ` + "`test_rule`" + `/` + "`add_rule`" + ` add one.
`

const (
	mdStart   = "<!-- secret-mask:start -->"
	mdEnd     = "<!-- secret-mask:end -->"
	tomlStart = "# >>> secret-mask MCP >>>"
	tomlEnd   = "# <<< secret-mask MCP <<<"
	skillMark = "managed by secret-mask"

	hookTimeout = 120 // seconds; Gemini counts milliseconds
	// Gemini CLI tools that read file contents or run commands.
	geminiMatcher = "read_file|read_many_files|grep_search|search_file_content|run_shell_command"
)

// InstallOptions select the agents and what is written for them.
type InstallOptions struct {
	Home     string
	Getenv   func(string) string
	LookPath func(name string) bool // command on PATH
	GOOS     string
	Command  []string // secret-mask argv written into the configs
	Clients  []string // ids to configure; empty = every detected client
	NoHooks  bool     // install without hooks, removing ones installed before
	DryRun   bool
	Force    bool // overwrite a skill or hook file secret-mask does not own
}

// Change is one file touched (or that would be touched) for a client.
type Change struct {
	Client, Kind, Path, Status string
}

// Report lists the changes, in client order.
type Report struct {
	Clients []string // display names of the clients handled
	Changes []Change
}

type editFn func(old []byte, exists bool) ([]byte, error)

type edit struct {
	kind, path      string
	install, remove editFn
	dir             bool // remove the parent directory once empty (skills)
}

type client struct {
	id, name string
	detect   func(e *agentEnv) bool
	edits    func(e *agentEnv) []edit
}

type agentEnv struct {
	InstallOptions
}

// ClientIDs lists the supported client ids.
func ClientIDs() []string {
	ids := make([]string, len(clients))
	for i, c := range clients {
		ids[i] = c.id
	}
	return ids
}

// Install configures the selected (or detected) clients: MCP server, hooks, skill and instructions.
func Install(o InstallOptions) (*Report, error) {
	return run(o, true)
}

// Uninstall removes everything Install wrote for the selected clients (default: all). Files keep the
// user's own content; files secret-mask owns are deleted.
func Uninstall(o InstallOptions) (*Report, error) {
	return run(o, false)
}

func run(o InstallOptions, install bool) (*Report, error) {
	e := &agentEnv{o}
	if e.Getenv == nil {
		e.Getenv = func(string) string { return "" }
	}
	if e.LookPath == nil {
		e.LookPath = func(string) bool { return false }
	}
	if len(e.Command) == 0 {
		e.Command = []string{"secret-mask"}
	}
	selected, err := e.selectClients(install)
	if err != nil {
		return nil, err
	}
	rep := &Report{}
	var errs []error
	done := map[string]bool{} // kind+path already handled by a client sharing it (VS Code, Copilot CLI)
	for _, c := range selected {
		rep.Clients = append(rep.Clients, c.name)
		for _, ed := range c.edits(e) {
			fn := ed.remove
			if install && !(e.NoHooks && ed.kind == "hook") {
				fn = ed.install
			}
			key := ed.kind + "\x00" + ed.path
			if done[key] {
				continue
			}
			done[key] = true
			status, err := e.apply(ed, fn)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %s: %w", c.name, ed.path, err))
				status = "failed: " + err.Error()
			}
			rep.Changes = append(rep.Changes, Change{Client: c.name, Kind: ed.kind, Path: ed.path, Status: status})
		}
	}
	return rep, errors.Join(errs...)
}

func (e *agentEnv) selectClients(install bool) ([]client, error) {
	if len(e.Clients) == 0 {
		var out []client
		for _, c := range clients {
			if !install || c.detect(e) {
				out = append(out, c)
			}
		}
		return out, nil
	}
	var out []client
	for _, id := range e.Clients {
		i := slices.IndexFunc(clients, func(c client) bool { return c.id == id })
		if i < 0 {
			return nil, fmt.Errorf("unknown client %q (%s)", id, strings.Join(ClientIDs(), ", "))
		}
		if !slices.ContainsFunc(out, func(c client) bool { return c.id == id }) {
			out = append(out, clients[i])
		}
	}
	return out, nil
}

// errForeign marks a file secret-mask does not own; it is reported and left alone.
type errForeign struct{ why string }

func (e *errForeign) Error() string { return e.why }

// apply runs fn on the file at ed.path and writes the result (nil = delete) unless this is a dry run.
func (e *agentEnv) apply(ed edit, fn editFn) (string, error) {
	old, err := os.ReadFile(ed.path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	out, err := fn(old, exists)
	var foreign *errForeign
	if errors.As(err, &foreign) {
		return "skipped: " + foreign.why, nil
	}
	if err != nil {
		return "", err
	}
	var status string
	switch {
	case out == nil && !exists, out != nil && exists && bytes.Equal(out, old):
		return "unchanged", nil
	case out == nil:
		status = "removed"
	case exists:
		status = "updated"
	default:
		status = "created"
	}
	if e.DryRun {
		return "would be " + status, nil
	}
	if out == nil {
		if err := os.Remove(ed.path); err != nil {
			return "", err
		}
		if ed.dir {
			os.Remove(filepath.Dir(ed.path)) // only succeeds when empty
		}
		return status, nil
	}
	perm := os.FileMode(0o644)
	if st, err := os.Stat(ed.path); err == nil {
		perm = st.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(ed.path), 0o755); err != nil {
		return "", err
	}
	return status, fsutil.WriteFileAtomic(ed.path, out, perm)
}

// ── clients ──────────────────────────────────────────────────────────────

var clients = []client{
	{
		id: "claude", name: "Claude Code",
		detect: func(e *agentEnv) bool { return isDir(e.claudeDir()) || e.LookPath("claude") },
		edits: func(e *agentEnv) []edit {
			userFile := filepath.Join(e.Home, ".claude.json")
			if d := e.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
				userFile = filepath.Join(d, ".claude.json")
			}
			return []edit{
				e.mcpEdit(userFile, "mcpServers", map[string]any{"type": "stdio"}),
				e.matcherHookEdit(filepath.Join(e.claudeDir(), "settings.json"), "PreToolUse", hook.Matcher, e.hookCommand(""), hookTimeout),
				e.skillEdit(filepath.Join(e.claudeDir(), "skills")),
			}
		},
	},
	{
		id: "codex", name: "Codex CLI",
		detect: func(e *agentEnv) bool { return isDir(e.codexDir()) || e.LookPath("codex") },
		edits: func(e *agentEnv) []edit {
			return []edit{
				e.codexMCPEdit(filepath.Join(e.codexDir(), "config.toml")),
				// Codex reads files through its shell tool, so the hook inspects shell commands.
				e.matcherHookEdit(filepath.Join(e.codexDir(), "hooks.json"), "PreToolUse", "Bash", e.hookCommand(hook.Codex), hookTimeout),
				blockEdit("instructions", filepath.Join(e.codexDir(), "AGENTS.md"), mdStart, mdEnd, Instructions, nil),
				e.skillEdit(filepath.Join(e.Home, ".agents", "skills")),
			}
		},
	},
	{
		id: "gemini", name: "Gemini CLI",
		detect: func(e *agentEnv) bool { return isDir(filepath.Join(e.Home, ".gemini")) || e.LookPath("gemini") },
		edits: func(e *agentEnv) []edit {
			settings := filepath.Join(e.Home, ".gemini", "settings.json")
			return []edit{
				e.mcpEdit(settings, "mcpServers", nil),
				e.matcherHookEdit(settings, "BeforeTool", geminiMatcher, e.hookCommand(hook.Gemini), hookTimeout*1000),
				blockEdit("instructions", filepath.Join(e.Home, ".gemini", "GEMINI.md"), mdStart, mdEnd, Instructions, nil),
			}
		},
	},
	{
		id: "cursor", name: "Cursor",
		detect: func(e *agentEnv) bool { return isDir(filepath.Join(e.Home, ".cursor")) },
		edits: func(e *agentEnv) []edit {
			return []edit{
				e.mcpEdit(filepath.Join(e.Home, ".cursor", "mcp.json"), "mcpServers", nil),
				e.cursorHookEdit(filepath.Join(e.Home, ".cursor", "hooks.json")),
				e.skillEdit(filepath.Join(e.Home, ".cursor", "skills")),
			}
		},
	},
	{
		id: "vscode", name: "VS Code (Copilot)",
		detect: func(e *agentEnv) bool { return isDir(e.vscodeUserDir()) },
		edits: func(e *agentEnv) []edit {
			return []edit{
				e.mcpEdit(filepath.Join(e.vscodeUserDir(), "mcp.json"), "servers", map[string]any{"type": "stdio"}),
				e.copilotHookEdit(filepath.Join(e.copilotDir(), "hooks", "secret-mask.json")),
				e.skillEdit(filepath.Join(e.copilotDir(), "skills")),
			}
		},
	},
	{
		id: "copilot", name: "GitHub Copilot CLI",
		detect: func(e *agentEnv) bool {
			return isFile(filepath.Join(e.copilotDir(), "mcp-config.json")) || e.LookPath("copilot")
		},
		edits: func(e *agentEnv) []edit {
			return []edit{
				e.mcpEdit(filepath.Join(e.copilotDir(), "mcp-config.json"), "mcpServers", map[string]any{"type": "local", "tools": []any{"*"}}),
				e.copilotHookEdit(filepath.Join(e.copilotDir(), "hooks", "secret-mask.json")),
				e.skillEdit(filepath.Join(e.copilotDir(), "skills")),
			}
		},
	},
}

func (e *agentEnv) dirFromEnv(name string, def ...string) string {
	if v := e.Getenv(name); v != "" {
		return v
	}
	return filepath.Join(append([]string{e.Home}, def...)...)
}

func (e *agentEnv) claudeDir() string  { return e.dirFromEnv("CLAUDE_CONFIG_DIR", ".claude") }
func (e *agentEnv) codexDir() string   { return e.dirFromEnv("CODEX_HOME", ".codex") }
func (e *agentEnv) copilotDir() string { return e.dirFromEnv("COPILOT_HOME", ".copilot") }

func (e *agentEnv) vscodeUserDir() string {
	switch e.GOOS {
	case "darwin":
		return filepath.Join(e.Home, "Library", "Application Support", "Code", "User")
	case "windows":
		return filepath.Join(e.dirFromEnv("APPDATA", "AppData", "Roaming"), "Code", "User")
	default:
		return filepath.Join(e.dirFromEnv("XDG_CONFIG_HOME", ".config"), "Code", "User")
	}
}

func isDir(p string) bool  { st, err := os.Stat(p); return err == nil && st.IsDir() }
func isFile(p string) bool { st, err := os.Stat(p); return err == nil && st.Mode().IsRegular() }

// ── commands ─────────────────────────────────────────────────────────────

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./\\-]+$`)

// hookCommand is the shell command line of the hook for client ("" = Claude Code's default format).
func (e *agentEnv) hookCommand(client string) string {
	words := make([]string, 0, len(e.Command)+3)
	for _, w := range e.Command {
		if !shellSafe.MatchString(w) {
			w = "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
		}
		words = append(words, w)
	}
	words = append(words, "hook")
	if client != "" {
		words = append(words, "--client", client)
	}
	return strings.Join(words, " ")
}

// isOurHook recognizes a hook command written by any secret-mask install, whatever its executable path.
func isOurHook(cmd string) bool {
	f := strings.Fields(cmd)
	for i, w := range f {
		if w == "hook" && i > 0 && strings.Contains(strings.Join(f[:i], " "), "secret-mask") {
			rest := f[i+1:]
			return len(rest) == 0 || (len(rest) == 2 && rest[0] == "--client")
		}
	}
	return false
}

// ── JSON edits ───────────────────────────────────────────────────────────

// jsonEdit applies fn to a JSON object file. A missing file is created only when create is set; an
// unchanged document keeps its original bytes. When removing (create unset), a document left empty is
// deleted: secret-mask created it.
func jsonEdit(create bool, fn func(doc map[string]any)) editFn {
	return func(old []byte, exists bool) ([]byte, error) {
		if !exists && !create {
			return nil, nil
		}
		doc := map[string]any{}
		if len(bytes.TrimSpace(old)) > 0 {
			if err := json.Unmarshal(old, &doc); err != nil {
				return nil, fmt.Errorf("not valid JSON (comments are not supported; edit it by hand): %w", err)
			}
			if doc == nil {
				doc = map[string]any{}
			}
		}
		before, _ := json.Marshal(doc)
		fn(doc)
		after, _ := json.Marshal(doc)
		if exists && bytes.Equal(before, after) {
			return old, nil
		}
		if !create && len(doc) == 0 {
			return nil, nil
		}
		out, err := json.MarshalIndent(doc, "", "  ")
		return append(out, '\n'), err
	}
}

func (e *agentEnv) mcpEdit(path, key string, extra map[string]any) edit {
	server := map[string]any{"command": e.Command[0], "args": mcpArgs(e.Command)}
	for k, v := range extra {
		server[k] = v
	}
	return edit{
		kind: "mcp", path: path,
		install: jsonEdit(true, func(doc map[string]any) { object(doc, key)[ServerName] = server }),
		remove: jsonEdit(false, func(doc map[string]any) {
			if servers, ok := doc[key].(map[string]any); ok {
				delete(servers, ServerName)
				if len(servers) == 0 {
					delete(doc, key)
				}
			}
		}),
	}
}

func mcpArgs(argv []string) []any {
	args := []any{}
	for _, a := range argv[1:] {
		args = append(args, a)
	}
	return append(args, "mcp")
}

// matcherHookEdit installs {"matcher", "hooks": [{type, command, timeout}]} under hooks.<event>, the
// format shared by Claude Code, Codex and Gemini CLI.
func (e *agentEnv) matcherHookEdit(path, event, matcher, command string, timeout int) edit {
	return edit{
		kind: "hook", path: path,
		install: jsonEdit(true, func(doc map[string]any) {
			removeOurHooks(doc)
			appendHook(doc, event, map[string]any{
				"matcher": matcher,
				"hooks":   []any{map[string]any{"type": "command", "command": command, "timeout": timeout}},
			})
		}),
		remove: jsonEdit(false, func(doc map[string]any) { removeOurHooks(doc) }),
	}
}

func (e *agentEnv) cursorHookEdit(path string) edit {
	command := e.hookCommand(hook.Cursor)
	return edit{
		kind: "hook", path: path,
		install: jsonEdit(true, func(doc map[string]any) {
			if _, ok := doc["version"]; !ok {
				doc["version"] = 1
			}
			removeOurHooks(doc)
			for _, event := range []string{"beforeReadFile", "beforeShellExecution"} {
				appendHook(doc, event, map[string]any{"command": command})
			}
		}),
		remove: jsonEdit(false, func(doc map[string]any) {
			if removeOurHooks(doc) && len(doc) == 1 && doc["version"] != nil {
				delete(doc, "version") // only what install added is left
			}
		}),
	}
}

// copilotHookEdit writes a hook manifest secret-mask owns. The PascalCase PreToolUse event selects the
// Claude Code payload and output format; without a matcher it sees every tool.
func (e *agentEnv) copilotHookEdit(path string) edit {
	command := e.hookCommand(hook.Copilot)
	ps := command
	if strings.HasPrefix(ps, "'") {
		ps = "& " + ps
	}
	manifest, _ := json.MarshalIndent(map[string]any{
		"version": 1,
		"hooks": map[string]any{
			"PreToolUse": []any{map[string]any{"type": "command", "bash": command, "powershell": ps, "timeoutSec": hookTimeout}},
		},
	}, "", "  ")
	owned := func(old []byte) bool {
		var doc map[string]any
		return json.Unmarshal(old, &doc) == nil && removeOurHooks(doc)
	}
	return ownedFileEdit("hook", path, append(manifest, '\n'), owned, e.Force, false)
}

func appendHook(doc map[string]any, event string, entry map[string]any) {
	hooks := object(doc, "hooks")
	list, _ := hooks[event].([]any)
	hooks[event] = append(list, entry)
}

// removeOurHooks drops every secret-mask hook from doc["hooks"], in any of the supported formats:
// {"hooks": [{"command"}]} groups, flat {"command"} entries and Copilot's {"bash"} entries. Groups and
// events left empty are removed. It reports whether anything was removed.
func removeOurHooks(doc map[string]any) bool {
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		return false
	}
	ours := func(v any) bool {
		m, _ := v.(map[string]any)
		for _, k := range []string{"command", "bash"} {
			if s, ok := m[k].(string); ok && isOurHook(s) {
				return true
			}
		}
		return false
	}
	removed := false
	for event, v := range hooks {
		list, ok := v.([]any)
		if !ok {
			continue
		}
		kept := []any{}
		for _, entry := range list {
			if ours(entry) {
				removed = true
				continue
			}
			if group, ok := entry.(map[string]any); ok {
				if inner, ok := group["hooks"].([]any); ok {
					keptInner := slices.DeleteFunc(slices.Clone(inner), ours)
					if len(keptInner) != len(inner) {
						removed = true
						if len(keptInner) == 0 {
							continue
						}
						group["hooks"] = keptInner
					}
				}
			}
			kept = append(kept, entry)
		}
		if len(kept) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = kept
		}
	}
	if removed && len(hooks) == 0 {
		delete(doc, "hooks")
	}
	return removed
}

// ── text edits ───────────────────────────────────────────────────────────

// blockEdit keeps body between the start and end markers of a text file, replacing an earlier block in
// place or appending one; remove cuts the block out. conflict reports content outside the block that
// would clash with it.
func blockEdit(kind, path, start, end, body string, conflict func(outside string) string) edit {
	return edit{
		kind: kind, path: path,
		install: func(old []byte, exists bool) ([]byte, error) {
			before, after, _ := cutBlock(string(old), start, end)
			if conflict != nil {
				if why := conflict(before + after); why != "" {
					return nil, &errForeign{why}
				}
			}
			block := start + "\n" + strings.TrimRight(body, "\n") + "\n" + end + "\n"
			if before != "" && !strings.HasSuffix(before, "\n\n") {
				before = strings.TrimRight(before, "\n") + "\n\n"
			}
			return []byte(before + block + after), nil
		},
		remove: func(old []byte, exists bool) ([]byte, error) {
			before, after, found := cutBlock(string(old), start, end)
			if !found {
				return old, nil
			}
			rest := strings.TrimRight(before, "\n")
			if rest != "" && after != "" {
				rest += "\n\n"
			}
			rest += strings.TrimLeft(after, "\n")
			if strings.TrimSpace(rest) == "" {
				return nil, nil
			}
			if !strings.HasSuffix(rest, "\n") {
				rest += "\n"
			}
			return []byte(rest), nil
		},
	}
}

// cutBlock splits s around the managed block (markers included, with its trailing newline).
func cutBlock(s, start, end string) (before, after string, found bool) {
	i := strings.Index(s, start)
	if i < 0 {
		return s, "", false
	}
	j := strings.Index(s[i:], end)
	if j < 0 {
		return s, "", false
	}
	k := i + j + len(end)
	if k < len(s) && s[k] == '\n' {
		k++
	}
	return s[:i], s[k:], true
}

// codexMCPEdit registers the MCP server in Codex's config.toml as a managed block. Codex passes only the
// variables named in env_vars to MCP servers.
func (e *agentEnv) codexMCPEdit(path string) edit {
	args := make([]string, 0, len(e.Command))
	for _, a := range mcpArgs(e.Command) {
		args = append(args, tomlString(a.(string)))
	}
	body := fmt.Sprintf("[mcp_servers.%s]\ncommand = %s\nargs = [%s]\nenv_vars = [\"GITLEAKS_CONFIG\"]\n",
		ServerName, tomlString(e.Command[0]), strings.Join(args, ", "))
	table := regexp.MustCompile(`(?m)^\s*\[\s*mcp_servers\.("?)` + regexp.QuoteMeta(ServerName) + `("?)\s*\]`)
	conflict := func(outside string) string {
		if table.MatchString(outside) {
			return "config.toml already has its own [mcp_servers." + ServerName + "] table"
		}
		return ""
	}
	return blockEdit("mcp", path, tomlStart, tomlEnd, body, conflict)
}

// tomlString is a TOML basic string.
func tomlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`).Replace(s) + `"`
}

// ownedFileEdit manages a whole file secret-mask owns. A different file already at path is foreign: it
// is left alone unless force is set, and never removed.
func ownedFileEdit(kind, path string, content []byte, owned func([]byte) bool, force, dir bool) edit {
	return edit{
		kind: kind, path: path, dir: dir,
		install: func(old []byte, exists bool) ([]byte, error) {
			if exists && !bytes.Equal(old, content) && !owned(old) && !force {
				return nil, &errForeign{"exists and was not written by secret-mask (use --force to replace it)"}
			}
			return content, nil
		},
		remove: func(old []byte, exists bool) ([]byte, error) {
			if exists && !owned(old) {
				return old, nil
			}
			return nil, nil
		},
	}
}

func (e *agentEnv) skillEdit(skillsDir string) edit {
	owned := func(old []byte) bool { return bytes.Contains(old, []byte(skillMark)) }
	return ownedFileEdit("skill", filepath.Join(skillsDir, ServerName, "SKILL.md"), []byte(Skill), owned, e.Force, true)
}

// ManagedBlock keeps body between the start and end marker lines of the text file at path, replacing an
// earlier block in place or appending one; an empty body removes the block. It returns the status
// ("created", "updated", "removed" or "unchanged").
func ManagedBlock(path, start, end, body string) (string, error) {
	ed := blockEdit("block", path, start, end, body, nil)
	fn := ed.install
	if body == "" {
		fn = ed.remove
	}
	return (&agentEnv{}).apply(ed, fn)
}
