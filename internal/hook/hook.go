// Package hook implements the pre-tool hook that blocks AI agents from reading files that still contain
// unmasked secrets, through their own tools, shell commands or other MCP servers (indexers, graph builders).
// It understands the hook payloads of Claude Code, Codex CLI, Gemini CLI, Cursor and GitHub Copilot (VS Code
// and CLI). It fails closed: any error denies the call. At session start it tells the agent to deal with
// unmasked secrets before anything else.
package hook

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/benakaben10/secret-mask/internal/detect"
)

// Matcher is the Claude Code PreToolUse matcher: the tools that read file contents, the shell, and every
// MCP tool (other servers may index or upload the project).
const Matcher = "Read|Grep|NotebookRead|Bash|mcp__.*"

// Clients whose hook payload and output format are supported.
const (
	Claude  = "claude"
	Codex   = "codex"
	Gemini  = "gemini"
	Cursor  = "cursor"
	Copilot = "copilot"
)

// Clients lists every supported client; Claude is the default.
var Clients = []string{Claude, Codex, Gemini, Cursor, Copilot}

// Input is the subset of the hook payloads that is used. Claude Code, Codex, Gemini and Copilot send
// tool_name + tool_input; Cursor sends file_path or command at the top level, and tool_input as a JSON string
// for MCP calls.
type Input struct {
	Cwd            string          `json:"cwd"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	FilePath       string          `json:"file_path"`
	Command        string          `json:"command"`
	WorkspaceRoots []string        `json:"workspace_roots"`

	args map[string]any // ToolInput as an object
}

func parseInput(raw []byte) (Input, error) {
	var in Input
	if err := json.Unmarshal(raw, &in); err != nil {
		return in, err
	}
	in.args = map[string]any{}
	if len(in.ToolInput) > 0 && json.Unmarshal(in.ToolInput, &in.args) != nil {
		var s string
		if json.Unmarshal(in.ToolInput, &s) == nil {
			_ = json.Unmarshal([]byte(s), &in.args) // Cursor MCP: a JSON document in a string; not JSON = no arguments
		}
	}
	if in.args == nil {
		in.args = map[string]any{}
	}
	return in, nil
}

func (in Input) root(projectDir string) string {
	root := projectDir
	if root == "" && len(in.WorkspaceRoots) > 0 {
		root = in.WorkspaceRoots[0]
	}
	if root == "" {
		root = in.Cwd
	}
	if root == "" {
		root, _ = os.Getwd()
	}
	return root
}

// Checker returns the unmasked findings for target (relative to root).
type Checker func(root, target string) ([]detect.Finding, error)

// Decision is the hook outcome.
type Decision struct {
	Allow  bool
	Reason string
}

// searchTools search a whole directory when no path is given.
var searchTools = map[string]bool{"Grep": true, "grep_search": true, "search_file_content": true, "grep": true, "rg": true}

var (
	// indexTools are MCP tools that read a whole project when given no path (indexers, graph builders,
	// uploaders); status, query and listing tools are not.
	indexTools   = regexp.MustCompile(`(?i)index|ingest|scan|embed|crawl|sync|upload|snapshot|build|analy[sz]e`)
	readOnlyMCPs = regexp.MustCompile(`(?i)status|list|get_|search|query|delete|trace|snippet|schema`)
	// mcpPathKeys are the arguments MCP tools commonly take a file or project path in.
	mcpPathKeys = []string{"repo_path", "project_path", "root", "dir", "repo", "file", "workspace"}
)

func isMCP(in Input) bool {
	return strings.HasPrefix(in.ToolName, "mcp__") || in.HookEventName == "beforeMCPExecution"
}

// revealRequested reports a shell command that runs `secret-mask reveal`, which prints real secrets and is
// for the user's own terminal only.
func revealRequested(in Input) bool {
	var cmds []string
	if in.Command != "" {
		cmds = append(cmds, in.Command)
	}
	switch c := in.args["command"].(type) {
	case string:
		cmds = append(cmds, c)
	case []any:
		for _, a := range c {
			if s, ok := a.(string); ok {
				cmds = append(cmds, s)
			}
		}
	}
	for _, c := range cmds {
		words := shellWords(c)
		for i, w := range words {
			if b := strings.TrimSuffix(filepath.Base(w), ".exe"); (b == "secret-mask" || strings.HasPrefix(b, "secret-mask_")) &&
				slices.Contains(words[i+1:], "reveal") {
				return true
			}
		}
	}
	return false
}

// Evaluate decides whether the tool call may proceed. projectDir is the client's project directory
// (may be empty); ownFiles are file names never scanned (the vault and the AI guide).
func Evaluate(raw []byte, projectDir string, ownFiles map[string]bool, check Checker) Decision {
	in, err := parseInput(raw)
	if err != nil {
		return deny("secret-mask hook could not parse its input (%v); reading is blocked to be safe.", err)
	}
	if revealRequested(in) {
		return deny("BLOCKED by secret-mask: `secret-mask reveal` prints the real secrets and is only for the user's own " +
			"terminal. An AI agent must never run it, and must never ask the user to paste its output.")
	}
	if isMCP(in) && strings.Contains(in.ToolName, "secret-mask") {
		return Decision{Allow: true} // secret-mask's own tools never return secret values
	}
	root := in.root(projectDir)
	cwd := in.Cwd
	if cwd == "" {
		cwd = root
	}
	if dir, ok := in.args["directory"].(string); ok && dir != "" && !isMCP(in) {
		cwd = resolve(root, dir) // Gemini's run_shell_command runs in this directory
	}

	for _, target := range targetsOf(in, cwd) {
		target = resolve(cwd, target)
		if ownFiles[filepath.Base(target)] {
			continue
		}
		info, err := os.Stat(target)
		if err != nil {
			// Nothing to read; let the tool report the error itself.
			continue
		}
		scanRoot, rel := root, ""
		if r, err := filepath.Rel(root, target); err == nil && r != ".." && !strings.HasPrefix(r, "../") {
			rel = r
		} else {
			// Outside the project: scan it on its own.
			scanRoot, rel = filepath.Dir(target), filepath.Base(target)
			if info.IsDir() {
				scanRoot, rel = target, "."
			}
		}
		findings, err := check(scanRoot, rel)
		if err != nil {
			return deny("secret-mask could not scan %s for secrets (%v); reading is blocked to be safe.", target, err)
		}
		if len(findings) > 0 {
			return deny("%s", blockMessage(scanRoot, findings))
		}
	}
	return Decision{Allow: true}
}

// targetsOf returns the paths a tool call reads, relative to cwd or absolute.
func targetsOf(in Input, cwd string) []string {
	if in.FilePath != "" {
		return []string{in.FilePath}
	}
	if in.Command != "" {
		return shellTargets(in.Command, cwd)
	}
	var targets []string
	keys := []string{"file_path", "notebook_path", "path", "filePath", "absolute_path"}
	if isMCP(in) {
		keys = append(keys, append(mcpPathKeys, "directory")...)
	}
	for _, key := range keys {
		if v, ok := in.args[key].(string); ok && v != "" {
			targets = append(targets, v)
		}
	}
	for _, key := range []string{"paths", "files"} {
		if paths, ok := in.args[key].([]any); ok {
			for _, p := range paths {
				if s, ok := p.(string); ok && s != "" {
					targets = append(targets, s)
				}
			}
		}
	}
	switch cmd := in.args["command"].(type) {
	case string:
		targets = append(targets, shellTargets(cmd, cwd)...)
	case []any:
		// Codex may pass argv, often ["bash", "-lc", "<script>"]: every element is parsed as shell.
		for _, a := range cmd {
			if s, ok := a.(string); ok {
				targets = append(targets, shellTargets(s, cwd)...)
			}
		}
	}
	if len(targets) == 0 && searchTools[in.ToolName] {
		targets = []string{"."}
	}
	// An MCP indexer called without a path works on the project it was started in.
	if len(targets) == 0 && isMCP(in) && indexTools.MatchString(in.ToolName) && !readOnlyMCPs.MatchString(in.ToolName) {
		targets = []string{"."}
	}
	return targets
}

// SessionContext is what the agent is told when a session starts: nothing when the project has no unmasked
// secret, otherwise to deal with them before any other work (indexing, graph building, reading files).
func SessionContext(raw []byte, projectDir string, check Checker) string {
	in, err := parseInput(raw)
	if err != nil {
		return ""
	}
	root := in.root(projectDir)
	findings, err := check(root, ".")
	if err != nil {
		return fmt.Sprintf("secret-mask could not scan %s for secrets (%v). Before indexing or reading files, call the "+
			"secret-mask MCP tool next_steps or run `secret-mask check %s`.", root, err, root)
	}
	if len(findings) == 0 {
		return ""
	}
	files := map[string]bool{}
	for _, f := range findings {
		files[f.File] = true
	}
	return fmt.Sprintf("secret-mask: this project has %d unmasked secret(s) in %s. Deal with this BEFORE anything else: "+
		"before indexing the project or building a code graph (other MCP servers), and before reading files. Tell the "+
		"user to run `secret-mask mask %s` in their own terminal (it needs their password) and wait for them; the "+
		"secret-mask MCP tool next_steps has the exact wording. Reads and indexing of these files are blocked until then.",
		len(findings), strings.Join(slices.Sorted(maps.Keys(files)), ", "), root)
}

// shellTargets is a best-effort reading of a shell command: every word naming an existing file is a
// target, glob words are expanded, and directories count only for recursive searches (rg, grep -r, …),
// which search the working directory when no path is given.
func shellTargets(command, cwd string) []string {
	words := shellWords(command)
	search := false
	for i, w := range words {
		switch filepath.Base(w) {
		case "rg", "ag", "ack":
			search = true
		case "grep", "egrep", "fgrep":
			if i > 0 && words[i-1] == "git" {
				search = true
				continue
			}
			for _, f := range words[i+1:] {
				if f == "--recursive" || f == "--dereference-recursive" ||
					(strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "--") && strings.ContainsAny(f, "rR")) {
					search = true
				}
			}
		}
	}
	var files, dirs []string
	seen := map[string]bool{}
	for _, w := range words {
		if strings.HasPrefix(w, "-") {
			_, v, ok := strings.Cut(w, "=") // --file=path
			if !ok {
				continue
			}
			w = v
		}
		if w == "" || strings.ContainsAny(w, "$`") {
			continue
		}
		candidates := []string{w}
		if strings.ContainsAny(w, "*?[") {
			candidates, _ = filepath.Glob(resolve(cwd, w))
		}
		for _, c := range candidates {
			p := resolve(cwd, c)
			if seen[p] {
				continue
			}
			info, err := os.Stat(p)
			if err != nil {
				continue
			}
			seen[p] = true
			if info.IsDir() {
				dirs = append(dirs, p)
			} else if info.Mode().IsRegular() {
				files = append(files, p)
			}
		}
	}
	if !search {
		return files
	}
	if len(files) == 0 && len(dirs) == 0 {
		return []string{cwd}
	}
	return append(files, dirs...)
}

// shellWords splits a command into words, honoring quotes and backslashes. Operators (| ; & < > ( ))
// separate words and are dropped, so "cat<.env" yields "cat" and ".env".
func shellWords(s string) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inWord = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				cur.WriteString(s[i+1:])
				i = len(s)
				break
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			inWord = true
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte(`"\$`+"`", s[i+1]) >= 0 {
					i++
				}
				cur.WriteByte(s[i])
			}
		case c == '\\' && i+1 < len(s):
			inWord = true
			i++
			cur.WriteByte(s[i])
		case strings.IndexByte(" \t\n|;&<>()", c) >= 0:
			flush()
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	flush()
	return words
}

func resolve(dir, p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[2:])
		}
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	return filepath.Clean(p)
}

func blockMessage(root string, findings []detect.Finding) string {
	perFile := map[string][]string{}
	for _, f := range findings {
		perFile[f.File] = append(perFile[f.File], fmt.Sprintf("line %d (%s)", f.StartLine, f.RuleID))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "BLOCKED by secret-mask: %d unmasked secret(s) found; this content must not be read until it is masked.\n", len(findings))
	for _, file := range slices.Sorted(maps.Keys(perFile)) {
		fmt.Fprintf(&b, "  %s: %s\n", file, strings.Join(perFile[file], ", "))
	}
	fmt.Fprintf(&b, "Stop the task and ask the user to run this themselves in a terminal (it needs their password), then retry:\n")
	fmt.Fprintf(&b, "  secret-mask mask %s\n", root)
	b.WriteString("Continue only after the user confirms. When the work is done, tell them the real values come back with:\n")
	fmt.Fprintf(&b, "  secret-mask restore %s\n", root)
	b.WriteString("Do not try to read these files another way (cat, grep, editors) and do not ask the user to paste secrets.")
	return b.String()
}

func deny(format string, args ...any) Decision {
	return Decision{Reason: fmt.Sprintf(format, args...)}
}

// Output renders the decision in the client's hook output format. A nil result means: print nothing.
func Output(client string, d Decision) []byte {
	var v any
	switch client {
	case Cursor:
		// Cursor expects an answer for every call.
		if d.Allow {
			v = map[string]any{"permission": "allow"}
		} else {
			v = map[string]any{
				"permission":    "deny",
				"user_message":  "secret-mask blocked this: unmasked secrets. Run `secret-mask mask` in a terminal.",
				"agent_message": d.Reason,
			}
		}
	case Gemini:
		if d.Allow {
			return nil
		}
		v = map[string]any{"decision": "deny", "reason": d.Reason}
	default: // Claude Code format, also read by Codex and Copilot
		if d.Allow {
			return nil
		}
		v = map[string]any{
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": d.Reason,
			},
		}
	}
	out, _ := json.Marshal(v)
	return out
}

// SessionOutput renders session-start context in the client's format (nil = nothing to say).
func SessionOutput(client, context string) []byte {
	if context == "" || client == Cursor || client == Gemini {
		return nil
	}
	out, _ := json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{"hookEventName": "SessionStart", "additionalContext": context},
	})
	return out
}
