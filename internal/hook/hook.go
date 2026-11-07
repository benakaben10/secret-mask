// Package hook implements the pre-tool hook that blocks AI agents from reading files that still contain
// unmasked secrets. It understands the hook payloads of Claude Code, Codex CLI, Gemini CLI, Cursor and
// GitHub Copilot (VS Code and CLI). It fails closed: any error denies the read.
package hook

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/benakaben10/secret-mask/internal/detect"
)

// Matcher is the Claude Code PreToolUse matcher for tools that read file contents.
const Matcher = "Read|Grep|NotebookRead"

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
// tool_name + tool_input; Cursor sends file_path or command at the top level.
type Input struct {
	Cwd            string         `json:"cwd"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	FilePath       string         `json:"file_path"`
	Command        string         `json:"command"`
	WorkspaceRoots []string       `json:"workspace_roots"`
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

// Evaluate decides whether the tool call may proceed. projectDir is the client's project directory
// (may be empty); ownFiles are file names never scanned (the vault and the AI guide).
func Evaluate(raw []byte, projectDir string, ownFiles map[string]bool, check Checker) Decision {
	var in Input
	if err := json.Unmarshal(raw, &in); err != nil {
		return deny("secret-mask hook could not parse its input (%v); reading is blocked to be safe.", err)
	}
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
	cwd := in.Cwd
	if cwd == "" {
		cwd = root
	}
	if dir, ok := in.ToolInput["directory"].(string); ok && dir != "" {
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
	for _, key := range []string{"file_path", "notebook_path", "path", "filePath", "absolute_path"} {
		if v, ok := in.ToolInput[key].(string); ok && v != "" {
			targets = append(targets, v)
		}
	}
	if paths, ok := in.ToolInput["paths"].([]any); ok {
		for _, p := range paths {
			if s, ok := p.(string); ok && s != "" {
				targets = append(targets, s)
			}
		}
	}
	switch cmd := in.ToolInput["command"].(type) {
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
	return targets
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
