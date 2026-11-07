// Package setup wires secret-mask into Claude Code: a PreToolUse hook in settings.json and an MCP
// server in .mcp.json. Existing settings are preserved and re-running is a no-op.
package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/OWNER/secret-mask/internal/fsutil"
	"github.com/OWNER/secret-mask/internal/hook"
)

// ServerName is the MCP server key.
const ServerName = "secret-mask"

// Options select where to install.
type Options struct {
	Scope      string // "project" (default) or "user"
	ProjectDir string // project root for the project scope
	HomeDir    string // home directory for the user scope
	Command    string // secret-mask executable as written into the config (default "secret-mask")
}

// Result lists what changed and anything left for the user to do.
type Result struct {
	Changed []string
	Notes   []string
}

// Apply installs the hook and the MCP server.
func Apply(o Options) (*Result, error) {
	if strings.TrimSpace(o.Command) == "" {
		o.Command = "secret-mask"
	}
	res := &Result{}
	var settingsPath string
	switch o.Scope {
	case "", "project":
		settingsPath = filepath.Join(o.ProjectDir, ".claude", "settings.json")
		mcpPath := filepath.Join(o.ProjectDir, ".mcp.json")
		changed, err := update(mcpPath, func(doc map[string]any) bool { return addMCPServer(doc, o.Command) })
		if err != nil {
			return nil, err
		}
		if changed {
			res.Changed = append(res.Changed, mcpPath)
		}
	case "user":
		settingsPath = filepath.Join(o.HomeDir, ".claude", "settings.json")
		res.Notes = append(res.Notes, fmt.Sprintf("register the MCP server for all projects with:\n  claude mcp add --scope user %s -- %s mcp", ServerName, o.Command))
	default:
		return nil, fmt.Errorf("unknown scope %q (project or user)", o.Scope)
	}
	changed, err := update(settingsPath, func(doc map[string]any) bool { return addHook(doc, o.Command+" hook") })
	if err != nil {
		return nil, err
	}
	if changed {
		res.Changed = append(res.Changed, settingsPath)
	}
	return res, nil
}

// update loads a JSON object (missing file = empty), applies fn and writes it back if fn changed it.
func update(path string, fn func(map[string]any) bool) (bool, error) {
	doc := map[string]any{}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &doc); err != nil {
			return false, fmt.Errorf("%s is not valid JSON: %w", path, err)
		}
		if doc == nil {
			doc = map[string]any{}
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return false, err
	}
	if !fn(doc) {
		return false, nil
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return true, fsutil.WriteFileAtomic(path, append(out, '\n'), 0o644)
}

func addHook(doc map[string]any, command string) bool {
	hooks := object(doc, "hooks")
	pre, _ := hooks["PreToolUse"].([]any)
	for _, e := range pre {
		entry, _ := e.(map[string]any)
		list, _ := entry["hooks"].([]any)
		for _, h := range list {
			if hm, _ := h.(map[string]any); hm["command"] == command {
				return false
			}
		}
	}
	hooks["PreToolUse"] = append(pre, map[string]any{
		"matcher": hook.Matcher,
		"hooks":   []any{map[string]any{"type": "command", "command": command, "timeout": 120}},
	})
	return true
}

// addMCPServer registers the server. A multi-word command (e.g. "docker run --rm -i image") becomes
// command + args, since MCP clients do not use a shell.
func addMCPServer(doc map[string]any, command string) bool {
	servers := object(doc, "mcpServers")
	fields := strings.Fields(command)
	args := []any{}
	for _, f := range fields[1:] {
		args = append(args, f)
	}
	want := map[string]any{"type": "stdio", "command": fields[0], "args": append(args, "mcp")}
	if cur, ok := servers[ServerName].(map[string]any); ok && sameServer(cur, want) {
		return false
	}
	servers[ServerName] = want
	return true
}

func sameServer(a, b map[string]any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// object returns doc[key] as an object, creating it if missing or not an object.
func object(doc map[string]any, key string) map[string]any {
	if m, ok := doc[key].(map[string]any); ok {
		return m
	}
	m := map[string]any{}
	doc[key] = m
	return m
}
