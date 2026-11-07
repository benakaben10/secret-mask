// Package hook implements a Claude Code PreToolUse hook that blocks AI agents from reading files that
// still contain unmasked secrets. It fails closed: any error denies the read.
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

// Matcher is the PreToolUse matcher for tools that read file contents.
const Matcher = "Read|Grep|NotebookRead"

// Input is the subset of the Claude Code hook payload that is used.
type Input struct {
	Cwd           string         `json:"cwd"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
}

// Checker returns the unmasked findings for target (relative to root).
type Checker func(root, target string) ([]detect.Finding, error)

// Decision is the hook outcome.
type Decision struct {
	Allow  bool
	Reason string
}

// Evaluate decides whether the tool call may proceed. projectDir is $CLAUDE_PROJECT_DIR (may be empty);
// ownFiles are file names never scanned (the vault and the AI guide).
func Evaluate(raw []byte, projectDir string, ownFiles map[string]bool, check Checker) Decision {
	var in Input
	if err := json.Unmarshal(raw, &in); err != nil {
		return deny("secret-mask hook could not parse its input (%v); reading is blocked to be safe.", err)
	}
	target := targetOf(in)
	if target == "" {
		if in.ToolName != "Grep" {
			return Decision{Allow: true}
		}
		target = "."
	}

	root := projectDir
	if root == "" {
		root = in.Cwd
	}
	if root == "" {
		root, _ = os.Getwd()
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(in.Cwd, target)
	}
	target = filepath.Clean(target)
	if ownFiles[filepath.Base(target)] {
		return Decision{Allow: true}
	}
	info, err := os.Stat(target)
	if err != nil {
		// Nothing to read; let the tool report the error itself.
		return Decision{Allow: true}
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		// Outside the project: scan it on its own.
		root, rel = filepath.Dir(target), filepath.Base(target)
		if info.IsDir() {
			root, rel = target, "."
		}
	}

	findings, err := check(root, rel)
	if err != nil {
		return deny("secret-mask could not scan %s for secrets (%v); reading is blocked to be safe.", target, err)
	}
	if len(findings) == 0 {
		return Decision{Allow: true}
	}
	return deny("%s", blockMessage(root, findings))
}

func targetOf(in Input) string {
	for _, key := range []string{"file_path", "notebook_path", "path"} {
		if v, ok := in.ToolInput[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
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
	fmt.Fprintf(&b, "Stop and ask the user to run this themselves in a terminal (it needs their password), then retry:\n")
	fmt.Fprintf(&b, "  secret-mask mask %s\n", root)
	b.WriteString("Do not try to read these files another way (cat, grep, editors) and do not ask the user to paste secrets.")
	return b.String()
}

func deny(format string, args ...any) Decision {
	return Decision{Reason: fmt.Sprintf(format, args...)}
}

// Output renders the decision as Claude Code hook JSON. Allow returns nil (no output, exit 0).
func Output(d Decision) []byte {
	if d.Allow {
		return nil
	}
	out, _ := json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": d.Reason,
		},
	})
	return out
}
