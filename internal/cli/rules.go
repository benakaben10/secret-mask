package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/benakaben10/secret-mask/internal/detect"
	"github.com/benakaben10/secret-mask/internal/mcp"
)

// rules lists the detection rules a scan of dir uses.
func (a *App) rules(args []string) error {
	fs := a.flagSet("rules")
	config := fs.String("config", "", "gitleaks config (default: $GITLEAKS_CONFIG, then <dir>/.gitleaks.toml)")
	id := fs.String("id", "", "show one rule in full (regex, keywords, allowlists)")
	source := fs.String("source", "", "only rules from: gitleaks, secret-mask or project")
	asJSON := fs.Bool("json", false, "print the rules (with every detail) as JSON")
	dir, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	set, err := detect.Rules(dir, *config)
	if err != nil {
		return err
	}
	if *id != "" {
		i := slices.IndexFunc(set.Rules, func(r detect.RuleInfo) bool { return r.ID == *id })
		if i < 0 {
			return &UsageError{fmt.Sprintf("no rule %q (see `secret-mask rules %s`)", *id, dir)}
		}
		out, _ := json.MarshalIndent(set.Rules[i], "", "  ")
		fmt.Fprintln(a.Stdout, string(out))
		return nil
	}
	rules := filterRules(set.Rules, "", *source)
	if *asJSON {
		out, _ := json.MarshalIndent(detect.RuleSet{Config: set.Config, Rules: rules, Allowlists: set.Allowlists}, "", "  ")
		fmt.Fprintln(a.Stdout, string(out))
		return nil
	}
	fmt.Fprint(a.Stdout, rulesHeader(set))
	for _, r := range rules {
		fmt.Fprintf(a.Stdout, "  %-45s %-12s %s\n", r.ID, r.Source, firstSentence(r.Description))
	}
	return nil
}

func rulesHeader(set *detect.RuleSet) string {
	counts := map[string]int{}
	for _, r := range set.Rules {
		counts[r.Source]++
	}
	cfg := set.Config
	if cfg == "" {
		cfg = "built-in gitleaks rules (no .gitleaks.toml)"
	}
	return fmt.Sprintf("Config: %s\n%d rules: %d gitleaks, %d secret-mask, %d project; %d global allowlist(s).\n",
		cfg, len(set.Rules), counts[detect.SourceGitleaks], counts[detect.SourceSecretMask], counts[detect.SourceProject], len(set.Allowlists))
}

func filterRules(rules []detect.RuleInfo, query, source string) []detect.RuleInfo {
	query = strings.ToLower(query)
	var out []detect.RuleInfo
	for _, r := range rules {
		if source != "" && r.Source != source {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(r.ID+" "+r.Description), query) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i > 0 {
		s = s[:i+1]
	}
	if len(s) > 110 {
		s = s[:107] + "..."
	}
	return s
}

// ruleSpecSchema is the JSON schema of a detect.RuleSpec plus extra properties.
func ruleSpecSchema(required []string, extra map[string]any) map[string]any {
	props := map[string]any{
		"id":           map[string]any{"type": "string", "description": "rule id: lowercase letters, digits, '.', '_', '-' (e.g. acme-api-token)"},
		"description":  map[string]any{"type": "string", "description": "what the rule finds"},
		"regex":        map[string]any{"type": "string", "description": "Go RE2 regex (no lookaround). Put the secret value in a capture group: only that part is masked"},
		"secret_group": map[string]any{"type": "integer", "description": "capture group holding the secret (default: first non-empty group, else the whole match)"},
		"entropy":      map[string]any{"type": "number", "description": "minimum Shannon entropy of the secret (0 = off; 3-4 filters out words)"},
		"keywords":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "lowercase strings one of which must be in the file before the regex runs (speed)"},
		"path":         map[string]any{"type": "string", "description": "only scan files whose project-relative path matches this regex, e.g. \\.env$"},
		"allowlist_regexes": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
			"description": "secret values to ignore (regexes), e.g. ^changeme$"},
	}
	for k, v := range extra {
		props[k] = v
	}
	return map[string]any{"type": "object", "properties": props, "required": required}
}

func parseSpec(raw json.RawMessage) (detect.RuleSpec, map[string]any, error) {
	var spec detect.RuleSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return spec, nil, fmt.Errorf("invalid arguments: %w", err)
	}
	var all map[string]any
	_ = json.Unmarshal(raw, &all) // same document as spec, already parsed above
	return spec, all, nil
}

func describeMatches(title string, matches []detect.Match) string {
	if len(matches) == 0 {
		return title + ": no match\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d match(es)\n", title, len(matches))
	for _, m := range matches {
		if m.Secret != "" {
			fmt.Fprintf(&b, "  %s:%d  secret (masked part) = %q\n", m.File, m.Line, m.Secret)
		} else {
			fmt.Fprintf(&b, "  %s:%d\n", m.File, m.Line)
		}
	}
	return b.String()
}

// ruleTools are the MCP tools to read the detection rules and add new ones.
func (a *App) ruleTools(root, config string) []mcp.Tool {
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	return []mcp.Tool{
		{
			Name: "list_rules",
			Description: "List the detection rules every scan of this project uses (check_secrets, the read hook, mask, " +
				"pre-commit): built-in gitleaks rules, secret-mask's password rules and the project's own .gitleaks.toml rules. " +
				"Filter with query/source, page with offset/limit; details=true returns each rule in full as JSON.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"query":   map[string]any{"type": "string", "description": "substring of the rule id or description, e.g. password, aws"},
				"source":  map[string]any{"type": "string", "enum": []string{detect.SourceGitleaks, detect.SourceSecretMask, detect.SourceProject}},
				"details": map[string]any{"type": "boolean", "description": "include regex, secret group, entropy, keywords, path and allowlists"},
				"offset":  map[string]any{"type": "integer", "minimum": 0},
				"limit":   map[string]any{"type": "integer", "minimum": 1, "maximum": 500, "description": "default 100"},
			}},
			Handler: func(ctx context.Context, raw json.RawMessage) (string, error) {
				var args struct {
					Query, Source string
					Details       bool
					Offset, Limit int
				}
				if err := json.Unmarshal(raw, &args); err != nil {
					return "", fmt.Errorf("invalid arguments: %w", err)
				}
				set, err := detect.Rules(root, config)
				if err != nil {
					return "", err
				}
				rules := filterRules(set.Rules, args.Query, args.Source)
				total := len(rules)
				if args.Limit <= 0 {
					args.Limit = 100
				}
				rules = rules[min(args.Offset, total):min(args.Offset+args.Limit, total)]
				var b strings.Builder
				b.WriteString(rulesHeader(set))
				fmt.Fprintf(&b, "Showing %d-%d of %d matching rule(s).\n", min(args.Offset+1, total), args.Offset+len(rules), total)
				if args.Details {
					out, _ := json.MarshalIndent(rules, "", "  ")
					b.Write(out)
					b.WriteString("\n")
				} else {
					for _, r := range rules {
						fmt.Fprintf(&b, "%s [%s] %s\n", r.ID, r.Source, firstSentence(r.Description))
					}
				}
				if args.Offset == 0 && args.Query == "" && args.Source == "" && len(set.Allowlists) > 0 {
					out, _ := json.MarshalIndent(set.Allowlists, "", "  ")
					fmt.Fprintf(&b, "Global allowlists (paths and values never reported):\n%s\n", out)
				}
				if args.Offset+len(rules) < total {
					fmt.Fprintf(&b, "More: call again with offset=%d.\n", args.Offset+len(rules))
				}
				return b.String(), nil
			},
		},
		{
			Name:        "get_rule",
			Description: "One detection rule in full, as JSON: regex, secret group, entropy, keywords, path filter, allowlists and source.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"id": map[string]any{"type": "string", "description": "rule id, from list_rules"},
			}, "required": []string{"id"}},
			Handler: func(ctx context.Context, raw json.RawMessage) (string, error) {
				var args struct{ ID string }
				if err := json.Unmarshal(raw, &args); err != nil {
					return "", fmt.Errorf("invalid arguments: %w", err)
				}
				set, err := detect.Rules(root, config)
				if err != nil {
					return "", err
				}
				i := slices.IndexFunc(set.Rules, func(r detect.RuleInfo) bool { return r.ID == args.ID })
				if i < 0 {
					return "", fmt.Errorf("no rule %q; call list_rules with query to find it", args.ID)
				}
				out, _ := json.MarshalIndent(set.Rules[i], "", "  ")
				return string(out) + "\n", nil
			},
		},
		{
			Name: "test_rule",
			Description: "Try a new detection rule before adding it. It runs alone over `sample` (text you provide; the matched " +
				"secret is shown so you can check what would be masked) and, with scan_project=true, over the project files " +
				"(locations only, never values). Nothing is written.",
			InputSchema: ruleSpecSchema([]string{"regex"}, map[string]any{
				"sample":       map[string]any{"type": "string", "description": "example text with fake secrets that the rule should (or should not) match"},
				"sample_path":  map[string]any{"type": "string", "description": "file name the sample is scanned as (matters for `path`), default sample.txt"},
				"scan_project": map[string]any{"type": "boolean", "description": "also run the rule over the project (locations only)"},
			}),
			Handler: func(ctx context.Context, raw json.RawMessage) (string, error) {
				spec, all, err := parseSpec(raw)
				if err != nil {
					return "", err
				}
				projectRoot := ""
				if scan, _ := all["scan_project"].(bool); scan {
					projectRoot = root
				}
				sample, project, err := detect.TestRule(ctx, spec, str(all, "sample"), str(all, "sample_path"), projectRoot)
				if err != nil {
					return "", err
				}
				block, _ := spec.TOML()
				var b strings.Builder
				fmt.Fprintf(&b, "Rule is valid:\n%s\n", block)
				if str(all, "sample") != "" {
					b.WriteString(describeMatches("Sample", sample))
				}
				if projectRoot != "" {
					b.WriteString(describeMatches("Project (rule alone, project allowlists not applied)", project))
				}
				b.WriteString("When it matches what you expect, add it with add_rule.\n")
				return b.String(), nil
			},
		},
		{
			Name: "add_rule",
			Description: "Add a new detection rule to the project's .gitleaks.toml (created with the default rules kept on). " +
				"It only adds: an existing rule id is refused, so rules cannot be replaced, disabled or allowlisted with it. " +
				"If `sample` is given, the rule must match it or nothing is written. Test it with test_rule first. " +
				"Afterwards every scan uses it; secrets it finds must be masked by the user (`secret-mask mask`).",
			InputSchema: ruleSpecSchema([]string{"id", "regex"}, map[string]any{
				"sample":      map[string]any{"type": "string", "description": "example text the rule must match"},
				"sample_path": map[string]any{"type": "string", "description": "file name the sample is scanned as, default sample.txt"},
			}),
			Handler: func(ctx context.Context, raw json.RawMessage) (string, error) {
				spec, all, err := parseSpec(raw)
				if err != nil {
					return "", err
				}
				if sample := str(all, "sample"); sample != "" {
					matches, _, err := detect.TestRule(ctx, spec, sample, str(all, "sample_path"), "")
					if err != nil {
						return "", err
					}
					if len(matches) == 0 {
						return "", fmt.Errorf("the rule does not match the sample; nothing was written")
					}
				}
				path, err := detect.AddRule(root, spec)
				if err != nil {
					return "", err
				}
				findings, err := checkPath(ctx, root, root, config)
				if err != nil {
					return "", err
				}
				n := 0
				for _, f := range findings {
					if f.RuleID == spec.ID {
						n++
					}
				}
				text := fmt.Sprintf("Added rule %q to %s.\n", spec.ID, path)
				if n > 0 {
					text += fmt.Sprintf("It finds %d unmasked secret(s) in the project. Do not read them; ask the user to run: secret-mask mask %s\n", n, root)
				} else {
					text += "It finds nothing unmasked in the project right now.\n"
				}
				return text, nil
			},
		},
	}
}
