package detect

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	gitleaksconfig "github.com/zricethezav/gitleaks/v8/config"

	"github.com/benakaben10/secret-mask/internal/fsutil"
)

// Rule sources.
const (
	SourceGitleaks   = "gitleaks"    // built-in gitleaks rules
	SourceSecretMask = "secret-mask" // BuiltinRules
	SourceProject    = "project"     // the project's (or an explicit) config
)

// AllowlistInfo describes an allowlist in plain strings.
type AllowlistInfo struct {
	Description string   `json:"description,omitempty"`
	Condition   string   `json:"condition,omitempty"`   // OR (default) or AND
	RegexTarget string   `json:"regexTarget,omitempty"` // secret (default), match or line
	Regexes     []string `json:"regexes,omitempty"`
	Paths       []string `json:"paths,omitempty"`
	StopWords   []string `json:"stopwords,omitempty"`
}

// RuleInfo describes an active rule in plain strings.
type RuleInfo struct {
	ID          string          `json:"id"`
	Source      string          `json:"source"`
	Description string          `json:"description,omitempty"`
	Regex       string          `json:"regex,omitempty"`
	SecretGroup int             `json:"secretGroup,omitempty"`
	Entropy     float64         `json:"entropy,omitempty"`
	Path        string          `json:"path,omitempty"`
	Keywords    []string        `json:"keywords,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	Allowlists  []AllowlistInfo `json:"allowlists,omitempty"`
}

// RuleSet is the effective configuration of a scan of a project.
type RuleSet struct {
	Config     string          `json:"config"` // config file in use, "" = built-in gitleaks rules
	Rules      []RuleInfo      `json:"rules"`  // sorted by id
	Allowlists []AllowlistInfo `json:"allowlists,omitempty"`
}

var ruleIDLine = regexp.MustCompile(`(?m)^\s*id\s*=\s*["']([^"']+)["']`)

func ruleIDs(toml string) map[string]bool {
	ids := map[string]bool{}
	for _, m := range ruleIDLine.FindAllStringSubmatch(toml, -1) {
		ids[m[1]] = true
	}
	return ids
}

// Rules returns every rule a scan of root uses, with where it comes from.
func Rules(root, config string) (*RuleSet, error) {
	path := ConfigPath(root, config)
	cfg, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}
	own := map[string]bool{}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		own = ruleIDs(string(data))
	}
	builtin := ruleIDs(BuiltinRules)
	set := &RuleSet{Config: path}
	for _, id := range slices.Sorted(maps.Keys(cfg.Rules)) {
		r := cfg.Rules[id]
		info := RuleInfo{
			ID: id, Description: r.Description, SecretGroup: r.SecretGroup, Entropy: r.Entropy,
			Keywords: r.Keywords, Tags: r.Tags, Allowlists: allowlistInfos(r.Allowlists),
		}
		if r.Regex != nil {
			info.Regex = r.Regex.String()
		}
		if r.Path != nil {
			info.Path = r.Path.String()
		}
		switch {
		case own[id]:
			info.Source = SourceProject
		case builtin[id]:
			info.Source = SourceSecretMask
		default:
			info.Source = SourceGitleaks
		}
		set.Rules = append(set.Rules, info)
	}
	set.Allowlists = allowlistInfos(cfg.Allowlists)
	return set, nil
}

func allowlistInfos(list []*gitleaksconfig.Allowlist) []AllowlistInfo {
	var out []AllowlistInfo
	for _, a := range list {
		info := AllowlistInfo{Description: a.Description, RegexTarget: a.RegexTarget, StopWords: a.StopWords}
		if a.MatchCondition == gitleaksconfig.AllowlistMatchAnd {
			info.Condition = "AND"
		}
		for _, r := range a.Regexes {
			info.Regexes = append(info.Regexes, r.String())
		}
		for _, p := range a.Paths {
			info.Paths = append(info.Paths, p.String())
		}
		out = append(out, info)
	}
	return out
}

// RuleSpec is a new rule to test or add.
type RuleSpec struct {
	ID            string   `json:"id"`
	Description   string   `json:"description"`
	Regex         string   `json:"regex"`
	SecretGroup   int      `json:"secret_group"`
	Entropy       float64  `json:"entropy"`
	Keywords      []string `json:"keywords"`
	Path          string   `json:"path"`
	AllowlistRegs []string `json:"allowlist_regexes"` // values (the secret) to ignore
}

var validRuleID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)

// TOML renders the rule as a [[rules]] block.
func (s RuleSpec) TOML() (string, error) {
	id := s.ID
	if id == "" {
		id = "test-rule"
	}
	if !validRuleID.MatchString(id) {
		return "", fmt.Errorf("rule id %q: use 2-64 lowercase letters, digits, '.', '_' or '-'", id)
	}
	if s.Regex == "" {
		return "", errors.New("regex is required")
	}
	lit := func(name, v string) (string, error) {
		if strings.Contains(v, "'''") {
			return "", fmt.Errorf("%s must not contain '''", name)
		}
		return "'''" + v + "'''", nil
	}
	var b strings.Builder
	b.WriteString("[[rules]]\n")
	fmt.Fprintf(&b, "id = %s\n", strconv.Quote(id))
	if s.Description != "" {
		fmt.Fprintf(&b, "description = %s\n", strconv.Quote(s.Description))
	}
	re, err := lit("regex", s.Regex)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "regex = %s\n", re)
	if s.SecretGroup > 0 {
		fmt.Fprintf(&b, "secretGroup = %d\n", s.SecretGroup)
	}
	if s.Entropy > 0 {
		fmt.Fprintf(&b, "entropy = %s\n", strconv.FormatFloat(s.Entropy, 'f', -1, 64))
	}
	if s.Path != "" {
		p, err := lit("path", s.Path)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "path = %s\n", p)
	}
	if len(s.Keywords) > 0 {
		kw := make([]string, len(s.Keywords))
		for i, k := range s.Keywords {
			kw[i] = strconv.Quote(strings.ToLower(k))
		}
		fmt.Fprintf(&b, "keywords = [%s]\n", strings.Join(kw, ", "))
	}
	if len(s.AllowlistRegs) > 0 {
		var regs []string
		for _, r := range s.AllowlistRegs {
			l, err := lit("allowlist regex", r)
			if err != nil {
				return "", err
			}
			regs = append(regs, l)
		}
		fmt.Fprintf(&b, "[[rules.allowlists]]\nregexes = [%s]\n", strings.Join(regs, ", "))
	}
	return b.String(), nil
}

// Validate checks that the rule compiles the way gitleaks loads it (regex syntax, secretGroup range).
func (s RuleSpec) Validate() error {
	block, err := s.TOML()
	if err != nil {
		return err
	}
	configMu.Lock()
	defer configMu.Unlock()
	_, err = loadConfig("", block, false)
	return err
}

// Match is a finding of a tested rule.
type Match struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Secret string `json:"secret,omitempty"` // only for sample text, never for project files
}

// TestRule runs spec alone over sample (saved as samplePath inside a temporary directory) and, when root
// is set, over the project. Project matches carry no secret value.
func TestRule(ctx context.Context, spec RuleSpec, sample, samplePath, root string) (sampleMatches, projectMatches []Match, err error) {
	if err := spec.Validate(); err != nil {
		return nil, nil, err
	}
	block, _ := spec.TOML()
	id := spec.ID
	if id == "" {
		id = "test-rule"
	}
	tmp, err := os.MkdirTemp("", "secret-mask-rule-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmp)
	cfg := filepath.Join(tmp, "rule.toml")
	if err := os.WriteFile(cfg, []byte(block), 0o600); err != nil {
		return nil, nil, err
	}
	only := func(findings []Finding, withSecret bool) []Match {
		var out []Match
		for _, f := range findings {
			if f.RuleID == id {
				m := Match{File: f.File, Line: f.StartLine}
				if withSecret {
					m.Secret = f.Secret
				}
				out = append(out, m)
			}
		}
		return out
	}
	if sample != "" {
		if samplePath == "" {
			samplePath = "sample.txt"
		}
		if !filepath.IsLocal(filepath.FromSlash(samplePath)) {
			return nil, nil, fmt.Errorf("sample_path %q must be a relative path", samplePath)
		}
		dir := filepath.Join(tmp, "sample")
		p := filepath.Join(dir, filepath.FromSlash(samplePath))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(p, []byte(sample), 0o600); err != nil {
			return nil, nil, err
		}
		findings, err := Scan(ctx, Options{Root: dir, Config: cfg})
		if err != nil {
			return nil, nil, err
		}
		sampleMatches = only(findings, true)
	}
	if root != "" {
		findings, err := Scan(ctx, Options{Root: root, Config: cfg})
		if err != nil {
			return nil, nil, err
		}
		projectMatches = only(findings, false)
	}
	return sampleMatches, projectMatches, nil
}

// AddRule appends spec to <root>/.gitleaks.toml (created with `[extend] useDefault = true`, so the default
// rules stay on). It only adds rules: an id that is already active is refused, so existing rules cannot be
// replaced, disabled or allowlisted this way. The file is restored if the result does not load.
func AddRule(root string, spec RuleSpec) (string, error) {
	if spec.ID == "" {
		return "", errors.New("id is required")
	}
	if err := spec.Validate(); err != nil {
		return "", err
	}
	path := filepath.Join(root, ".gitleaks.toml")
	if p := ConfigPath(root, ""); p != "" && p != path {
		return "", fmt.Errorf("scans use %s (from $GITLEAKS_CONFIG), so a rule in %s would have no effect; add it there by hand", p, path)
	}
	set, err := Rules(root, "")
	if err != nil {
		return "", err
	}
	if slices.ContainsFunc(set.Rules, func(r RuleInfo) bool { return r.ID == spec.ID }) {
		return "", fmt.Errorf("rule %q already exists; pick another id (existing rules cannot be changed this way)", spec.ID)
	}
	block, _ := spec.TOML()
	old, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	content := string(old)
	if !exists {
		content = "# gitleaks config used by secret-mask (and gitleaks). Default rules stay on:\n[extend]\nuseDefault = true\n"
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += "\n" + block
	perm := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		perm = st.Mode().Perm()
	}
	if err := fsutil.WriteFileAtomic(path, []byte(content), perm); err != nil {
		return "", err
	}
	restore := func() {
		if exists {
			fsutil.WriteFileAtomic(path, old, perm)
		} else {
			os.Remove(path)
		}
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		restore()
		return "", fmt.Errorf("%s no longer loads, change reverted: %w", path, err)
	}
	if _, ok := cfg.Rules[spec.ID]; !ok {
		restore()
		return "", fmt.Errorf("%s does not activate the new rule (does it disable it?), change reverted", path)
	}
	return path, nil
}
