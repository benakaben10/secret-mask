// Package detect finds secrets with gitleaks, embedded as a library: no external binary is needed and
// the rules always match the gitleaks version secret-mask was built with.
package detect

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	_ "unsafe" // go:linkname, see extendDepth

	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	gitleaksconfig "github.com/zricethezav/gitleaks/v8/config"
	gitleaks "github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// Finding is the subset of a gitleaks finding that masking needs.
type Finding struct {
	RuleID    string `json:"RuleID"`
	File      string `json:"File"`
	StartLine int    `json:"StartLine"`
	Secret    string `json:"Secret"`
}

// ErrRedacted means a report was produced with --redact and cannot be used for masking.
var ErrRedacted = errors.New("report is redacted; run gitleaks without --redact")

// BuiltinRules are secret-mask's own rules (self-chosen passwords), added to every config.
//
//go:embed rules.toml
var BuiltinRules string

// Options describe one scan.
type Options struct {
	Root   string // project root: base for relative paths, .gitleaks.toml and .gitleaksignore
	Target string // file or directory to scan, relative to Root (default ".")
	// Config is an optional gitleaks config. Default: $GITLEAKS_CONFIG, then <Root>/.gitleaks.toml,
	// then the built-in gitleaks rules. secret-mask's BuiltinRules are added to any of them.
	Config string
}

// ConfigPath returns the gitleaks config a scan of root uses ("" = the built-in rules).
func ConfigPath(root, config string) string {
	if config != "" {
		return config
	}
	if env := os.Getenv("GITLEAKS_CONFIG"); env != "" {
		return env
	}
	if p := filepath.Join(root, ".gitleaks.toml"); fileExists(p) {
		return p
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// maxFileSize matches the masking engine's limit.
const maxFileSize = 100 << 20

// gitleaks loads configs through the global viper instance (including `[extend]`), so loading is serialized.
var configMu sync.Mutex

// extendDepth is gitleaks' package-level counter of nested `[extend]` loads. gitleaks never resets it, so
// after two configs with `[extend] useDefault = true` in one process (the MCP server, a long hook run) it
// silently stops adding the default rules and skips rule validation. It is reset before every load.
//
//go:linkname extendDepth github.com/zricethezav/gitleaks/v8/config.extendDepth
var extendDepth int

func init() {
	// gitleaks logs to stderr at info level; keep stdout clean (MCP) and stderr quiet.
	logging.Logger = logging.Logger.Level(zerolog.ErrorLevel)
}

// Scan returns the unredacted findings under Root/Target, with paths relative to Root.
func Scan(ctx context.Context, o Options) ([]Finding, error) {
	if o.Target == "" {
		o.Target = "."
	}
	cfg, err := LoadConfig(ConfigPath(o.Root, o.Config))
	if err != nil {
		return nil, err
	}

	det := gitleaks.NewDetectorContext(ctx, cfg)
	det.MaxTargetMegaBytes = maxFileSize / 1_000_000
	// .gitleaksignore entries are root-relative (file:rule:line) and applied here.
	ignored, err := loadIgnore(filepath.Join(o.Root, ".gitleaksignore"))
	if err != nil {
		return nil, err
	}

	absRoot, err := filepath.Abs(o.Root)
	if err != nil {
		return nil, err
	}
	target := filepath.Join(absRoot, o.Target)
	if _, err := os.Stat(target); err != nil {
		return nil, err
	}
	results, err := det.DetectSource(ctx, &relFiles{root: absRoot, target: target, cfg: &cfg, sema: det})
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", target, err)
	}

	out := make([]Finding, 0, len(results))
	for _, r := range results {
		rel, ok := relTo(absRoot, r.File)
		if !ok || ignored[fmt.Sprintf("%s:%s:%d", rel, r.RuleID, r.StartLine)] {
			continue
		}
		out = append(out, Finding{RuleID: r.RuleID, File: rel, StartLine: r.StartLine, Secret: r.Secret})
	}
	return out, nil
}

// relFiles walks target like gitleaks' Files source, but gives gitleaks root-relative, slash-separated
// paths. Rule `path` patterns and path allowlists are therefore matched against "config/app.yaml", never
// against the absolute path (where a directory above the project could match them).
type relFiles struct {
	root, target string
	cfg          *gitleaksconfig.Config
	sema         *gitleaks.Detector
}

func (s *relFiles) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	var wg sync.WaitGroup
	err := filepath.WalkDir(s.target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, rerr := filepath.Rel(s.root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		skip := rel != "." && slices.ContainsFunc(s.cfg.Allowlists, func(a *gitleaksconfig.Allowlist) bool { return a.PathAllowed(rel) })
		if d.IsDir() {
			if skip || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if skip || !d.Type().IsRegular() {
			return nil // symlinks are not followed
		}
		if info, err := d.Info(); err != nil || info.Size() == 0 || info.Size() > maxFileSize {
			return nil
		}
		wg.Add(1)
		s.sema.Sema.Go(func() error {
			defer wg.Done()
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			return (&sources.File{Content: f, Path: rel, Config: s.cfg}).Fragments(ctx, yield)
		})
		return nil
	})
	wg.Wait()
	return err
}

// loadIgnore reads root-relative `file:rule:line` fingerprints. Commit fingerprints (4 fields) do not
// apply to a directory scan and are skipped.
func loadIgnore(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			continue
		}
		file := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(strings.ReplaceAll(parts[0], "\\", "/"))), "./")
		out[file+":"+parts[1]+":"+parts[2]] = true
	}
	return out, nil
}

// LoadConfig loads a gitleaks config file, or the built-in gitleaks rules when path is empty, and adds
// secret-mask's BuiltinRules unless the config defines the same id or disables it in [extend].
func LoadConfig(path string) (gitleaksconfig.Config, error) {
	configMu.Lock()
	defer configMu.Unlock()
	return loadConfig(path, "", true)
}

// loadConfig reads a config file (path), TOML text (text), or the gitleaks defaults when both are empty.
// With builtin, secret-mask's rules join the config's own rules before gitleaks assembles it, so they can be
// targeted by `[[allowlists]] targetRules` like any rule. The caller holds configMu.
func loadConfig(path, text string, builtin bool) (cfg gitleaksconfig.Config, err error) {
	name := path
	// gitleaks panics on invalid rule regexes.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("gitleaks config %s: %v", name, r)
		}
	}()
	var extra gitleaksconfig.ViperConfig
	if builtin {
		if extra, err = readViper("", BuiltinRules); err != nil {
			return cfg, fmt.Errorf("secret-mask rules: %w", err)
		}
	}
	switch {
	case path != "":
	case text != "":
		name = "(inline)"
	default:
		name = "(built-in)"
	}
	vc, err := readViper(path, text)
	if err != nil {
		return cfg, fmt.Errorf("gitleaks config %s: %w", name, err)
	}
	for _, r := range extra.Rules {
		defined := false
		for i := range vc.Rules {
			defined = defined || vc.Rules[i].ID == r.ID
		}
		if !defined && !slices.Contains(vc.Extend.DisabledRules, r.ID) {
			vc.Rules = append(vc.Rules, r)
		}
	}
	extendDepth = 0
	if cfg, err = vc.Translate(); err != nil {
		return cfg, fmt.Errorf("gitleaks config %s: %w", name, err)
	}
	return cfg, nil
}

// readViper parses a config through gitleaks' global viper instance, which Translate keeps using for
// `[extend]`. The caller holds configMu.
func readViper(path, text string) (vc gitleaksconfig.ViperConfig, err error) {
	viper.Reset()
	viper.SetConfigType("toml")
	switch {
	case path != "":
		viper.SetConfigFile(path)
		err = viper.ReadInConfig()
	case text != "":
		err = viper.ReadConfig(strings.NewReader(text))
	default:
		err = viper.ReadConfig(strings.NewReader(gitleaksconfig.DefaultConfig))
	}
	if err == nil {
		err = viper.Unmarshal(&vc)
	}
	return vc, err
}

// LoadReport reads a gitleaks JSON report (from the gitleaks CLI). Absolute paths are made relative
// to dir; findings outside dir are dropped.
func LoadReport(path, dir string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var findings []Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("parse gitleaks report %s: %w", path, err)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.Secret == "" || f.Secret == "REDACTED" || strings.Trim(f.Secret, "*") == "" {
			return nil, fmt.Errorf("%s: %w", path, ErrRedacted)
		}
		rel, ok := relTo(absDir, f.File)
		if !ok {
			continue
		}
		f.File = rel
		out = append(out, f)
	}
	return out, nil
}

// relTo makes file (absolute, or already relative to root) a clean slash path inside root.
func relTo(absRoot, file string) (string, bool) {
	rel := file
	if filepath.IsAbs(file) {
		var err error
		if rel, err = filepath.Rel(absRoot, file); err != nil {
			return "", false
		}
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}
