// Package detect finds secrets with gitleaks, embedded as a library: no external binary is needed and
// the rules always match the gitleaks version secret-mask was built with.
package detect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

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

// Options describe one scan.
type Options struct {
	Root   string // project root: base for relative paths, .gitleaks.toml and .gitleaksignore
	Target string // file or directory to scan, relative to Root (default ".")
	// Config is an optional gitleaks config. Default: $GITLEAKS_CONFIG, then <Root>/.gitleaks.toml,
	// then the built-in gitleaks rules.
	Config string
}

// maxFileSize matches the masking engine's limit.
const maxFileSize = 100 << 20

// gitleaks loads configs through the global viper instance (including `[extend]`), so loading is serialized.
var configMu sync.Mutex

func init() {
	// gitleaks logs to stderr at info level; keep stdout clean (MCP) and stderr quiet.
	logging.Logger = logging.Logger.Level(zerolog.ErrorLevel)
}

// Scan returns the unredacted findings under Root/Target, with paths relative to Root.
func Scan(ctx context.Context, o Options) ([]Finding, error) {
	if o.Target == "" {
		o.Target = "."
	}
	cfgPath := o.Config
	if cfgPath == "" {
		cfgPath = os.Getenv("GITLEAKS_CONFIG")
	}
	if cfgPath == "" {
		if _, err := os.Stat(filepath.Join(o.Root, ".gitleaks.toml")); err == nil {
			cfgPath = filepath.Join(o.Root, ".gitleaks.toml")
		}
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return nil, err
	}

	det := gitleaks.NewDetectorContext(ctx, cfg)
	det.MaxTargetMegaBytes = maxFileSize / 1_000_000
	// gitleaks would fingerprint the absolute paths it walked; .gitleaksignore entries are root-relative
	// (file:rule:line), so they are applied here instead.
	ignored, err := loadIgnore(filepath.Join(o.Root, ".gitleaksignore"))
	if err != nil {
		return nil, err
	}

	absRoot, err := filepath.Abs(o.Root)
	if err != nil {
		return nil, err
	}
	// Absolute, so gitleaks reports absolute paths regardless of the process cwd.
	target := filepath.Join(absRoot, o.Target)
	if _, err := os.Stat(target); err != nil {
		return nil, err
	}
	results, err := det.DetectSource(ctx, &sources.Files{
		Config:      &cfg,
		Path:        target,
		Sema:        det.Sema,
		MaxFileSize: maxFileSize,
	})
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

// LoadConfig loads a gitleaks config file, or the built-in rules when path is empty.
func LoadConfig(path string) (cfg gitleaksconfig.Config, err error) {
	configMu.Lock()
	defer configMu.Unlock()
	// gitleaks panics on invalid rule regexes.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("gitleaks config %s: %v", path, r)
		}
	}()
	viper.Reset()
	viper.SetConfigType("toml")
	if path == "" {
		if err := viper.ReadConfig(strings.NewReader(gitleaksconfig.DefaultConfig)); err != nil {
			return gitleaksconfig.Config{}, fmt.Errorf("built-in gitleaks config: %w", err)
		}
	} else {
		viper.SetConfigFile(path)
		if err := viper.ReadInConfig(); err != nil {
			return gitleaksconfig.Config{}, fmt.Errorf("gitleaks config %s: %w", path, err)
		}
	}
	var vc gitleaksconfig.ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		return gitleaksconfig.Config{}, fmt.Errorf("gitleaks config %s: %w", path, err)
	}
	if cfg, err = vc.Translate(); err != nil {
		return gitleaksconfig.Config{}, fmt.Errorf("gitleaks config %s: %w", path, err)
	}
	return cfg, nil
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
