package detect

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Secrets are assembled at run time so this source file never contains a detectable secret.
var (
	awsKey      = "AKIA" + "QYLPMN5HHHFPZAM2"
	githubToken = "ghp_" + "8Rk2Lm9Qx7Vt3Zb5Nc1Hd4Jf6Gs0Pw2Ya8Ue"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func secrets(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.File+"="+f.Secret)
	}
	slices.Sort(out)
	return out
}

func TestScanDefaultRules(t *testing.T) {
	dir := tree(t, map[string]string{
		"config/.env": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"ci/build.sh": "export GITHUB_TOKEN=" + githubToken + "\n",
		"README.md":   "nothing to see\n",
	})
	got, err := Scan(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ci/build.sh=" + githubToken, "config/.env=" + awsKey}
	if !reflect.DeepEqual(secrets(got), want) {
		t.Errorf("Scan = %v, want %v", secrets(got), want)
	}
	for _, f := range got {
		if f.RuleID == "" || f.StartLine != 1 {
			t.Errorf("finding %+v lacks rule/line", f)
		}
	}
}

func TestScanSingleFileAndSubdir(t *testing.T) {
	dir := tree(t, map[string]string{
		"a/.env": "AWS_ACCESS_KEY_ID=" + awsKey + "\n",
		"b/.env": "GITHUB_TOKEN=" + githubToken + "\n",
	})
	got, err := Scan(context.Background(), Options{Root: dir, Target: "b/.env"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secrets(got), []string{"b/.env=" + githubToken}) {
		t.Errorf("file scan = %v", secrets(got))
	}
	got, err = Scan(context.Background(), Options{Root: dir, Target: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secrets(got), []string{"a/.env=" + awsKey}) {
		t.Errorf("subdir scan = %v", secrets(got))
	}
}

func TestScanRelativeRootFromOtherCwd(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "proj")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("KEY="+awsKey+"\n"), 0o644)
	t.Chdir(parent)
	got, err := Scan(context.Background(), Options{Root: "proj"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secrets(got), []string{".env=" + awsKey}) {
		t.Errorf("Scan = %v", secrets(got))
	}
}

const extraRule = `
[extend]
useDefault = true

[[rules]]
id = "custom-password"
regex = '''PASSWORD=(\S{6,})'''
secretGroup = 1
keywords = ["password"]
`

func TestScanRepoConfigAndIgnore(t *testing.T) {
	dir := tree(t, map[string]string{
		".gitleaks.toml": extraRule,
		".env":           "PASSWORD=Admin@123\nAWS_ACCESS_KEY_ID=" + awsKey + "\n",
	})
	got, err := Scan(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secrets(got), []string{".env=" + awsKey, ".env=Admin@123"}) {
		t.Fatalf("repo config not used: %v", secrets(got))
	}

	// .gitleaksignore (file:rule:line) suppresses one finding.
	var awsRule string
	for _, f := range got {
		if f.Secret == awsKey {
			awsRule = f.RuleID
		}
	}
	os.WriteFile(filepath.Join(dir, ".gitleaksignore"), []byte(".env:"+awsRule+":2\n"), 0o644)
	got, err = Scan(context.Background(), Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secrets(got), []string{".env=Admin@123"}) {
		t.Errorf("with .gitleaksignore: %v", secrets(got))
	}
}

func TestScanConfigPrecedence(t *testing.T) {
	dir := tree(t, map[string]string{".env": "PASSWORD=Admin@123\n"})
	cfg := filepath.Join(t.TempDir(), "leak.toml")
	os.WriteFile(cfg, []byte(extraRule), 0o644)

	got, _ := Scan(context.Background(), Options{Root: dir})
	if len(got) != 0 {
		t.Errorf("default rules should not flag a short password: %v", secrets(got))
	}
	got, err := Scan(context.Background(), Options{Root: dir, Config: cfg})
	if err != nil || len(got) != 1 {
		t.Errorf("explicit config: %v, %v", secrets(got), err)
	}
	t.Setenv("GITLEAKS_CONFIG", cfg)
	got, err = Scan(context.Background(), Options{Root: dir})
	if err != nil || len(got) != 1 {
		t.Errorf("GITLEAKS_CONFIG: %v, %v", secrets(got), err)
	}
}

func TestScanErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Scan(context.Background(), Options{Root: dir, Target: "missing"}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing target: %v", err)
	}
	if _, err := Scan(context.Background(), Options{Root: dir, Config: filepath.Join(dir, "nope.toml")}); err == nil {
		t.Error("missing config: want an error")
	}
	bad := filepath.Join(dir, "bad.toml")
	os.WriteFile(bad, []byte("[[rules]]\nid = \"x\"\nregex = '''(unclosed'''\n"), 0o644)
	if _, err := Scan(context.Background(), Options{Root: dir, Config: bad}); err == nil {
		t.Error("invalid config: want an error")
	}
}

func TestLoadConfigDefault(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) < 100 {
		t.Errorf("built-in config has %d rules", len(cfg.Rules))
	}
}

func writeReport(t *testing.T, findings []map[string]any) string {
	t.Helper()
	data, _ := json.Marshal(findings)
	path := filepath.Join(t.TempDir(), "report.json")
	os.WriteFile(path, data, 0o600)
	return path
}

func TestLoadReport(t *testing.T) {
	dir := t.TempDir()
	abs, _ := filepath.Abs(dir)
	report := writeReport(t, []map[string]any{
		{"RuleID": "r1", "File": "config/.env", "StartLine": 3, "Secret": "s1"},
		{"RuleID": "r2", "File": filepath.Join(abs, "k8s", "secret.yaml"), "StartLine": 7, "Secret": "s2"},
		{"RuleID": "r3", "File": "./a/../b.json", "StartLine": 1, "Secret": "s3"},
		{"RuleID": "r4", "File": filepath.Join(filepath.Dir(abs), "outside.env"), "StartLine": 1, "Secret": "s4"},
		{"RuleID": "r5", "File": "../escape.env", "StartLine": 1, "Secret": "s5"},
	})
	got, err := LoadReport(report, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []Finding{
		{RuleID: "r1", File: "config/.env", StartLine: 3, Secret: "s1"},
		{RuleID: "r2", File: "k8s/secret.yaml", StartLine: 7, Secret: "s2"},
		{RuleID: "r3", File: "b.json", StartLine: 1, Secret: "s3"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LoadReport =\n%+v\nwant\n%+v", got, want)
	}
}

func TestLoadReportRedacted(t *testing.T) {
	for _, secret := range []string{"REDACTED", "*****", ""} {
		report := writeReport(t, []map[string]any{{"RuleID": "r", "File": "a", "Secret": secret}})
		if _, err := LoadReport(report, t.TempDir()); !errors.Is(err, ErrRedacted) {
			t.Errorf("secret %q: err = %v, want ErrRedacted", secret, err)
		}
	}
}

func TestLoadReportErrors(t *testing.T) {
	if _, err := LoadReport(filepath.Join(t.TempDir(), "missing.json"), "."); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: err = %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte("not json"), 0o600)
	if _, err := LoadReport(bad, "."); err == nil || !strings.Contains(err.Error(), "parse gitleaks report") {
		t.Errorf("bad json: err = %v", err)
	}
}
