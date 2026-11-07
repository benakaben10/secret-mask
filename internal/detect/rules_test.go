package detect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulesListsEverySource(t *testing.T) {
	dir := tree(t, map[string]string{".gitleaks.toml": extraRule})
	set, err := Rules(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if set.Config != filepath.Join(dir, ".gitleaks.toml") {
		t.Errorf("config = %q", set.Config)
	}
	sources := map[string]int{}
	byID := map[string]RuleInfo{}
	for _, r := range set.Rules {
		sources[r.Source]++
		byID[r.ID] = r
	}
	if sources[SourceGitleaks] < 200 || sources[SourceSecretMask] != 9 || sources[SourceProject] != 1 {
		t.Errorf("sources = %v", sources)
	}
	aws := byID["aws-access-token"]
	if aws.Regex == "" || len(aws.Keywords) == 0 || len(aws.Allowlists) == 0 || aws.Source != SourceGitleaks {
		t.Errorf("aws rule = %+v", aws)
	}
	if byID["secret-mask-url-password"].SecretGroup != 1 || byID["custom-ticket"].Source != SourceProject {
		t.Error("details missing")
	}
	if len(set.Allowlists) == 0 {
		t.Error("global allowlists missing")
	}
	builtin, _ := Rules(t.TempDir(), "")
	if builtin.Config != "" || len(builtin.Rules) != len(set.Rules)-1 {
		t.Errorf("built-in set: %q %d", builtin.Config, len(builtin.Rules))
	}
}

func TestTestRule(t *testing.T) {
	spec := RuleSpec{ID: "acme-token", Regex: `\b(acme_[a-z]{2}_[A-Za-z0-9]{24})\b`, Keywords: []string{"ACME_"}}
	dir := tree(t, map[string]string{"config/app.env": "T=acme_pr_Q7xT2mZ9vB4nR8wK3sD6fH1j\n", "README.md": "none\n"})
	sample, project, err := TestRule(context.Background(), spec, "x\nTOKEN=acme_pr_Q7xT2mZ9vB4nR8wK3sD6fH1j\n", "", dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sample) != 1 || sample[0].Line != 2 || sample[0].Secret != "acme_pr_Q7xT2mZ9vB4nR8wK3sD6fH1j" {
		t.Errorf("sample = %+v", sample)
	}
	if len(project) != 1 || project[0].File != "config/app.env" || project[0].Secret != "" {
		t.Errorf("project = %+v (values must not be returned)", project)
	}
	// path restricts the rule; sample_path is what it is matched against.
	spec.Path = `\.env$`
	if s, _, _ := TestRule(context.Background(), spec, "acme_pr_Q7xT2mZ9vB4nR8wK3sD6fH1j", "notes.md", ""); len(s) != 0 {
		t.Errorf("path ignored: %+v", s)
	}
	for _, bad := range []RuleSpec{
		{Regex: `(unclosed`},
		{Regex: `token=(\w+)`, SecretGroup: 2},
		{ID: "Bad ID", Regex: `x`},
		{Regex: `a'''b`},
		{},
	} {
		if _, _, err := TestRule(context.Background(), bad, "x", "", ""); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestAddRule(t *testing.T) {
	dir := tree(t, map[string]string{".env": "T=acme_pr_Q7xT2mZ9vB4nR8wK3sD6fH1j\nAWS_ACCESS_KEY_ID=" + awsKey + "\n"})
	spec := RuleSpec{ID: "acme-token", Description: `ACME "internal" token`, Regex: `\b(acme_[a-z]{2}_[A-Za-z0-9]{24})\b`, Keywords: []string{"acme_"}}
	path, err := AddRule(dir, spec)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), "# gitleaks config") || !strings.Contains(string(data), "useDefault = true") {
		t.Errorf("new config:\n%s", data)
	}
	got, _ := Scan(context.Background(), Options{Root: dir})
	if len(got) != 2 {
		t.Errorf("defaults and new rule both active: %v", secrets(got))
	}
	if _, err := AddRule(dir, spec); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("duplicate: %v", err)
	}
	for _, id := range []string{"aws-access-token", "secret-mask-password-unquoted"} {
		if _, err := AddRule(dir, RuleSpec{ID: id, Regex: `NEVER(\w+)`}); err == nil {
			t.Errorf("replacing %s accepted", id)
		}
	}
	// A second rule is appended; the file keeps loading.
	if _, err := AddRule(dir, RuleSpec{ID: "acme-ticket", Regex: `TICKET=(TK-\d{6,})`, SecretGroup: 1}); err != nil {
		t.Fatal(err)
	}
	set, _ := Rules(dir, "")
	n := 0
	for _, r := range set.Rules {
		if r.Source == SourceProject {
			n++
		}
	}
	if n != 2 {
		t.Errorf("project rules = %d", n)
	}
	t.Setenv("GITLEAKS_CONFIG", filepath.Join(t.TempDir(), "x.toml"))
	if _, err := AddRule(dir, RuleSpec{ID: "other", Regex: `x(\w+)`}); err == nil || !strings.Contains(err.Error(), "GITLEAKS_CONFIG") {
		t.Errorf("GITLEAKS_CONFIG: %v", err)
	}
}
