package guide

import (
	"strings"
	"testing"

	"github.com/OWNER/secret-mask/internal/vault"
)

func TestRender(t *testing.T) {
	m := vault.Manifest{Entries: []vault.Entry{
		{ID: "0000000000000001", RuleID: "r", Files: []string{".env", "k8s/secret.yaml"}},
		{ID: "0000000000000002", RuleID: "r", Files: []string{".env"}},
	}}
	got := Render(m, ".secret-mask.vault")

	for _, want := range []string{
		"# Secret masking — rules for AI assistants",
		"__SECRET_MASK_<16 hex>__",
		"byte-for-byte",
		"`.secret-mask.vault`",
		"You MUST NOT",
		"`secret-mask status`",
		"missing: 0",
		"## Masked files (2 files, 2 secrets)",
		"| `.env` | 2 |",
		"| `k8s/secret.yaml` | 1 |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("guide is missing %q\n---\n%s", want, got)
		}
	}
	if strings.Index(got, "`.env`") > strings.Index(got, "`k8s/secret.yaml`") {
		t.Error("files are not sorted")
	}
	if strings.Contains(got, "%!") {
		t.Errorf("format verb error in guide:\n%s", got)
	}
}

func TestRenderEmpty(t *testing.T) {
	got := Render(vault.Manifest{}, "v")
	if !strings.Contains(got, "## Masked files (0 files, 0 secrets)") {
		t.Errorf("empty guide:\n%s", got)
	}
}
