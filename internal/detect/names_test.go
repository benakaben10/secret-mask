package detect

import (
	"context"
	"reflect"
	"testing"
)

// Names, prose and settings that look like key = value are not secrets; found scanning this repository.
func TestRulesSkipNamesAndProse(t *testing.T) {
	files := map[string]string{
		"internal/cli/cli.go":   "const DefaultPasswordEnv = \"SECRET_MASK_PASSWORD\"\nconst SourceSecretMask = \"secret-mask\"\n",
		"install.sh":            "#!/bin/sh\n# One-line installer for secret-mask: downloads the release binary\necho \"the token: is printed below\"\n",
		".github/workflows.yml": "permissions:\n  id-token: write\n  contents: read\n",
		"docs/setup.yaml":       "users:\n  - password: " + "Adm1n-2024\n",
	}
	got, err := Scan(context.Background(), Options{Root: tree(t, files)})
	if err != nil {
		t.Fatal(err)
	}
	// Only the YAML list item is a setting holding a secret.
	if !reflect.DeepEqual(secrets(got), []string{"docs/setup.yaml=Adm1n-2024"}) {
		t.Errorf("findings = %v", secrets(got))
	}
}
