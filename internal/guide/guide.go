// Package guide renders the instructions that tell AI assistants to leave placeholders untouched.
package guide

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/OWNER/secret-mask/internal/vault"
)

// DefaultName is the guide file written next to the vault.
const DefaultName = "SECRET_MASK_AI_GUIDE.md"

const rules = `# Secret masking — rules for AI assistants

This directory was processed by ` + "`secret-mask`" + `. Secrets were replaced with placeholders like

    __SECRET_MASK_0123456789abcdef__

The original values are encrypted in ` + "`%[1]s`" + ` and are put back with ` + "`secret-mask restore`" + `.
Restore only works if every placeholder is still present **exactly as written**.

## You MUST

1. Keep every ` + "`__SECRET_MASK_<16 hex>__`" + ` token byte-for-byte: same characters, same case, same underscores.
2. Keep the surrounding syntax: if the token is quoted, keep the quotes; if it is unquoted, do not add quotes.
3. When you move or copy configuration, move the placeholder with it. Moving it to another file is fine.
4. Treat a placeholder as an opaque, valid value. Code and config may reference it as-is.

## You MUST NOT

- Replace a placeholder with a real-looking value, an example value, ` + "`<redacted>`, `changeme`, `${VAR}`" + ` or an empty string.
- Delete, shorten, re-case, re-encode (base64, URL, escaping), split or reformat a placeholder.
- Invent new ` + "`__SECRET_MASK_...__`" + ` tokens, or reuse one for a different setting.
- Edit, regenerate or delete ` + "`%[1]s`" + ` or this file.
- Try to guess or reconstruct the original secrets.

If a task seems to require changing a placeholder, stop and ask the user instead.

## Before you finish

Run ` + "`secret-mask status`" + ` — it must report ` + "`missing: 0`" + `.

`

// Render builds the guide. It lists files and placeholder counts only, never secret values.
func Render(m vault.Manifest, vaultName string) string {
	perFile := map[string]int{}
	for _, e := range m.Entries {
		for _, f := range e.Files {
			perFile[f]++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, rules, vaultName)
	fmt.Fprintf(&b, "## Masked files (%d files, %d secrets)\n\n| File | Placeholders |\n|---|---|\n", len(perFile), len(m.Entries))
	for _, f := range slices.Sorted(maps.Keys(perFile)) {
		fmt.Fprintf(&b, "| `%s` | %d |\n", f, perFile[f])
	}
	return b.String()
}
