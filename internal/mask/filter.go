package mask

import (
	"strings"

	"github.com/OWNER/secret-mask/internal/detect"
)

// Unmasked drops findings whose "secret" is (or contains) a placeholder: a masked value such as
// `password: __SECRET_MASK_…__` can still match permissive rules, but it is not a leak.
func Unmasked(findings []detect.Finding, skip map[string]bool) []detect.Finding {
	out := make([]detect.Finding, 0, len(findings))
	for _, f := range findings {
		if skip[f.File] || strings.Contains(f.Secret, Prefix) || Pattern.MatchString(f.Secret) {
			continue
		}
		out = append(out, f)
	}
	return out
}
