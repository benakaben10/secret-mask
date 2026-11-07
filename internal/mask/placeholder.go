// Package mask replaces secrets with placeholders and puts them back.
package mask

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
)

// Prefix starts every placeholder: __SECRET_MASK_<16 lowercase hex>__.
const Prefix = "__SECRET_MASK_"

// Pattern matches a placeholder exactly. Anything else (case change, trimming, re-quoting) no longer
// matches and is reported as missing on restore.
var Pattern = regexp.MustCompile(`__SECRET_MASK_[0-9a-f]{16}__`)

// Placeholder returns the token for id.
func Placeholder(id string) string { return Prefix + id + "__" }

// IDOf returns the id inside a token matched by Pattern.
func IDOf(token string) string { return token[len(Prefix) : len(token)-2] }

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
