package mask

import (
	"cmp"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/benakaben10/secret-mask/internal/detect"
	"github.com/benakaben10/secret-mask/internal/fsutil"
)

// Options control Mask and Restore.
type Options struct {
	Skip   map[string]bool // dir-relative, slash-separated paths never touched (vault, guide)
	DryRun bool            // compute the result without writing files
	Force  bool            // Restore only: write what can be restored even if placeholders are missing
}

// MaskResult summarizes a Mask run.
type MaskResult struct {
	Files   map[string]int // file -> occurrences replaced
	Skipped []string       // human-readable reasons, one per skipped finding/file
	Masked  int            // total occurrences replaced
}

type secretRule struct{ value, rule string }

// ForeignError means the tree already holds placeholders that the vault does not know: it was masked
// with another vault (deleted, moved or passed with a different --vault). Masking again would bury
// those placeholders under a second vault, so it is refused.
type ForeignError struct {
	Files  map[string][]string // file -> unknown placeholders
	Tokens int
}

func (e *ForeignError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "refusing to mask: %d placeholder(s) are not in this vault, so this tree was already masked with another vault:\n", e.Tokens)
	for _, f := range slices.Sorted(maps.Keys(e.Files)) {
		fmt.Fprintf(&b, "  %s: %s\n", f, strings.Join(e.Files[f], ", "))
	}
	b.WriteString("restore it with the vault that masked it (or pass that vault with --vault) before masking again")
	return b.String()
}

// CheckForeign returns a *ForeignError when dir contains placeholders whose id is not known.
func CheckForeign(dir string, skip map[string]bool, known func(id string) bool) error {
	hits, err := Scan(dir, skip)
	if err != nil {
		return err
	}
	e := &ForeignError{Files: map[string][]string{}}
	for _, h := range hits {
		for _, id := range h.IDs() {
			if tok := Placeholder(id); !known(id) && !slices.Contains(e.Files[h.Rel], tok) {
				e.Files[h.Rel] = append(e.Files[h.Rel], tok)
				e.Tokens++
			}
		}
	}
	if e.Tokens > 0 {
		return e
	}
	return nil
}

// Mask replaces every occurrence of each finding's secret in that finding's file with the secret's
// placeholder. Within a file, longer secrets go first so a secret containing another is masked whole.
// The same value gets the same placeholder everywhere, including values already in the vault.
// Existing placeholders are never modified, and a tree holding placeholders of another vault is refused
// with a *ForeignError before anything is written.
func Mask(dir string, findings []detect.Finding, s *State, opt Options) (*MaskResult, error) {
	if err := CheckForeign(dir, opt.Skip, func(id string) bool { _, ok := s.secrets[id]; return ok }); err != nil {
		return nil, err
	}
	byFile := map[string]map[string]string{}
	for _, f := range findings {
		if opt.Skip[f.File] {
			continue
		}
		if byFile[f.File] == nil {
			byFile[f.File] = map[string]string{}
		}
		byFile[f.File][f.Secret] = f.RuleID
	}

	res := &MaskResult{Files: map[string]int{}}
	for _, rel := range slices.Sorted(maps.Keys(byFile)) {
		n, err := maskFile(dir, rel, byFile[rel], s, opt.DryRun, res)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			res.Files[rel] = n
			res.Masked += n
		}
	}
	return res, nil
}

func maskFile(dir, rel string, secrets map[string]string, s *State, dryRun bool, res *MaskResult) (int, error) {
	path := filepath.Join(dir, filepath.FromSlash(rel))
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		res.Skipped = append(res.Skipped, rel+": not a regular file")
		return 0, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if fsutil.IsBinary(data) {
		res.Skipped = append(res.Skipped, rel+": binary file")
		return 0, nil
	}

	ordered := make([]secretRule, 0, len(secrets))
	for v, r := range secrets {
		ordered = append(ordered, secretRule{v, r})
	}
	slices.SortFunc(ordered, func(a, b secretRule) int {
		return cmp.Or(cmp.Compare(len(b.value), len(a.value)), cmp.Compare(a.value, b.value))
	})

	content := string(data)
	tokens := Pattern.FindAllString(content, -1)
	replaced := 0
	for _, sr := range ordered {
		if strings.Contains(sr.value, Prefix) || overlapsAny(sr.value, tokens) {
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %s secret overlaps a placeholder", rel, sr.rule))
			continue
		}
		if _, n := replaceOutsideTokens(content, sr.value, ""); n == 0 {
			// e.g. gitleaks decoded a base64 value; the literal secret is not in the file.
			res.Skipped = append(res.Skipped, fmt.Sprintf("%s: %s secret not found literally (encoded?)", rel, sr.rule))
			continue
		}
		id, err := s.idFor(sr.value, sr.rule)
		if err != nil {
			return 0, err
		}
		token := Placeholder(id)
		var n int
		content, n = replaceOutsideTokens(content, sr.value, token)
		tokens = append(tokens, token)
		s.addFile(id, rel)
		replaced += n
	}
	if replaced == 0 {
		return 0, nil
	}
	if _, ok := s.originals[rel]; !ok {
		s.originals[rel] = fsutil.SHA256Hex(data)
	}
	if dryRun {
		return replaced, nil
	}
	return replaced, fsutil.WriteFileAtomic(path, []byte(content), info.Mode().Perm())
}

// replaceOutsideTokens replaces old with new only in the text between placeholders, so an existing
// placeholder is never altered even by a value that straddles its edge. It returns the result and the
// number of replacements.
func replaceOutsideTokens(content, old, new string) (string, int) {
	var b strings.Builder
	n, last := 0, 0
	for _, loc := range append(Pattern.FindAllStringIndex(content, -1), []int{len(content), len(content)}) {
		seg := content[last:loc[0]]
		n += strings.Count(seg, old)
		b.WriteString(strings.ReplaceAll(seg, old, new))
		b.WriteString(content[loc[0]:loc[1]])
		last = loc[1]
	}
	return b.String(), n
}

func overlapsAny(secret string, tokens []string) bool {
	for _, t := range tokens {
		if strings.Contains(t, secret) {
			return true
		}
	}
	return false
}
