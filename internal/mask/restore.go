package mask

import (
	"bytes"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/benakaben10/secret-mask/internal/fsutil"
)

const maxFileSize = 100 << 20

// Hit is a file that contains at least one placeholder.
type Hit struct {
	Rel     string
	path    string
	mode    fs.FileMode
	Content string
}

// IDs returns the placeholder ids in the file, in order of appearance.
func (h Hit) IDs() []string {
	tokens := Pattern.FindAllString(h.Content, -1)
	ids := make([]string, len(tokens))
	for i, t := range tokens {
		ids[i] = IDOf(t)
	}
	return ids
}

// Scan walks dir (skipping .git, symlinks, binaries, files over 100 MiB and opt.Skip) and returns the
// files containing placeholders.
func Scan(dir string, skip map[string]bool) ([]Hit, error) {
	var hits []Hit
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if skip[rel] {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if fsutil.IsBinary(data) || !bytes.Contains(data, []byte(Prefix)) {
			return nil
		}
		hits = append(hits, Hit{Rel: rel, path: path, mode: info.Mode().Perm(), Content: string(data)})
		return nil
	})
	return hits, err
}

// RestoreResult summarizes a Restore run.
type RestoreResult struct {
	Files     map[string]int // file -> placeholders restored
	Restored  int
	Missing   []string // vault ids with no placeholder left anywhere
	Unknown   []string // placeholders found in files that this vault does not know
	Identical []string // restored files byte-identical to their content before masking
	Edited    []string // restored files edited since masking (other edits are kept)
}

// MissingError lists vault ids whose placeholders were deleted or altered.
type MissingError struct {
	IDs   []string
	files func(id string) []string
}

func (e *MissingError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d placeholder(s) are missing or were altered:", len(e.IDs))
	for _, id := range e.IDs {
		fmt.Fprintf(&b, "\n  %s (masked in: %s)", Placeholder(id), strings.Join(e.files(id), ", "))
	}
	return b.String()
}

// NewMissingError builds a MissingError for ids, using files to describe where each was masked.
func NewMissingError(ids []string, files func(id string) []string) *MissingError {
	return &MissingError{IDs: ids, files: files}
}

// Restore puts original values back. Placeholders are looked up anywhere under dir, so one moved to
// another file is still restored. If any vault id has no placeholder left, nothing is written and a
// *MissingError is returned, unless opt.Force.
func Restore(dir string, s *State, opt Options) (*RestoreResult, error) {
	hits, err := Scan(dir, opt.Skip)
	if err != nil {
		return nil, err
	}
	res := &RestoreResult{Files: map[string]int{}}
	found := map[string]bool{}
	unknown := map[string]bool{}
	type write struct {
		hit     Hit
		content string
	}
	var writes []write
	for _, h := range hits {
		n := 0
		out := Pattern.ReplaceAllStringFunc(h.Content, func(token string) string {
			v, ok := s.secrets[IDOf(token)]
			if !ok {
				unknown[token] = true
				return token
			}
			found[IDOf(token)] = true
			n++
			return v
		})
		if n > 0 {
			writes = append(writes, write{h, out})
			res.Files[h.Rel] = n
			res.Restored += n
		}
	}
	for _, id := range s.IDs() {
		if !found[id] {
			res.Missing = append(res.Missing, id)
		}
	}
	res.Unknown = slices.Sorted(maps.Keys(unknown))
	if len(res.Missing) > 0 && !opt.Force {
		return res, NewMissingError(res.Missing, s.Files)
	}
	for _, w := range writes {
		if want, ok := s.originals[w.hit.Rel]; ok {
			if fsutil.SHA256Hex([]byte(w.content)) == want {
				res.Identical = append(res.Identical, w.hit.Rel)
			} else {
				res.Edited = append(res.Edited, w.hit.Rel)
			}
		}
		if !opt.DryRun {
			if err := fsutil.WriteFileAtomic(w.hit.path, []byte(w.content), w.hit.mode); err != nil {
				return nil, err
			}
		}
	}
	return res, nil
}
