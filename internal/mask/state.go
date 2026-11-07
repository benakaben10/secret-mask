package mask

import (
	"maps"
	"slices"
	"time"

	"github.com/OWNER/secret-mask/internal/vault"
)

// State is the decrypted vault content plus lookup indexes.
type State struct {
	created   string
	secrets   map[string]string // id -> value
	byValue   map[string]string // value -> id
	originals map[string]string // file -> sha256 before first masking
	entries   map[string]*vault.Entry
	now       func() time.Time
}

// NewState returns an empty state for a new vault.
func NewState() *State {
	s := &State{
		secrets:   map[string]string{},
		byValue:   map[string]string{},
		originals: map[string]string{},
		entries:   map[string]*vault.Entry{},
		now:       time.Now,
	}
	s.created = s.timestamp()
	return s
}

// FromVault rebuilds the state from an opened vault.
func FromVault(m vault.Manifest, p *vault.Payload) *State {
	s := NewState()
	if m.Created != "" {
		s.created = m.Created
	}
	for id, v := range p.Secrets {
		s.secrets[id] = v
		s.byValue[v] = id
	}
	maps.Copy(s.originals, p.Originals)
	for _, e := range m.Entries {
		s.entries[e.ID] = &vault.Entry{ID: e.ID, RuleID: e.RuleID, Files: slices.Clone(e.Files)}
	}
	return s
}

// Len is the number of distinct secrets.
func (s *State) Len() int { return len(s.secrets) }

// Value returns the original value for id.
func (s *State) Value(id string) (string, bool) {
	v, ok := s.secrets[id]
	return v, ok
}

// IDs returns all secret ids, sorted.
func (s *State) IDs() []string { return slices.Sorted(maps.Keys(s.secrets)) }

// Files returns the files id was masked in.
func (s *State) Files(id string) []string {
	if e, ok := s.entries[id]; ok {
		return slices.Clone(e.Files)
	}
	return nil
}

// Original returns the sha256 of file before it was first masked.
func (s *State) Original(file string) (string, bool) {
	h, ok := s.originals[file]
	return h, ok
}

// Manifest returns the plaintext manifest with entries sorted by id.
func (s *State) Manifest() vault.Manifest {
	m := vault.Manifest{Created: s.created, Updated: s.timestamp()}
	for _, id := range slices.Sorted(maps.Keys(s.entries)) {
		e := s.entries[id]
		m.Entries = append(m.Entries, vault.Entry{ID: e.ID, RuleID: e.RuleID, Files: slices.Clone(e.Files)})
	}
	return m
}

// Payload returns the data to encrypt.
func (s *State) Payload() vault.Payload {
	return vault.Payload{Secrets: maps.Clone(s.secrets), Originals: maps.Clone(s.originals)}
}

// idFor returns the id of value, creating a new one for an unseen value.
func (s *State) idFor(value, rule string) (string, error) {
	if id, ok := s.byValue[value]; ok {
		return id, nil
	}
	for {
		id, err := newID()
		if err != nil {
			return "", err
		}
		if _, taken := s.secrets[id]; taken {
			continue
		}
		s.secrets[id] = value
		s.byValue[value] = id
		s.entries[id] = &vault.Entry{ID: id, RuleID: rule}
		return id, nil
	}
}

func (s *State) addFile(id, file string) {
	e := s.entries[id]
	if !slices.Contains(e.Files, file) {
		e.Files = append(e.Files, file)
		slices.Sort(e.Files)
	}
}

func (s *State) timestamp() string { return s.now().UTC().Format(time.RFC3339) }
