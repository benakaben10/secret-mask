package vault

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fastIter keeps tests quick; the default count is covered by TestSealUsesDefaultIterations.
const fastIter = 1000

func sample() (Manifest, Payload) {
	m := Manifest{
		Created: "2026-01-01T00:00:00Z",
		Updated: "2026-01-02T00:00:00Z",
		Entries: []Entry{{ID: "0123456789abcdef", RuleID: "config-credential", Files: []string{".env", "app.yaml"}}},
	}
	p := Payload{
		Secrets:   map[string]string{"0123456789abcdef": "S3cr3t!"},
		Originals: map[string]string{".env": "deadbeef"},
	}
	return m, p
}

func TestSealOpenRoundTrip(t *testing.T) {
	m, p := sample()
	v, err := seal("correct horse", m, p, fastIter)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(v.Ciphertext, "S3cr3t") {
		t.Fatal("ciphertext contains the plaintext secret")
	}
	got, err := Open(v, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got, p) {
		t.Errorf("payload = %+v, want %+v", *got, p)
	}
}

func TestSealUsesFreshSaltAndNonce(t *testing.T) {
	m, p := sample()
	a, err := seal("pw-12345", m, p, fastIter)
	if err != nil {
		t.Fatal(err)
	}
	b, err := seal("pw-12345", m, p, fastIter)
	if err != nil {
		t.Fatal(err)
	}
	if a.KDF.Salt == b.KDF.Salt || a.Nonce == b.Nonce || a.Ciphertext == b.Ciphertext {
		t.Error("two seals reused salt, nonce or ciphertext")
	}
}

func TestSealUsesDefaultIterations(t *testing.T) {
	m, p := sample()
	v, err := Seal("pw-12345", m, p)
	if err != nil {
		t.Fatal(err)
	}
	if v.KDF.Iterations != DefaultIterations || v.KDF.Name != KDFName || v.Format != Format {
		t.Errorf("kdf = %+v, format = %q", v.KDF, v.Format)
	}
	if _, err := Open(v, "pw-12345"); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejects(t *testing.T) {
	m, p := sample()
	tests := []struct {
		name    string
		mutate  func(v *Vault)
		pw      string
		wantErr error
		wantMsg string
	}{
		{name: "wrong password", pw: "wrong", wantErr: ErrWrongPassword},
		{name: "manifest file renamed", mutate: func(v *Vault) { v.Manifest.Entries[0].Files[0] = "other.env" }, wantErr: ErrWrongPassword},
		{name: "manifest entry added", mutate: func(v *Vault) { v.Manifest.Entries = append(v.Manifest.Entries, Entry{ID: "x"}) }, wantErr: ErrWrongPassword},
		{name: "ciphertext flipped", mutate: func(v *Vault) { v.Ciphertext = flip(v.Ciphertext) }, wantErr: ErrWrongPassword},
		{name: "salt changed", mutate: func(v *Vault) { v.KDF.Salt = flip(v.KDF.Salt) }, wantErr: ErrWrongPassword},
		{name: "iterations changed", mutate: func(v *Vault) { v.KDF.Iterations++ }, wantErr: ErrWrongPassword},
		{name: "unknown format", mutate: func(v *Vault) { v.Format = "secret-mask/v9" }, wantMsg: "unsupported vault format"},
		{name: "unknown kdf", mutate: func(v *Vault) { v.KDF.Name = "md5" }, wantMsg: "unsupported kdf"},
		{name: "zero iterations", mutate: func(v *Vault) { v.KDF.Iterations = 0 }, wantMsg: "unsupported kdf"},
		{name: "bad base64", mutate: func(v *Vault) { v.Nonce = "%%%" }, wantMsg: "corrupt vault"},
		{name: "short nonce", mutate: func(v *Vault) { v.Nonce = "AAAA" }, wantMsg: "nonce is 3 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := seal("right-password", m, p, fastIter)
			if err != nil {
				t.Fatal(err)
			}
			if tt.mutate != nil {
				tt.mutate(v)
			}
			pw := tt.pw
			if pw == "" {
				pw = "right-password"
			}
			_, err = Open(v, pw)
			if err == nil {
				t.Fatal("Open succeeded, want an error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("err = %v, want it to contain %q", err, tt.wantMsg)
			}
		})
	}
}

// flip changes the first base64 character to a different valid one.
func flip(s string) string {
	if s[0] == 'A' {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}

func TestReadWrite(t *testing.T) {
	m, p := sample()
	v, err := seal("pw-12345", m, p, fastIter)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "v.json")
	if err := Write(path, v); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("vault mode = %v, want 0600", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "S3cr3t") {
		t.Fatal("vault file contains the plaintext secret")
	}
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, v) {
		t.Errorf("Read = %+v, want %+v", got, v)
	}
	if _, err := Open(got, "pw-12345"); err != nil {
		t.Fatal(err)
	}
}

func TestReadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Read(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: err = %v, want ErrNotExist", err)
	}
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("{not json"), 0o600)
	if _, err := Read(bad); err == nil || !strings.Contains(err.Error(), "parse vault") {
		t.Errorf("bad json: err = %v", err)
	}
}

func TestOpenCorruptPayload(t *testing.T) {
	// A payload that decrypts but is not JSON can only come from a buggy writer; Open must not panic.
	m, _ := sample()
	v, err := seal("pw-12345", m, Payload{}, fastIter)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(v, "pw-12345"); err != nil {
		t.Fatalf("empty payload should open: %v", err)
	}
}
