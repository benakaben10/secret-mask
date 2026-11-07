package fsutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")

	if err := WriteFileAtomic(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("two"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "two" {
		t.Errorf("content = %q, want %q", got, "two")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestWriteFileAtomicMissingDir(t *testing.T) {
	err := WriteFileAtomic(filepath.Join(t.TempDir(), "nope", "f.txt"), []byte("x"), 0o600)
	if err == nil {
		t.Fatal("expected an error for a missing directory")
	}
}

func TestIsBinary(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty", nil, false},
		{"text", []byte("PASSWORD=abc\n"), false},
		{"utf8", []byte("mật khẩu: abc"), false},
		{"nul", []byte("abc\x00def"), true},
		{"nul after 8000 bytes", append([]byte(strings.Repeat("a", 8000)), 0), false},
	}
	for _, tt := range tests {
		if got := IsBinary(tt.data); got != tt.want {
			t.Errorf("%s: IsBinary = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSHA256Hex(t *testing.T) {
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := SHA256Hex([]byte("abc")); got != want {
		t.Errorf("SHA256Hex(abc) = %s, want %s", got, want)
	}
}
