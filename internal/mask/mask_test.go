package mask

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/benakaben10/secret-mask/internal/detect"
	"github.com/benakaben10/secret-mask/internal/fsutil"
	"github.com/benakaben10/secret-mask/internal/vault"
)

// tree writes files (slash paths) under a temp dir and returns it.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func read(t *testing.T, dir, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func f(file, secret string) detect.Finding {
	return detect.Finding{RuleID: "test-rule", File: file, Secret: secret}
}

// Test values are assembled at run time so the source never contains a detectable secret.
var liveKey = "live_" + "kQ9xT2mZ7vB4nR8w"

var originalFiles = map[string]string{
	".env":            "DB_HOST=db\nDB_PASSWORD=Admin@123\nJWT_SECRET=s3cr3t-jwt-k3y\nPORT=8080\n",
	"config/app.json": `{"db":{"password":"Admin@123"},"api":{"key":"` + liveKey + `"}}` + "\n",
	"k8s/secret.yaml": "apiVersion: v1\nkind: Secret\nstringData:\n  DATABASE_PASSWORD: \"Prod-DB-Pass\"\n",
	"README.md":       "no secrets here\n",
}

var originalFindings = []detect.Finding{
	f(".env", "Admin@123"),
	f(".env", "s3cr3t-jwt-k3y"),
	f("config/app.json", "Admin@123"),
	f("config/app.json", liveKey),
	f("k8s/secret.yaml", "Prod-DB-Pass"),
}

func TestMaskRestoreRoundTrip(t *testing.T) {
	dir := tree(t, originalFiles)
	s := NewState()

	res, err := Mask(dir, originalFindings, s, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Masked != 5 || len(res.Files) != 3 || len(res.Skipped) != 0 {
		t.Fatalf("Mask = %+v", res)
	}
	if s.Len() != 4 {
		t.Errorf("distinct secrets = %d, want 4 (Admin@123 is shared)", s.Len())
	}
	for rel := range originalFiles {
		content := read(t, dir, rel)
		for _, fd := range originalFindings {
			if strings.Contains(content, fd.Secret) {
				t.Errorf("%s still contains %q after masking", rel, fd.Secret)
			}
		}
	}
	if got := read(t, dir, "README.md"); got != originalFiles["README.md"] {
		t.Errorf("README.md changed: %q", got)
	}

	rres, err := Restore(dir, s, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rres.Restored != 5 || len(rres.Missing) != 0 || len(rres.Identical) != 3 || len(rres.Edited) != 0 {
		t.Errorf("Restore = %+v", rres)
	}
	for rel, want := range originalFiles {
		if got := read(t, dir, rel); got != want {
			t.Errorf("%s after restore =\n%q\nwant\n%q", rel, got, want)
		}
	}
}

func TestSameSecretSamePlaceholder(t *testing.T) {
	dir := tree(t, originalFiles)
	s := NewState()
	if _, err := Mask(dir, originalFindings, s, Options{}); err != nil {
		t.Fatal(err)
	}
	var shared string
	for _, id := range s.IDs() {
		if v, _ := s.Value(id); v == "Admin@123" {
			shared = id
		}
	}
	if want := []string{".env", "config/app.json"}; !reflect.DeepEqual(s.Files(shared), want) {
		t.Errorf("files of shared secret = %v, want %v", s.Files(shared), want)
	}
	for _, rel := range []string{".env", "config/app.json"} {
		if !strings.Contains(read(t, dir, rel), Placeholder(shared)) {
			t.Errorf("%s does not use the shared placeholder", rel)
		}
	}
}

func TestOverlappingSecrets(t *testing.T) {
	// "abc12345" is inside "xyz-abc12345-xyz"; the longer one must be masked whole and both restored.
	files := map[string]string{"a.env": "LONG=xyz-abc12345-xyz\nSHORT=abc12345\nBOTH=abc12345/xyz-abc12345-xyz\n"}
	dir := tree(t, files)
	s := NewState()
	res, err := Mask(dir, []detect.Finding{f("a.env", "abc12345"), f("a.env", "xyz-abc12345-xyz")}, s, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Masked != 4 {
		t.Errorf("masked %d occurrences, want 4", res.Masked)
	}
	masked := read(t, dir, "a.env")
	if strings.Contains(masked, "abc12345") {
		t.Errorf("secret left in %q", masked)
	}
	if _, err := Restore(dir, s, Options{}); err != nil {
		t.Fatal(err)
	}
	if got := read(t, dir, "a.env"); got != files["a.env"] {
		t.Errorf("restore = %q, want %q", got, files["a.env"])
	}
}

func TestMaskSkips(t *testing.T) {
	dir := tree(t, map[string]string{
		"enc.yaml":   "data:\n  password: UHJvZC1E" + "Qi1QYXNz\n",
		"bin.dat":    "TOKEN=abcdefgh\x00binary",
		"skipme.env": "PASSWORD=hunter2hunter2\n",
	})
	if err := os.Symlink(filepath.Join(dir, "skipme.env"), filepath.Join(dir, "link.env")); err != nil {
		t.Fatal(err)
	}
	s := NewState()
	res, err := Mask(dir, []detect.Finding{
		f("enc.yaml", "Prod-DB-Pass"), // decoded by gitleaks, not literal in the file
		f("bin.dat", "abcdefgh"),
		f("link.env", "hunter2hunter2"),
		f("missing.env", "whatever1"),
		f("skipme.env", "hunter2hunter2"),
	}, s, Options{Skip: map[string]bool{"skipme.env": true}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Masked != 0 || s.Len() != 0 {
		t.Errorf("masked %d, state %d; want nothing", res.Masked, s.Len())
	}
	joined := strings.Join(res.Skipped, "\n")
	for _, want := range []string{"enc.yaml: test-rule secret not found literally", "bin.dat: binary file", "link.env: not a regular file", "missing.env: not a regular file"} {
		if !strings.Contains(joined, want) {
			t.Errorf("skipped reasons %q missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "skipme.env") {
		t.Error("files in Skip must be ignored silently")
	}
	if got := read(t, dir, "skipme.env"); got != "PASSWORD=hunter2hunter2\n" {
		t.Errorf("skipped file was modified: %q", got)
	}
}

func TestMaskSecretOverlappingPlaceholder(t *testing.T) {
	dir := tree(t, map[string]string{"a.env": "X=__SECRET_MASK_0123456789abcdef__\nY=SECRET_MASK_0123\n"})
	res, err := Mask(dir, []detect.Finding{f("a.env", "SECRET_MASK_0123"), f("a.env", "__SECRET_MASK_x")}, NewState(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Masked != 0 || len(res.Skipped) != 2 {
		t.Errorf("Mask = %+v, want both skipped", res)
	}
}

func TestMaskDryRun(t *testing.T) {
	dir := tree(t, originalFiles)
	res, err := Mask(dir, originalFindings, NewState(), Options{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Masked != 5 {
		t.Errorf("dry run masked = %d, want 5", res.Masked)
	}
	for rel, want := range originalFiles {
		if got := read(t, dir, rel); got != want {
			t.Errorf("dry run changed %s", rel)
		}
	}
}

func TestMaskPreservesMode(t *testing.T) {
	dir := tree(t, map[string]string{"run.sh": "#!/bin/sh\nTOKEN=abcdefgh123\n"})
	os.Chmod(filepath.Join(dir, "run.sh"), 0o750)
	if _, err := Mask(dir, []detect.Finding{f("run.sh", "abcdefgh123")}, NewState(), Options{}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(dir, "run.sh"))
	if info.Mode().Perm() != 0o750 {
		t.Errorf("mode = %v, want 0750", info.Mode().Perm())
	}
}

func TestMaskAgainReusesVault(t *testing.T) {
	dir := tree(t, originalFiles)
	s := NewState()
	if _, err := Mask(dir, originalFindings[:2], s, Options{}); err != nil {
		t.Fatal(err)
	}
	firstIDs := s.IDs()
	hashAfterFirst, _ := s.Original(".env")

	// Simulate a vault round trip, then mask the rest plus a value seen before.
	s2 := FromVault(s.Manifest(), ptr(s.Payload()))
	res, err := Mask(dir, originalFindings, s2, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Masked != 3 {
		t.Errorf("second run masked %d, want 3", res.Masked)
	}
	for _, id := range firstIDs {
		if _, ok := s2.Value(id); !ok {
			t.Errorf("id %s lost on second run", id)
		}
	}
	if h, _ := s2.Original(".env"); h != hashAfterFirst {
		t.Error("original hash of .env must be kept from the first masking")
	}
	if _, err := Restore(dir, s2, Options{}); err != nil {
		t.Fatal(err)
	}
	for rel, want := range originalFiles {
		if got := read(t, dir, rel); got != want {
			t.Errorf("%s after two masks + restore = %q", rel, got)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func maskedTree(t *testing.T) (string, *State) {
	t.Helper()
	dir := tree(t, originalFiles)
	s := NewState()
	if _, err := Mask(dir, originalFindings, s, Options{}); err != nil {
		t.Fatal(err)
	}
	return dir, s
}

func TestRestoreMovedPlaceholder(t *testing.T) {
	dir, s := maskedTree(t)
	// An AI moves the k8s secret value into a new file and removes the old one.
	token := Pattern.FindString(read(t, dir, "k8s/secret.yaml"))
	os.Remove(filepath.Join(dir, "k8s", "secret.yaml"))
	write(t, dir, "k8s/moved.yaml", "password: "+token+"\n")

	res, err := Restore(dir, s, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := read(t, dir, "k8s/moved.yaml"); got != "password: Prod-DB-Pass\n" {
		t.Errorf("moved placeholder restored to %q", got)
	}
	if res.Files["k8s/moved.yaml"] != 1 {
		t.Errorf("Files = %v", res.Files)
	}
}

func TestRestoreMissingPlaceholderWritesNothing(t *testing.T) {
	for name, damage := range map[string]func(string) string{
		"deleted":    func(c string) string { return Pattern.ReplaceAllString(c, "changeme") },
		"upper-case": func(c string) string { return Pattern.ReplaceAllStringFunc(c, strings.ToUpper) },
		"truncated": func(c string) string {
			return Pattern.ReplaceAllStringFunc(c, func(p string) string { return p[:len(p)-2] })
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, s := maskedTree(t)
			write(t, dir, "k8s/secret.yaml", damage(read(t, dir, "k8s/secret.yaml")))
			envBefore := read(t, dir, ".env")

			res, err := Restore(dir, s, Options{})
			var missing *MissingError
			if !errors.As(err, &missing) {
				t.Fatalf("err = %v, want *MissingError", err)
			}
			if len(missing.IDs) != 1 || len(res.Missing) != 1 {
				t.Errorf("missing = %v", missing.IDs)
			}
			if !strings.Contains(err.Error(), "k8s/secret.yaml") {
				t.Errorf("error should name where it was masked: %v", err)
			}
			if got := read(t, dir, ".env"); got != envBefore {
				t.Error("files were written although placeholders are missing")
			}
		})
	}
}

func TestRestoreForce(t *testing.T) {
	dir, s := maskedTree(t)
	write(t, dir, "k8s/secret.yaml", "deleted\n")
	res, err := Restore(dir, s, Options{Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Missing) != 1 {
		t.Errorf("Missing = %v, want 1", res.Missing)
	}
	if got := read(t, dir, ".env"); got != originalFiles[".env"] {
		t.Errorf(".env not restored with --force: %q", got)
	}
}

func TestRestoreUnknownAndEdited(t *testing.T) {
	dir, s := maskedTree(t)
	foreign := Placeholder("ffffffffffffffff")
	write(t, dir, ".env", read(t, dir, ".env")+"OTHER="+foreign+"\n")

	res, err := Restore(dir, s, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Unknown, []string{foreign}) {
		t.Errorf("Unknown = %v", res.Unknown)
	}
	if !reflect.DeepEqual(res.Edited, []string{".env"}) {
		t.Errorf("Edited = %v, want [.env]", res.Edited)
	}
	if got := read(t, dir, ".env"); got != originalFiles[".env"]+"OTHER="+foreign+"\n" {
		t.Errorf(".env = %q", got)
	}
}

func TestRestoreDryRun(t *testing.T) {
	dir, s := maskedTree(t)
	before := read(t, dir, ".env")
	res, err := Restore(dir, s, Options{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Restored != 5 {
		t.Errorf("dry run restored %d", res.Restored)
	}
	if read(t, dir, ".env") != before {
		t.Error("dry run wrote files")
	}
}

func TestScan(t *testing.T) {
	p1, p2 := Placeholder("0000000000000001"), Placeholder("0000000000000002")
	dir := tree(t, map[string]string{
		"a.env":          "A=" + p1 + "\nB=" + p2 + "\n",
		"plain.txt":      "nothing",
		".git/config":    "x=" + p1,
		"vault.json":     p1,
		"bin.dat":        p1 + "\x00",
		"sub/dir/c.yaml": "c: " + p2,
	})
	hits, err := Scan(dir, map[string]bool{"vault.json": true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, h := range hits {
		got[h.Rel] = h.IDs()
	}
	want := map[string][]string{
		"a.env":          {"0000000000000001", "0000000000000002"},
		"sub/dir/c.yaml": {"0000000000000002"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Scan = %v, want %v", got, want)
	}
}

func TestPlaceholder(t *testing.T) {
	p := Placeholder("0123456789abcdef")
	if p != "__SECRET_MASK_0123456789abcdef__" || !Pattern.MatchString(p) || IDOf(p) != "0123456789abcdef" {
		t.Errorf("placeholder = %q", p)
	}
	for _, bad := range []string{"__SECRET_MASK_0123456789ABCDEF__", "__SECRET_MASK_0123456789abcde__", "__secret_mask_0123456789abcdef__"} {
		if Pattern.MatchString(bad) {
			t.Errorf("Pattern matched %q", bad)
		}
	}
	a, _ := newID()
	b, _ := newID()
	if a == b || !Pattern.MatchString(Placeholder(a)) {
		t.Errorf("newID = %q, %q", a, b)
	}
}

func TestStateManifestAndPayload(t *testing.T) {
	_, s := maskedTree(t)
	m := s.Manifest()
	if len(m.Entries) != 4 || m.Created == "" || m.Updated == "" {
		t.Fatalf("manifest = %+v", m)
	}
	for i := 1; i < len(m.Entries); i++ {
		if m.Entries[i-1].ID >= m.Entries[i].ID {
			t.Error("manifest entries are not sorted by id")
		}
	}
	p := s.Payload()
	if len(p.Secrets) != 4 || len(p.Originals) != 3 {
		t.Errorf("payload = %d secrets, %d originals", len(p.Secrets), len(p.Originals))
	}
	// Payload must be a copy.
	for k := range p.Secrets {
		p.Secrets[k] = "tampered"
	}
	for _, id := range s.IDs() {
		if v, _ := s.Value(id); v == "tampered" {
			t.Fatal("Payload exposed internal map")
		}
	}

	// Round trip through the vault types keeps everything.
	s2 := FromVault(m, &p)
	if s2.Len() != s.Len() || s2.Manifest().Created != m.Created {
		t.Error("FromVault lost data")
	}
	if s2.Files("nope") != nil {
		t.Error("Files of unknown id should be nil")
	}
	_ = vault.Manifest{}
}

func TestOriginalHash(t *testing.T) {
	dir, s := maskedTree(t)
	_ = dir
	h, ok := s.Original(".env")
	if !ok || h != fsutil.SHA256Hex([]byte(originalFiles[".env"])) {
		t.Errorf("original hash = %s, %v", h, ok)
	}
	if _, ok := s.Original("README.md"); ok {
		t.Error("unmasked file has an original hash")
	}
}

func TestMissingErrorMessage(t *testing.T) {
	err := NewMissingError([]string{"0123456789abcdef"}, func(string) []string { return []string{"a.env", "b.yaml"} })
	want := "1 placeholder(s) are missing or were altered:\n  __SECRET_MASK_0123456789abcdef__ (masked in: a.env, b.yaml)"
	if err.Error() != want {
		t.Errorf("Error() =\n%s\nwant\n%s", err.Error(), want)
	}
}
