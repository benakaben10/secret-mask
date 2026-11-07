package mask

import (
	"reflect"
	"testing"

	"github.com/OWNER/secret-mask/internal/detect"
)

func TestUnmasked(t *testing.T) {
	p := Placeholder("0123456789abcdef")
	in := []detect.Finding{
		{File: "a.env", Secret: "real-secret"},
		{File: "a.env", Secret: p},
		{File: "b.yaml", Secret: "pw: " + p},
		{File: ".secret-mask.vault", Secret: "ciphertext"},
	}
	got := Unmasked(in, map[string]bool{".secret-mask.vault": true})
	if !reflect.DeepEqual(got, in[:1]) {
		t.Errorf("Unmasked = %+v", got)
	}
	if len(Unmasked(nil, nil)) != 0 {
		t.Error("nil input")
	}
}
