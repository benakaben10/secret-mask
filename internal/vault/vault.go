// Package vault encrypts the original secret values with a password.
//
// The file keeps a plaintext manifest (placeholder ids, rule ids and file paths — never secret values)
// so that `status` and the AI guide work without the password. The manifest is bound to the ciphertext
// as AES-GCM additional data, so editing it without the password makes the vault fail to open.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/benakaben10/secret-mask/internal/fsutil"
)

const (
	// Format identifies the vault file layout.
	Format = "secret-mask/v1"
	// KDFName is the key derivation function used for new vaults.
	KDFName = "pbkdf2-sha256"
	// DefaultIterations follows the OWASP 2023 recommendation for PBKDF2-HMAC-SHA256.
	DefaultIterations = 600_000

	saltSize  = 16
	nonceSize = 12
	keySize   = 32
)

// ErrWrongPassword is returned when decryption fails: wrong password or a modified vault.
var ErrWrongPassword = errors.New("wrong password, or the vault was modified")

// Vault is the on-disk file.
type Vault struct {
	Format     string   `json:"format"`
	KDF        KDF      `json:"kdf"`
	Nonce      string   `json:"nonce"`
	Manifest   Manifest `json:"manifest"`
	Ciphertext string   `json:"ciphertext"`
}

// KDF records how the key was derived from the password.
type KDF struct {
	Name       string `json:"name"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
}

// Manifest is the plaintext, authenticated part of the vault.
type Manifest struct {
	Created string  `json:"created"`
	Updated string  `json:"updated"`
	Entries []Entry `json:"entries"`
}

// Entry describes one masked secret without its value.
type Entry struct {
	ID     string   `json:"id"`
	RuleID string   `json:"rule"`
	Files  []string `json:"files"`
}

// Payload is the encrypted part.
type Payload struct {
	Secrets   map[string]string `json:"secrets"`   // id -> original value
	Originals map[string]string `json:"originals"` // file -> sha256 of its content before it was first masked
}

// Seal encrypts p under a key derived from password, binding m as additional data.
func Seal(password string, m Manifest, p Payload) (*Vault, error) {
	return seal(password, m, p, DefaultIterations)
}

func seal(password string, m Manifest, p Payload, iterations int) (*Vault, error) {
	salt := make([]byte, saltSize)
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	gcm, err := newGCM(password, salt, iterations)
	if err != nil {
		return nil, err
	}
	aad, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return &Vault{
		Format:     Format,
		KDF:        KDF{Name: KDFName, Iterations: iterations, Salt: enc(salt)},
		Nonce:      enc(nonce),
		Manifest:   m,
		Ciphertext: enc(gcm.Seal(nil, nonce, plain, aad)),
	}, nil
}

// Open decrypts the payload. It returns ErrWrongPassword if the password is wrong or anything in the
// vault (including the manifest) was changed.
func Open(v *Vault, password string) (*Payload, error) {
	if v.Format != Format {
		return nil, fmt.Errorf("unsupported vault format %q", v.Format)
	}
	if v.KDF.Name != KDFName || v.KDF.Iterations <= 0 {
		return nil, fmt.Errorf("unsupported kdf %q (%d iterations)", v.KDF.Name, v.KDF.Iterations)
	}
	salt, err1 := dec(v.KDF.Salt)
	nonce, err2 := dec(v.Nonce)
	ct, err3 := dec(v.Ciphertext)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("corrupt vault: %w", err)
	}
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("corrupt vault: nonce is %d bytes", len(nonce))
	}
	gcm, err := newGCM(password, salt, v.KDF.Iterations)
	if err != nil {
		return nil, err
	}
	aad, err := json.Marshal(v.Manifest)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrWrongPassword
	}
	var p Payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("corrupt vault payload: %w", err)
	}
	return &p, nil
}

// Read loads a vault file.
func Read(path string) (*Vault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parse vault %s: %w", path, err)
	}
	return &v, nil
}

// Write saves a vault file readable only by its owner.
func Write(path string, v *Vault) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(data, '\n'), 0o600)
}

func newGCM(password string, salt []byte, iterations int) (cipher.AEAD, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func enc(b []byte) string          { return base64.StdEncoding.EncodeToString(b) }
func dec(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
