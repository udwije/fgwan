//go:build !windows

package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const backendName = "AES-GCM with a local key file (development fallback)"

// keyPath is the sibling key file protecting the credential blob.
func keyPath() (string, error) {
	d, err := DefaultDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "credentials.key"), nil
}

// loadOrCreateKey returns a 32-byte key, generating one on first use.
//
// This is a development convenience for non-Windows hosts. Unlike Windows
// DPAPI, the key sits next to the ciphertext, so its protection is only the
// 0600 file mode: it stops another local account reading the passphrases, but
// anyone who can read both files can decrypt. Production deployments are
// expected to be on Windows, where the DPAPI backend is used instead.
func loadOrCreateKey() ([]byte, error) {
	p, err := keyPath()
	if err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(p); err == nil && len(b) == 32 {
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, key, 0o600); err != nil {
		return nil, fmt.Errorf("secret: writing key file: %w", err)
	}
	return key, nil
}

func aead() (cipher.AEAD, error) {
	key, err := loadOrCreateKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func protect(plain []byte) ([]byte, error) {
	g, err := aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plain, []byte("fgwan:snmpv3:v1")), nil
}

func unprotect(blob []byte) ([]byte, error) {
	g, err := aead()
	if err != nil {
		return nil, err
	}
	if len(blob) < g.NonceSize() {
		return nil, fmt.Errorf("secret: stored credential is truncated")
	}
	nonce, ct := blob[:g.NonceSize()], blob[g.NonceSize():]
	plain, err := g.Open(nil, nonce, ct, []byte("fgwan:snmpv3:v1"))
	if err != nil {
		return nil, fmt.Errorf("secret: cannot decrypt stored credential (wrong key file, or tampered with): %w", err)
	}
	return plain, nil
}

// DefaultDir returns the per-user configuration directory.
func DefaultDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "fgwan"), nil
}

// restrictACL tightens the file mode; the ACL concept is Windows-specific.
func restrictACL(path string) error { return os.Chmod(path, 0o600) }
