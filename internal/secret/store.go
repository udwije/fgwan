// Package secret stores SNMPv3 credentials outside the configuration file,
// encrypted with a platform key store rather than sitting in plaintext JSON.
package secret

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotFound is returned when no credential has been stored yet.
var ErrNotFound = errors.New("secret: no stored credential (run: fgwan -set-credentials)")

// Credential is the secret material for one SNMPv3 session.
type Credential struct {
	Username string `json:"username"`
	AuthPass string `json:"auth_pass"`
	PrivPass string `json:"priv_pass"`
}

// Store persists a Credential in encrypted form.
type Store struct {
	path string
}

// NewStore returns a store backed by the given blob path. An empty path
// defaults to the per-platform data directory.
func NewStore(path string) (*Store, error) {
	if path == "" {
		d, err := DefaultDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(d, "credentials.dat")
	}
	return &Store{path: path}, nil
}

// Path reports where the encrypted blob lives.
func (s *Store) Path() string { return s.path }

// Exists reports whether a credential has been stored.
func (s *Store) Exists() bool {
	fi, err := os.Stat(s.path)
	return err == nil && fi.Size() > 0
}

// Save encrypts and writes the credential, replacing any previous value.
func (s *Store) Save(c Credential) error {
	plain, err := json.Marshal(c)
	if err != nil {
		return err
	}
	defer zero(plain)

	blob, err := protect(plain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("secret: %w", err)
	}

	// Write via a temporary file so a crash cannot leave a half-written blob.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("secret: %w", err)
	}
	return restrictACL(s.path)
}

// Load reads and decrypts the stored credential.
func (s *Store) Load() (Credential, error) {
	blob, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return Credential{}, ErrNotFound
		}
		return Credential{}, fmt.Errorf("secret: %w", err)
	}
	if len(blob) == 0 {
		return Credential{}, ErrNotFound
	}
	plain, err := unprotect(blob)
	if err != nil {
		return Credential{}, err
	}
	defer zero(plain)

	var c Credential
	if err := json.Unmarshal(plain, &c); err != nil {
		return Credential{}, fmt.Errorf("secret: stored credential is corrupt: %w", err)
	}
	return c, nil
}

// Delete removes the stored credential.
func (s *Store) Delete() error {
	err := os.Remove(s.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("secret: %w", err)
	}
	return nil
}

// Describe reports the backing key store, for display in the UI and logs.
func Describe() string { return backendName }

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
