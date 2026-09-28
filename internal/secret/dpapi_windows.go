//go:build windows

package secret

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

const backendName = "Windows DPAPI (machine scope)"

var (
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtect   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotect = crypt32.NewProc("CryptUnprotectData")
	procLocalFree      = kernel32.NewProc("LocalFree")
)

// DPAPI flags.
const (
	cryptprotectUIForbidden  = 0x1
	cryptprotectLocalMachine = 0x4
)

// dataBlob mirrors the Win32 DATA_BLOB structure.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

// bytes copies the blob contents into Go-managed memory.
func (b dataBlob) bytes() []byte {
	if b.cbData == 0 || b.pbData == nil {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

func (b dataBlob) free() {
	if b.pbData != nil {
		procLocalFree.Call(uintptr(unsafe.Pointer(b.pbData)))
	}
}

// entropy binds the blob to this application, so another process on the same
// machine cannot decrypt it by calling DPAPI with default parameters.
var entropy = []byte("fgwan:snmpv3:v1")

// protect encrypts with machine-scope DPAPI. Machine scope is required because
// the collector runs as LOCAL SERVICE while setup runs as an administrator;
// a user-scope blob written by one could not be read by the other.
func protect(plain []byte) ([]byte, error) {
	in := newBlob(plain)
	ent := newBlob(entropy)
	var out dataBlob

	r, _, err := procCryptProtect.Call(
		uintptr(unsafe.Pointer(&in)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("fgwan SNMPv3 credential"))),
		uintptr(unsafe.Pointer(&ent)),
		0,
		0,
		uintptr(cryptprotectLocalMachine|cryptprotectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("secret: CryptProtectData: %w", err)
	}
	defer out.free()
	return out.bytes(), nil
}

// unprotect reverses protect.
func unprotect(blob []byte) ([]byte, error) {
	in := newBlob(blob)
	ent := newBlob(entropy)
	var out dataBlob

	r, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		uintptr(unsafe.Pointer(&ent)),
		0,
		0,
		uintptr(cryptprotectLocalMachine|cryptprotectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("secret: CryptUnprotectData failed (blob written on another machine, or tampered with): %w", err)
	}
	defer out.free()
	return out.bytes(), nil
}

// DefaultDir returns %ProgramData%\fgwan.
func DefaultDir() (string, error) {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "fgwan"), nil
}

// restrictACL removes inherited access so only SYSTEM, Administrators and the
// collector's service account can read the blob. DPAPI machine scope protects
// against the file being copied to another machine; this ACL is what stops
// other local users reading it here.
func restrictACL(path string) error {
	steps := [][]string{
		{path, "/inheritance:r"},
		{path, "/grant:r", "*S-1-5-18:(F)"},     // NT AUTHORITY\SYSTEM
		{path, "/grant:r", "*S-1-5-32-544:(F)"}, // BUILTIN\Administrators
		{path, "/grant:r", "*S-1-5-19:(R)"},     // NT AUTHORITY\LOCAL SERVICE
	}
	for _, args := range steps {
		if out, err := exec.Command("icacls.exe", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("secret: icacls %v: %v: %s", args[1:], err, out)
		}
	}
	return nil
}
