//go:build windows

package term

import (
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

const enableEchoInput = 0x0004

// withEchoDisabled runs fn with console echo turned off.
func withEchoDisabled(fn func() error) error {
	h, err := syscall.GetStdHandle(syscall.STD_INPUT_HANDLE)
	if err != nil {
		return fn() // not a console (piped input): read normally
	}
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(uintptr(h), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return fn()
	}
	procSetConsoleMode.Call(uintptr(h), uintptr(mode&^enableEchoInput))
	defer procSetConsoleMode.Call(uintptr(h), uintptr(mode))
	return fn()
}
