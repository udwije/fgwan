//go:build !windows

package term

import (
	"os"
	"os/exec"
)

// withEchoDisabled runs fn with terminal echo turned off, using stty.
func withEchoDisabled(fn func() error) error {
	if !isTTY() {
		return fn()
	}
	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	if err := off.Run(); err != nil {
		return fn()
	}
	defer func() {
		on := exec.Command("stty", "echo")
		on.Stdin = os.Stdin
		on.Run()
	}()
	return fn()
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
