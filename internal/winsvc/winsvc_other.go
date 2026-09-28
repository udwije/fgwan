//go:build !windows

// Package winsvc runs fgwan under the Windows Service Control Manager.
//
// On other platforms there is no SCM, so Run always reports that the process
// is not a service and the caller runs in the foreground. Use systemd, launchd
// or a supervisor there instead.
package winsvc

import "errors"

// ErrNotService is returned when the process was not started by a service
// manager. Callers should fall back to running in the foreground.
var ErrNotService = errors.New("winsvc: service mode is only supported on Windows")

// Run always returns ErrNotService on non-Windows platforms.
func Run(serviceName string, fn func(stop <-chan struct{})) error { return ErrNotService }
