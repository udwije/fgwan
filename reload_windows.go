//go:build windows

package main

import "os"

// notifyReload is a no-op on Windows, which has no SIGHUP. Reconfiguration
// there goes through the wizard at /setup.html, which applies changes to the
// running collector without a restart.
func notifyReload(chan<- os.Signal) {}
