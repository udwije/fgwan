//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// notifyReload wires SIGHUP to the configuration reload path.
func notifyReload(c chan<- os.Signal) { signal.Notify(c, syscall.SIGHUP) }
