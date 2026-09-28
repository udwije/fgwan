// Package logfile provides a size-rotating log writer.
//
// A service has no console, so its diagnostics have to land somewhere durable.
// Left unbounded that file would grow forever on a host nobody looks at, so
// this rotates it and keeps a small number of previous files.
package logfile

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Writer is an io.WriteCloser that rotates once the file passes a size limit.
type Writer struct {
	path     string
	maxBytes int64
	keep     int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// New opens (or creates) path for appending. maxBytes of 0 selects 8 MiB, and
// keep of 0 selects 3 previous files.
func New(path string, maxBytes int64, keep int) (*Writer, error) {
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	if keep <= 0 {
		keep = 3
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("logfile: %w", err)
		}
	}
	w := &Writer{path: path, maxBytes: maxBytes, keep: keep}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("logfile: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("logfile: %w", err)
	}
	w.f, w.size = f, fi.Size()
	return nil
}

// Write appends to the log, rotating first if the entry would exceed the cap.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, os.ErrClosed
	}
	if w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			// Rotation failing is not a reason to lose the message.
			fmt.Fprintf(os.Stderr, "logfile: rotate: %v\n", err)
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate shifts fgwan.log -> fgwan.log.1 -> fgwan.log.2 ... and reopens.
// It must be called with w.mu held.
func (w *Writer) rotate() error {
	if err := w.f.Close(); err != nil {
		return err
	}
	// Drop the oldest, then walk backwards so nothing is overwritten early.
	os.Remove(fmt.Sprintf("%s.%d", w.path, w.keep))
	for i := w.keep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
	}
	os.Rename(w.path, w.path+".1")
	return w.open()
}

// Close closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
