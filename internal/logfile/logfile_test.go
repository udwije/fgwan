package logfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotationKeepsBoundedHistory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fgwan.log")

	// 100-byte cap, keep 2 previous files.
	w, err := New(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	line := strings.Repeat("x", 40) + "\n"
	for i := 0; i < 20; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := os.Stat(p); err != nil {
		t.Fatalf("current log missing: %v", err)
	}
	for i := 1; i <= 2; i++ {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", p, i)); err != nil {
			t.Errorf("expected rotated file .%d: %v", i, err)
		}
	}
	// The whole point: rotation is bounded, so a forgotten host cannot fill
	// its disk with our logs.
	if _, err := os.Stat(p + ".3"); err == nil {
		t.Error("kept more history than requested")
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) > 3 {
		t.Errorf("log directory holds %d files, want at most 3", len(entries))
	}
}

func TestAppendsToExistingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.log")
	if err := os.WriteFile(p, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := New(p, 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("second\n")); err != nil {
		t.Fatal(err)
	}
	w.Close()

	b, _ := os.ReadFile(p)
	if got := string(b); got != "first\nsecond\n" {
		t.Errorf("content = %q, want the earlier run preserved", got)
	}
}
