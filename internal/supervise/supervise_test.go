package supervise

import (
	"errors"
	"sync"
	"testing"
	"time"

	"fgwan/internal/collect"
	"fgwan/internal/config"
)

// fakeSource mimics a device whose octet counters keep climbing. The counter
// deliberately lives outside the source, because a real agent does not reset
// its counters just because fgwan reloaded its own configuration: carrying
// baselines across a reload is only meaningful if the device is continuous.
type fakeSource struct {
	cfg     *config.Config
	counter *uint64

	mu     sync.Mutex
	closed bool
}

func (f *fakeSource) Discover() error { return nil }

func (f *fakeSource) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeSource) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *fakeSource) Poll() (map[string]collect.Reading, error) {
	*f.counter += 625000
	out := map[string]collect.Reading{}
	for _, i := range f.cfg.AllIfaces() {
		out[i.ID] = collect.Reading{
			In: *f.counter, Out: *f.counter, Up: true, Present: true, Width: 64,
		}
	}
	return out, nil
}

func (f *fakeSource) Meta() map[string]collect.Meta {
	out := map[string]collect.Meta{}
	for _, i := range f.cfg.AllIfaces() {
		out[i.ID] = collect.Meta{Resolved: true}
	}
	return out
}

func (f *fakeSource) Health() map[string]any { return map[string]any{"mode": "fake"} }

// cfgWith builds a valid single-zone configuration.
//
// The poll interval is set enormously high so the collector's ticker never
// fires during the test: every sample is driven explicitly. No capacity is
// declared, which disables the spike guard — these tests drive polls
// microseconds apart, so the computed rates are meaninglessly large and only
// the plumbing is under test.
func cfgWith(t *testing.T, ids ...string) *config.Config {
	t.Helper()
	z := config.Zone{ID: "z1", Name: "Z"}
	for _, id := range ids {
		z.Interfaces = append(z.Interfaces, config.Iface{
			ID: id, Match: id, Kind: "phys",
		})
	}
	c := &config.Config{
		Device:    config.Device{Host: "10.0.0.1"},
		PollMS:    3600000,
		WindowSec: 3600000,
		Zones:     []config.Zone{z},
	}
	// Round-trip through the real writer so the test only ever uses
	// configurations the product would actually accept.
	if err := config.Save(t.TempDir()+"/c.json", c); err != nil {
		t.Fatalf("config rejected: %v", err)
	}
	return c
}

// waitFrames blocks until the ring holds at least n frames. The first poll of
// a cold start happens on a background goroutine, so tests must synchronise on
// it rather than assume it has already landed.
func waitFrames(t *testing.T, s *Supervisor, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Ring().Len() >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d frames (have %d)", n, s.Ring().Len())
}

// poll drives one collection cycle, with a short pause so the elapsed time
// between samples is non-zero.
func poll(s *Supervisor) {
	time.Sleep(2 * time.Millisecond)
	s.Collector().PollOnceForTest()
}

func newTestSupervisor(t *testing.T, cfg *config.Config) (*Supervisor, *uint64, func() int) {
	t.Helper()
	var counter uint64
	var built int
	factory := func(c *config.Config, _ collect.Source) (collect.Source, error) {
		built++
		return &fakeSource{cfg: c, counter: &counter}, nil
	}
	s, err := New(cfg, factory, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, &counter, func() int { return built }
}

func TestReloadKeepsHistoryForSurvivingInterfaces(t *testing.T) {
	s, _, _ := newTestSupervisor(t, cfgWith(t, "a", "b"))

	waitFrames(t, s, 1) // the automatic cold-start poll: baseline only
	poll(s)             // first frame carrying real values
	before := s.Ring().Len()
	if before != 2 {
		t.Fatalf("expected 2 frames before reload, got %d", before)
	}

	if err := s.Reload(cfgWith(t, "a", "c")); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if s.Generation() != 2 {
		t.Errorf("generation = %d, want 2", s.Generation())
	}

	// A reload that carried baselines over must not poll immediately: doing so
	// would compute a rate over a sliver of elapsed time. So the frame count
	// should be unchanged.
	if got := s.Ring().Len(); got != before {
		t.Errorf("history length = %d, want %d preserved across reload", got, before)
	}

	var sawA bool
	for _, f := range s.Ring().Snapshot(0) {
		if _, ok := f.V["b"]; ok {
			t.Error("removed interface b should not survive the reload")
		}
		if _, ok := f.V["c"]; ok {
			t.Error("newly added interface c must not be given invented history")
		}
		if f.V["a"] != nil {
			sawA = true
		}
	}
	if !sawA {
		t.Error("surviving interface a lost all of its history")
	}

	// The point of carrying baselines over: the very next sample for a
	// surviving interface is a real rate, not another baseline gap.
	poll(s)
	last, ok := s.Ring().Last()
	if !ok {
		t.Fatal("no frame after polling the new generation")
	}
	if last.V["a"] == nil {
		t.Error("surviving interface a should produce a rate immediately, not re-baseline")
	}
	if last.V["c"] != nil {
		t.Error("newly added interface c should spend its first poll establishing a baseline")
	}
}

func TestReloadFailureLeavesPreviousGenerationRunning(t *testing.T) {
	var counter uint64
	fail := false
	factory := func(c *config.Config, _ collect.Source) (collect.Source, error) {
		if fail {
			return nil, errors.New("source unavailable")
		}
		return &fakeSource{cfg: c, counter: &counter}, nil
	}

	s, err := New(cfgWith(t, "a"), factory, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	waitFrames(t, s, 1)

	fail = true
	if err := s.Reload(cfgWith(t, "a", "b")); err == nil {
		t.Fatal("expected reload to fail")
	}
	if s.Generation() != 1 {
		t.Errorf("generation advanced to %d despite a failed reload", s.Generation())
	}
	if got := len(s.Config().AllIfaces()); got != 1 {
		t.Errorf("config changed despite a failed reload: %d interfaces", got)
	}

	// The original generation must still be collecting.
	before := s.Ring().Len()
	poll(s)
	if s.Ring().Len() != before+1 {
		t.Error("previous generation stopped collecting after a failed reload")
	}
}

func TestReloadClosesTheSupersededSource(t *testing.T) {
	var counter uint64
	var sources []*fakeSource
	factory := func(c *config.Config, _ collect.Source) (collect.Source, error) {
		fs := &fakeSource{cfg: c, counter: &counter}
		sources = append(sources, fs)
		return fs, nil
	}

	s, err := New(cfgWith(t, "a"), factory, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	waitFrames(t, s, 1)

	if err := s.Reload(cfgWith(t, "a", "b")); err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(sources))
	}
	if !sources[0].isClosed() {
		t.Error("the superseded source was not closed; its socket would leak")
	}
	if sources[1].isClosed() {
		t.Error("the live source must not be closed")
	}
}

func TestReloadAdjustsWindowCapacity(t *testing.T) {
	s, _, _ := newTestSupervisor(t, cfgWith(t, "a"))
	waitFrames(t, s, 1)
	poll(s)

	grown := cfgWith(t, "a")
	grown.PollMS = 3600000
	grown.WindowSec = 7200000 // double the window
	if err := config.Save(t.TempDir()+"/c.json", grown); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(grown); err != nil {
		t.Fatal(err)
	}
	if got, want := s.Ring().Cap(), grown.Capacity(); got != want {
		t.Errorf("ring capacity = %d, want %d after a window change", got, want)
	}
	if s.Ring().Len() != 2 {
		t.Errorf("held frames = %d, want the existing 2 carried over", s.Ring().Len())
	}
}
