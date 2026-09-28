package collect

import (
	"testing"

	"fgwan/internal/config"
)

func newTestCollector() *Collector {
	return &Collector{
		cfg:   &config.Config{SpikeGuardX: 10, PollMS: 5000, WindowSec: 3600},
		speed: map[string]int{"wan1": 1000, "t1": 100},
	}
}

func TestRateBasic(t *testing.T) {
	c := newTestCollector()
	// 625 000 bytes over 5 s = 1 Mbit/s
	got, ok := c.rate(0, 625000, 5, 64, "wan1")
	if !ok {
		t.Fatal("rate rejected a valid delta")
	}
	if want := 1e6; got != want {
		t.Errorf("rate = %v, want %v", got, want)
	}
}

func TestRate64BitBackwardsIsReset(t *testing.T) {
	c := newTestCollector()
	if _, ok := c.rate(5000000, 1000, 5, 64, "wan1"); ok {
		t.Error("a 64-bit counter going backwards must be treated as a reset, not a wrap")
	}
	if c.resets != 1 {
		t.Errorf("resets = %d, want 1", c.resets)
	}
}

func TestRate32BitWrapIsCorrected(t *testing.T) {
	c := newTestCollector()
	old := uint64(1<<32 - 1000)
	cur := uint64(2000) // wrapped, true delta is 3000 bytes
	got, ok := c.rate(old, cur, 5, 32, "t1")
	if !ok {
		t.Fatal("a 32-bit wrap should be corrected, not discarded")
	}
	if want := 3000.0 * 8 / 5; got != want {
		t.Errorf("rate = %v, want %v", got, want)
	}
}

func TestSpikeGuardRejectsImplausibleRate(t *testing.T) {
	c := newTestCollector()
	// 100 Mbit/s tunnel: a delta implying ~16 Gbit/s must be discarded.
	if _, ok := c.rate(0, 10000000000, 5, 32, "t1"); ok {
		t.Error("spike guard should reject a rate far above link capacity")
	}
	if c.resets == 0 {
		t.Error("discarded spike should be counted as a reset")
	}
}

func TestNoCapacityMeansNoSpikeGuard(t *testing.T) {
	c := newTestCollector()
	if _, ok := c.rate(0, 10000000000, 5, 64, "unknown"); !ok {
		t.Error("without a declared capacity the guard must not fire")
	}
}

// After a reconfiguration, an interface that was already being polled should
// keep its counter baseline, otherwise every edit punches a one-sample gap
// into every surviving chart.
func TestSeedBaselinesCarriesSurvivors(t *testing.T) {
	oldCfg := &config.Config{
		Device: config.Device{Host: "h"}, PollMS: 5000, WindowSec: 3600, SpikeGuardX: 10,
		Zones: []config.Zone{{ID: "z", Interfaces: []config.Iface{
			{ID: "a", Match: "port1", Kind: "phys"},
			{ID: "b", Match: "port2", Kind: "phys"},
		}}},
	}
	old := New(oldCfg, nil, nil, nil)
	old.prev["a"] = prev{in: 100, out: 200, valid: true}
	old.prev["b"] = prev{in: 300, out: 400, valid: true}

	newCfg := &config.Config{
		Device: config.Device{Host: "h"}, PollMS: 5000, WindowSec: 3600, SpikeGuardX: 10,
		Zones: []config.Zone{{ID: "z", Interfaces: []config.Iface{
			{ID: "a", Match: "port1", Kind: "phys"},
			{ID: "c", Match: "port3", Kind: "phys"},
		}}},
	}
	fresh := New(newCfg, nil, nil, nil)
	fresh.SeedBaselines(old)

	if p := fresh.prev["a"]; !p.valid || p.in != 100 {
		t.Error("surviving interface a should keep its baseline")
	}
	if _, ok := fresh.prev["b"]; ok {
		t.Error("removed interface b should not be carried over")
	}
	if p := fresh.prev["c"]; p.valid {
		t.Error("newly added interface c must start without a baseline")
	}
}
