package collect

import (
	"math"
	"math/rand"
	"sync"
	"time"

	"fgwan/internal/config"
)

// SimSource fabricates plausible counters so the UI and the whole pipeline can
// be exercised without touching a live firewall. Enable with -sim.
type SimSource struct {
	cfg *config.Config

	mu    sync.Mutex
	state map[string]*simIface
	rng   *rand.Rand
	start time.Time
}

type simIface struct {
	in, out    uint64
	baseRx     float64 // Mbps
	baseTx     float64
	lvlRx      float64
	lvlTx      float64
	phase      float64
	burst      int
	downUntil  time.Time
	nextChange time.Time
	up         bool
	width      int
}

// NewSimSource builds a simulator for the configured interfaces.
func NewSimSource(cfg *config.Config) *SimSource {
	s := &SimSource{
		cfg:   cfg,
		state: map[string]*simIface{},
		rng:   rand.New(rand.NewSource(20260920)),
		start: time.Now(),
	}
	for _, f := range cfg.AllIfaces() {
		speed := float64(f.Speed)
		if speed <= 0 {
			speed = 100
		}
		si := &simIface{
			baseRx: speed * 0.22,
			baseTx: speed * 0.08,
			phase:  s.rng.Float64() * 6.28,
			up:     true,
			width:  64,
		}
		if f.Kind == "tunnel" {
			si.baseTx = speed * 0.16
			si.width = 32
			si.in = uint64(s.rng.Int31())
			si.out = uint64(s.rng.Int31())
		}
		si.lvlRx, si.lvlTx = si.baseRx, si.baseTx
		si.nextChange = time.Now().Add(time.Duration(60+s.rng.Intn(240)) * time.Second)
		s.state[f.ID] = si
	}
	return s
}

// Discover is a no-op for the simulator.
func (s *SimSource) Discover() error { return nil }

// Close is a no-op for the simulator.
func (s *SimSource) Close() error { return nil }

// Poll advances the simulated counters by one interval.
func (s *SimSource) Poll() (map[string]Reading, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dt := s.cfg.PollInterval().Seconds()
	now := time.Now()
	out := make(map[string]Reading, len(s.state))

	for id, si := range s.state {
		// Occasionally flap a link so gap rendering gets exercised.
		if now.After(si.nextChange) {
			if si.up {
				si.downUntil = now.Add(time.Duration(20+s.rng.Intn(60)) * time.Second)
				si.up = false
			} else {
				si.up = true
			}
			si.nextChange = now.Add(time.Duration(120+s.rng.Intn(420)) * time.Second)
		}
		if !si.up && now.After(si.downUntil) {
			si.up = true
		}
		if !si.up {
			out[id] = Reading{Present: true, Up: false, Width: si.width}
			continue
		}

		si.phase += 0.016
		if s.rng.Float64() < 0.012 {
			si.burst = 6 + s.rng.Intn(10)
		}
		mul := 1.0
		if si.burst > 0 {
			mul = 1.5 + s.rng.Float64()*0.6
			si.burst--
		}
		wave := 1 + 0.26*math.Sin(si.phase) + 0.12*math.Sin(si.phase*3.3)
		si.lvlRx = clampMin(si.lvlRx*0.78+si.baseRx*wave*0.22*mul+(s.rng.Float64()-0.5)*si.baseRx*0.1, si.baseRx*0.12)
		si.lvlTx = clampMin(si.lvlTx*0.78+si.baseTx*wave*0.22*mul+(s.rng.Float64()-0.5)*si.baseTx*0.1, si.baseTx*0.12)

		si.in += uint64(si.lvlRx * 1e6 / 8 * dt)
		si.out += uint64(si.lvlTx * 1e6 / 8 * dt)
		if si.width == 32 {
			si.in &= 0xffffffff
			si.out &= 0xffffffff
		}
		out[id] = Reading{In: si.in, Out: si.out, Up: true, Present: true, Width: si.width}
	}
	return out, nil
}

// Meta returns synthetic discovery data.
func (s *SimSource) Meta() map[string]Meta {
	out := map[string]Meta{}
	i := 1
	for _, f := range s.cfg.AllIfaces() {
		out[f.ID] = Meta{Index: i, Alias: f.Label, Resolved: true, Speed: f.Speed}
		i++
	}
	return out
}

// Health reports simulator status.
func (s *SimSource) Health() map[string]any {
	return map[string]any{
		"mode":      "simulator",
		"uptime_s":  time.Since(s.start).Seconds(),
		"engine_id": "simulated",
	}
}

func clampMin(v, min float64) float64 {
	if v < min {
		return min
	}
	return v
}
