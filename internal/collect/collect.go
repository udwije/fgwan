// Package collect polls the FortiGate and turns octet counters into bit rates.
package collect

import (
	"fmt"
	"log"
	"sync"
	"time"

	"fgwan/internal/ber"
	"fgwan/internal/config"
	"fgwan/internal/snmp"
	"fgwan/internal/store"
)

// IF-MIB columns.
var (
	oidIfName      = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.1")
	oidIfHCIn      = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.6")
	oidIfHCOut     = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.10")
	oidIfHighSpeed = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.15")
	oidIfAlias     = ber.MustParseOIDString("1.3.6.1.2.1.31.1.1.1.18")
	oidIfOperState = ber.MustParseOIDString("1.3.6.1.2.1.2.2.1.8")
	oidSysUpTime   = ber.MustParseOIDString("1.3.6.1.2.1.1.3.0")
)

// Source abstracts the data origin so the simulator can stand in for SNMP.
type Source interface {
	Discover() error
	Poll() (map[string]Reading, error)
	Meta() map[string]Meta
	Health() map[string]any
	Close() error
}

// Reading is one raw counter observation for an interface.
type Reading struct {
	In      uint64
	Out     uint64
	Up      bool
	Present bool
	Width   int // counter width in bits: 64 or 32
}

// Meta is discovery-time information about an interface.
type Meta struct {
	Index    int    `json:"index"`
	Alias    string `json:"alias"`
	Resolved bool   `json:"resolved"`
	Speed    int    `json:"speed_mbps"`
}

// prev remembers the last accepted counter sample for delta computation.
type prev struct {
	in, out uint64
	at      time.Time
	valid   bool
}

// Collector drives the poll loop and publishes frames.
type Collector struct {
	cfg   *config.Config
	src   Source
	ring  *store.Ring
	subs  *Hub
	ifs   []config.Iface
	speed map[string]int

	mu        sync.Mutex
	prev      map[string]prev
	lastPoll  time.Time
	lastErr   string
	pollFails uint64
	resets    uint64

	// seededAt is the timestamp of the newest counter baseline carried over
	// from a previous generation, or the zero time on a cold start.
	seededAt time.Time
}

// New builds a collector over the given source.
func New(cfg *config.Config, src Source, ring *store.Ring, hub *Hub) *Collector {
	c := &Collector{
		cfg: cfg, src: src, ring: ring, subs: hub,
		ifs:   cfg.AllIfaces(),
		prev:  map[string]prev{},
		speed: map[string]int{},
	}
	for _, f := range c.ifs {
		c.speed[f.ID] = f.Speed
	}
	return c
}

// SeedBaselines carries counter baselines over from a previous collector, so a
// reconfiguration does not force every surviving interface to spend one poll
// re-establishing its delta reference (which would punch a gap in the chart).
func (c *Collector) SeedBaselines(old *Collector) {
	if old == nil {
		return
	}
	old.mu.Lock()
	src := make(map[string]prev, len(old.prev))
	for k, v := range old.prev {
		src[k] = v
	}
	old.mu.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.ifs {
		if p, ok := src[f.ID]; ok {
			c.prev[f.ID] = p
			if p.at.After(c.seededAt) {
				c.seededAt = p.at
			}
		}
	}
}

// Run polls until the stop channel closes.
func (c *Collector) Run(stop <-chan struct{}) {
	if err := c.src.Discover(); err != nil {
		log.Printf("discovery failed (will retry): %v", err)
	}
	tick := time.NewTicker(c.cfg.PollInterval())
	defer tick.Stop()
	redisc := time.NewTicker(time.Duration(c.cfg.RediscoverS) * time.Second)
	defer redisc.Stop()

	// A cold start polls immediately, so the dashboard has a baseline at once.
	//
	// After a reconfiguration the carried-over baselines may be only
	// milliseconds old, and polling straight away would compute a rate over
	// that sliver of time. On real hardware that is not a wild overshoot —
	// the counter has genuinely only advanced by a few milliseconds' worth —
	// but it is a poor sample: agents refresh interface counters on their own
	// cadence, so a sub-second delta is as likely to read zero as anything
	// else, which puts a spurious dip at the very moment of the change. The
	// simulator is worse still, since it fabricates a whole interval of octets
	// per call regardless of elapsed time, which would trip the spike guard.
	//
	// Waiting out the remainder of the interval costs newly added interfaces
	// one extra cycle before they appear, and keeps every surviving series
	// continuous and correctly scaled. That is the right side of the trade for
	// a dashboard whose whole point is uninterrupted history.
	c.mu.Lock()
	seeded := c.seededAt
	c.mu.Unlock()
	if !seeded.IsZero() {
		if wait := c.cfg.PollInterval() - time.Since(seeded); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-stop:
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}

	c.once()
	for {
		select {
		case <-stop:
			return
		case <-redisc.C:
			if err := c.src.Discover(); err != nil {
				log.Printf("rediscovery failed: %v", err)
			}
		case <-tick.C:
			c.once()
		}
	}
}

// once performs a single poll and publishes the resulting frame.
func (c *Collector) once() {
	now := time.Now()
	readings, err := c.src.Poll()

	c.mu.Lock()
	c.lastPoll = now
	if err != nil {
		c.pollFails++
		c.lastErr = err.Error()
	} else {
		c.lastErr = ""
	}

	frame := store.Frame{TS: now.UnixMilli(), V: map[string]*store.Point{}}

	for _, iface := range c.ifs {
		id := iface.ID
		if err != nil {
			frame.V[id] = nil
			c.prev[id] = prev{}
			continue
		}
		r, ok := readings[id]
		if !ok || !r.Present || !r.Up {
			frame.V[id] = nil
			c.prev[id] = prev{} // force a fresh baseline when it returns
			continue
		}
		p := c.prev[id]
		c.prev[id] = prev{in: r.In, out: r.Out, at: now, valid: true}
		if !p.valid {
			frame.V[id] = nil // first sample only establishes a baseline
			continue
		}
		dt := now.Sub(p.at).Seconds()
		if dt <= 0 {
			frame.V[id] = nil
			continue
		}
		rx, okRx := c.rate(p.in, r.In, dt, r.Width, id)
		tx, okTx := c.rate(p.out, r.Out, dt, r.Width, id)
		if !okRx || !okTx {
			frame.V[id] = nil
			continue
		}
		frame.V[id] = &store.Point{Rx: rx, Tx: tx}
	}
	c.mu.Unlock()

	c.ring.Push(frame)
	c.subs.Broadcast(frame)
}

// PollOnceForTest performs a single poll cycle. It exists so tests can drive
// the collector deterministically instead of waiting on the ticker.
func (c *Collector) PollOnceForTest() { c.once() }

// rate converts a counter delta into bits per second, rejecting resets.
func (c *Collector) rate(old, cur uint64, dt float64, width int, id string) (float64, bool) {
	var delta uint64
	switch {
	case cur >= old:
		delta = cur - old
	case width == 32:
		// A 32-bit counter can legitimately wrap; correct once.
		delta = (1 << 32) - (old & 0xffffffff) + (cur & 0xffffffff)
	default:
		// A 64-bit counter going backwards means a reset, not a wrap.
		c.resets++
		return 0, false
	}
	bps := float64(delta) * 8 / dt
	if mbps := c.speed[id]; mbps > 0 {
		if limit := float64(mbps) * 1e6 * float64(c.cfg.SpikeGuardX); bps > limit {
			// Implausible for the link: treat as a rekey or counter reset.
			c.resets++
			return 0, false
		}
	}
	return bps, true
}

// Health reports collector and source status for /healthz.
func (c *Collector) Health() map[string]any {
	c.mu.Lock()
	out := map[string]any{
		"last_poll_unix_ms": c.lastPoll.UnixMilli(),
		"last_poll_age_s":   time.Since(c.lastPoll).Seconds(),
		"poll_failures":     c.pollFails,
		"counter_resets":    c.resets,
		"last_error":        c.lastErr,
		"samples":           c.ring.Len(),
		"capacity":          c.ring.Cap(),
		"poll_interval_ms":  c.cfg.PollMS,
		"window_seconds":    c.cfg.WindowSec,
	}
	c.mu.Unlock()
	for k, v := range c.src.Health() {
		out[k] = v
	}
	return out
}

// Meta exposes discovery results.
func (c *Collector) Meta() map[string]Meta { return c.src.Meta() }

// SNMPSource polls a real FortiGate.
type SNMPSource struct {
	cfg    *config.Config
	cl     *snmp.Client
	vpnCol config.VPN

	mu       sync.Mutex
	ifIndex  map[string]int // ifName -> ifIndex
	tunIndex map[string]int // phase-2 name -> table index
	meta     map[string]Meta
	discAt   time.Time
	sysUp    uint64
	vpnBase  []uint32
}

// NewSNMPSource builds a live SNMP source.
func NewSNMPSource(cfg *config.Config, cl *snmp.Client) (*SNMPSource, error) {
	base, err := ber.ParseOIDString(cfg.VPNTable.BaseOID)
	if err != nil {
		return nil, err
	}
	return &SNMPSource{
		cfg: cfg, cl: cl, vpnCol: cfg.VPNTable, vpnBase: base,
		ifIndex:  map[string]int{},
		tunIndex: map[string]int{},
		meta:     map[string]Meta{},
	}, nil
}

// Close releases the SNMP socket.
func (s *SNMPSource) Close() error { return s.cl.Close() }

// Client exposes the underlying SNMP client so a reconfiguration can reuse the
// existing session when the device parameters have not changed.
func (s *SNMPSource) Client() *snmp.Client { return s.cl }

// Config returns the configuration this source was built for, so a reload can
// decide whether the SNMP session is still valid.
func (s *SNMPSource) Config() *config.Config { return s.cfg }

// Discover resolves ifName and phase-2 names to their table indexes.
func (s *SNMPSource) Discover() error {
	names, err := s.cl.Walk(oidIfName)
	if err != nil {
		return fmt.Errorf("walk ifName: %w", err)
	}
	alias, _ := s.cl.Walk(oidIfAlias)
	speed, _ := s.cl.Walk(oidIfHighSpeed)

	aliasByIdx := map[int]string{}
	for _, vb := range alias {
		aliasByIdx[lastArc(vb.OID)] = vb.Str()
	}
	speedByIdx := map[int]int{}
	for _, vb := range speed {
		speedByIdx[lastArc(vb.OID)] = int(vb.Uint())
	}

	s.mu.Lock()
	s.ifIndex = map[string]int{}
	for _, vb := range names {
		s.ifIndex[vb.Str()] = lastArc(vb.OID)
	}
	s.mu.Unlock()

	tun := map[string]int{}
	if s.cfg.VPNTable.Enabled && s.vpnCol.ColName != 0 {
		col := ber.Concat(s.vpnBase, s.vpnCol.ColName)
		rows, err := s.cl.Walk(col)
		if err != nil {
			log.Printf("walk VPN phase-2 names (%s): %v", ber.String(col), err)
		}
		for _, vb := range rows {
			tun[vb.Str()] = lastArc(vb.OID)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunIndex = tun
	s.discAt = time.Now()
	s.meta = map[string]Meta{}
	for _, f := range s.cfg.AllIfaces() {
		m := Meta{Speed: f.Speed}
		if f.Kind == "tunnel" {
			if idx, ok := tun[f.Match]; ok {
				m.Index, m.Resolved = idx, true
			}
		} else {
			if idx, ok := s.ifIndex[f.Match]; ok {
				m.Index, m.Resolved = idx, true
				m.Alias = aliasByIdx[idx]
				if sp := speedByIdx[idx]; sp > 0 && f.Speed == 0 {
					m.Speed = sp
				}
			}
		}
		if !m.Resolved {
			log.Printf("interface %q (%s) did not resolve to an index", f.ID, f.Match)
		}
		s.meta[f.ID] = m
	}
	return nil
}

// Poll fetches every configured counter in a single GetRequest.
func (s *SNMPSource) Poll() (map[string]Reading, error) {
	s.mu.Lock()
	ifIdx := copyMap(s.ifIndex)
	tunIdx := copyMap(s.tunIndex)
	s.mu.Unlock()

	var oids [][]uint32
	type slot struct {
		id     string
		kind   string
		base   int // position of the first varbind for this interface
		width  int
		status bool
	}
	var slots []slot

	if s.cfg.TrackSysUptime() {
		oids = append(oids, oidSysUpTime)
	}

	for _, f := range s.cfg.AllIfaces() {
		if f.Kind == "tunnel" {
			idx, ok := tunIdx[f.Match]
			if !ok {
				continue
			}
			hasStatus := s.vpnCol.ColStatus != 0
			slots = append(slots, slot{f.ID, f.Kind, len(oids), 32, hasStatus})
			oids = append(oids,
				ber.Concat(s.vpnBase, s.vpnCol.ColIn, uint32(idx)),
				ber.Concat(s.vpnBase, s.vpnCol.ColOut, uint32(idx)))
			if hasStatus {
				oids = append(oids, ber.Concat(s.vpnBase, s.vpnCol.ColStatus, uint32(idx)))
			}
			continue
		}
		idx, ok := ifIdx[f.Match]
		if !ok {
			continue
		}
		slots = append(slots, slot{f.ID, f.Kind, len(oids), 64, true})
		oids = append(oids,
			ber.Concat(oidIfHCIn, uint32(idx)),
			ber.Concat(oidIfHCOut, uint32(idx)),
			ber.Concat(oidIfOperState, uint32(idx)))
	}

	if len(slots) == 0 {
		return map[string]Reading{}, nil
	}

	vbs, err := s.cl.Get(oids)
	if err != nil {
		return nil, err
	}
	if len(vbs) != len(oids) {
		return nil, fmt.Errorf("snmp: asked for %d varbinds, got %d", len(oids), len(vbs))
	}

	out := make(map[string]Reading, len(slots))
	if s.cfg.TrackSysUptime() && vbs[0].Exists() {
		up := vbs[0].Uint()
		s.mu.Lock()
		if up < s.sysUp {
			log.Printf("sysUpTime went backwards (%d -> %d): agent restarted, counter baselines will be rebuilt", s.sysUp, up)
		}
		s.sysUp = up
		s.mu.Unlock()
	}

	for _, sl := range slots {
		in, outVB := vbs[sl.base], vbs[sl.base+1]
		r := Reading{Width: sl.width}
		if !in.Exists() || !outVB.Exists() {
			out[sl.id] = r
			continue
		}
		r.Present = true
		r.In, r.Out = in.Uint(), outVB.Uint()
		if !sl.status {
			r.Up = true // no status column detected: readable counters imply up
		} else {
			st := vbs[sl.base+2]
			if sl.kind == "tunnel" {
				r.Up = !st.Exists() || st.Int() == s.vpnCol.UpValue
			} else {
				r.Up = st.Exists() && st.Int() == 1 // ifOperStatus up(1)
			}
		}
		out[sl.id] = r
	}
	return out, nil
}

// Meta returns discovery results.
func (s *SNMPSource) Meta() map[string]Meta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Meta, len(s.meta))
	for k, v := range s.meta {
		out[k] = v
	}
	return out
}

// Health exposes SNMP transport counters.
func (s *SNMPSource) Health() map[string]any {
	st := s.cl.Stats()
	s.mu.Lock()
	age := time.Since(s.discAt).Seconds()
	nIf, nTun := len(s.ifIndex), len(s.tunIndex)
	s.mu.Unlock()
	return map[string]any{
		"mode":              "snmp",
		"snmp_requests":     st.Requests,
		"snmp_timeouts":     st.Timeouts,
		"snmp_auth_fails":   st.AuthFails,
		"snmp_resyncs":      st.Resyncs,
		"snmp_discoveries":  st.Rediscovers,
		"index_cache_age_s": age,
		"if_table_rows":     nIf,
		"vpn_table_rows":    nTun,
		"engine_id":         fmt.Sprintf("%x", s.cl.EngineID()),
	}
}

func lastArc(o []uint32) int {
	if len(o) == 0 {
		return -1
	}
	return int(o[len(o)-1])
}

func copyMap(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
