// Package supervise owns the running collector and swaps it out when the
// configuration changes, without restarting the process.
//
// Reconfiguration is expected to be routine rather than exceptional: an
// operator adds a newly provisioned tunnel, moves an interface to a different
// zone, or corrects a declared capacity. Making that require a service restart
// would mean losing the accumulated window and a visible gap on a dashboard
// that people are watching, so the swap is done in place and carries over as
// much state as remains valid.
package supervise

import (
	"fmt"
	"log"
	"sync"

	"fgwan/internal/collect"
	"fgwan/internal/config"
	"fgwan/internal/snmp"
	"fgwan/internal/store"
)

// SourceFactory builds a data source for a configuration. The previous source
// is passed so implementations can reuse an existing SNMP session when the
// device parameters are unchanged; it is nil on first start.
type SourceFactory func(cfg *config.Config, prev collect.Source) (collect.Source, error)

// Supervisor holds the current generation of config, source, collector and
// ring, and can replace them atomically.
type Supervisor struct {
	factory SourceFactory
	hub     *collect.Hub

	mu    sync.RWMutex
	cfg   *config.Config
	src   collect.Source
	col   *collect.Collector
	ring  *store.Ring
	stop  chan struct{}
	gen   int
	simul bool
}

// New starts the first generation.
func New(cfg *config.Config, factory SourceFactory, sim bool) (*Supervisor, error) {
	s := &Supervisor{factory: factory, hub: collect.NewHub(), simul: sim}

	src, err := factory(cfg, nil)
	if err != nil {
		return nil, err
	}
	ring := store.New(cfg.Capacity())
	col := collect.New(cfg, src, ring, s.hub)

	stop := make(chan struct{})
	go col.Run(stop)

	s.cfg, s.src, s.col, s.ring, s.stop = cfg, src, col, ring, stop
	s.gen = 1
	return s, nil
}

// Reload swaps in a new configuration. On failure the previous generation is
// left running untouched, so a bad edit degrades to "nothing changed" rather
// than to an outage.
func (s *Supervisor) Reload(cfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldCfg, oldSrc, oldCol, oldRing, oldStop := s.cfg, s.src, s.col, s.ring, s.stop

	// Build the replacement before tearing anything down.
	newSrc, err := s.factory(cfg, oldSrc)
	if err != nil {
		return fmt.Errorf("reload: %w", err)
	}

	close(oldStop)

	// Only close the old source if the factory handed back a genuinely new
	// one; when the SNMP session is reused, closing it would kill the socket
	// the new source depends on.
	if newSrc != oldSrc {
		if err := oldSrc.Close(); err != nil {
			log.Printf("reload: closing previous source: %v", err)
		}
	}

	ring := oldRing.Rebuild(cfg.Capacity(), cfg.IfaceIDs())
	col := collect.New(cfg, newSrc, ring, s.hub)
	col.SeedBaselines(oldCol)

	stop := make(chan struct{})
	go col.Run(stop)

	s.cfg, s.src, s.col, s.ring, s.stop = cfg, newSrc, col, ring, stop
	s.gen++

	kept := 0
	for id := range cfg.IfaceIDs() {
		if oldCfg.IfaceIDs()[id] {
			kept++
		}
	}
	log.Printf("reloaded configuration (generation %d): %d zones, %d interfaces, %d kept their history",
		s.gen, len(cfg.Zones), len(cfg.AllIfaces()), kept)
	return nil
}

// Close stops the current generation.
func (s *Supervisor) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop != nil {
		close(s.stop)
		s.stop = nil
	}
	if s.src != nil {
		return s.src.Close()
	}
	return nil
}

// Config returns the configuration currently in force.
func (s *Supervisor) Config() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Ring returns the current ring buffer.
func (s *Supervisor) Ring() *store.Ring {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ring
}

// Collector returns the current collector.
func (s *Supervisor) Collector() *collect.Collector {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.col
}

// Hub returns the broadcast hub, which survives reloads so connected browsers
// are never disconnected by a reconfiguration.
func (s *Supervisor) Hub() *collect.Hub { return s.hub }

// Generation reports how many configurations have been loaded. The dashboard
// watches this to notice that it should refetch its interface list.
func (s *Supervisor) Generation() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.gen
}

// Simulated reports whether this is a simulator run.
func (s *Supervisor) Simulated() bool { return s.simul }

// SNMPFactory returns a SourceFactory that builds live SNMP sources, reusing
// the previous session when the device parameters are unchanged.
func SNMPFactory(dial func(*config.Config) (*snmp.Client, error)) SourceFactory {
	return func(cfg *config.Config, prev collect.Source) (collect.Source, error) {
		if ps, ok := prev.(*collect.SNMPSource); ok {
			if old := ps.Config(); old != nil && !cfg.SessionChanged(old) {
				// Same device and credentials: keep the discovered engine ID
				// and time synchronisation instead of re-handshaking.
				src, err := collect.NewSNMPSource(cfg, ps.Client())
				if err != nil {
					return nil, err
				}
				return src, nil
			}
		}
		cl, err := dial(cfg)
		if err != nil {
			return nil, err
		}
		return collect.NewSNMPSource(cfg, cl)
	}
}

// SimFactory returns a SourceFactory producing synthetic data.
func SimFactory() SourceFactory {
	return func(cfg *config.Config, _ collect.Source) (collect.Source, error) {
		return collect.NewSimSource(cfg), nil
	}
}
