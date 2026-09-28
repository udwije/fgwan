// Package api serves the JSON API, the WebSocket stream and the embedded UI.
package api

import (
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"time"

	"fgwan/internal/supervise"
)

// Server wires the supervisor to HTTP. Every request reads the current
// generation through the supervisor, so a reconfiguration is picked up without
// rebuilding the handler.
type Server struct {
	sup   *supervise.Supervisor
	ui    fs.FS
	setup *SetupServer
}

// New builds the HTTP server. Either sup or setup may be nil: the standalone
// wizard has no supervisor, and a locked-down collector has no setup.
func New(sup *supervise.Supervisor, ui fs.FS, setup *SetupServer) *Server {
	return &Server{sup: sup, ui: ui, setup: setup}
}

// Handler returns the configured mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	if s.setup != nil {
		s.setup.Register(mux)
	}
	if s.sup != nil {
		mux.HandleFunc("/api/interfaces", s.handleInterfaces)
		mux.HandleFunc("/api/series", s.handleSeries)
		mux.HandleFunc("/ws", s.handleWS)
	}
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.Handle("/", http.FileServer(http.FS(s.ui)))
	return mux
}

type ifaceOut struct {
	ID       string `json:"id"`
	Zone     string `json:"zone"`
	Name     string `json:"name"`
	Label    string `json:"label"`
	Kind     string `json:"kind"`
	Speed    int    `json:"speed_mbps"`
	Color    string `json:"color"`
	Index    int    `json:"if_index"`
	Alias    string `json:"alias"`
	Resolved bool   `json:"resolved"`
}

type zoneOut struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Subtitle   string     `json:"subtitle"`
	Interfaces []ifaceOut `json:"interfaces"`
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	cfg := s.sup.Config()
	meta := s.sup.Collector().Meta()

	zones := make([]zoneOut, 0, len(cfg.Zones))
	for _, z := range cfg.Zones {
		zo := zoneOut{ID: z.ID, Name: z.Name, Subtitle: z.Subtitle}
		for _, f := range z.Interfaces {
			m := meta[f.ID]
			speed := f.Speed
			if speed == 0 {
				speed = m.Speed
			}
			zo.Interfaces = append(zo.Interfaces, ifaceOut{
				ID: f.ID, Zone: z.ID, Name: f.Match, Label: f.Label, Kind: f.Kind,
				Speed: speed, Color: f.Color,
				Index: m.Index, Alias: m.Alias, Resolved: m.Resolved,
			})
		}
		zones = append(zones, zo)
	}
	writeJSON(w, map[string]any{
		"device":           cfg.Device.Host,
		"simulator":        s.sup.Simulated(),
		"poll_interval_ms": cfg.PollMS,
		"window_seconds":   cfg.WindowSec,
		"security":         cfg.Device.V3.SecurityLevel,
		"auth_protocol":    cfg.Device.V3.AuthProtocol,
		"priv_protocol":    cfg.Device.V3.PrivProtocol,
		"generation":       s.sup.Generation(),
		"setup_enabled":    s.setup != nil,
		"zones":            zones,
	})
}

func (s *Server) handleSeries(w http.ResponseWriter, r *http.Request) {
	cfg := s.sup.Config()
	ring := s.sup.Ring()
	max := ring.Cap()
	if q := r.URL.Query().Get("window"); q != "" {
		if secs, err := strconv.Atoi(q); err == nil && secs > 0 {
			if n := secs * 1000 / cfg.PollMS; n > 0 && n < max {
				max = n
			}
		}
	}
	writeJSON(w, map[string]any{
		"generation": s.sup.Generation(),
		"frames":     ring.Snapshot(max),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if s.sup == nil {
		writeJSON(w, map[string]any{"mode": "setup", "collector": false})
		return
	}
	h := s.sup.Collector().Health()
	h["ws_clients"] = s.sup.Hub().Count()
	h["generation"] = s.sup.Generation()
	writeJSON(w, h)
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrade(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer conn.Close()

	// The hub outlives any single generation, so a reconfiguration never drops
	// a connected browser.
	ch, cancel := s.sup.Hub().Subscribe()
	defer cancel()

	done := make(chan struct{})
	go conn.readLoop(done)

	// Send the newest frame immediately so a fresh tab is not blank until the
	// next tick; the client has already backfilled the window over /api/series.
	if f, ok := s.sup.Ring().Last(); ok {
		if b, err := json.Marshal(f); err == nil {
			if err := conn.WriteText(b); err != nil {
				return
			}
		}
	}

	keepalive := time.NewTicker(30 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-done:
			return
		case <-keepalive.C:
			if err := conn.writeFrame(0x9, nil); err != nil {
				return
			}
		case f, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(f)
			if err != nil {
				log.Printf("ws: marshal: %v", err)
				continue
			}
			if err := conn.WriteText(b); err != nil {
				return
			}
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("api: encode: %v", err)
	}
}
