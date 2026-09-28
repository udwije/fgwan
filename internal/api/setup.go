package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"fgwan/internal/config"
	"fgwan/internal/discover"
	"fgwan/internal/secret"
	"fgwan/internal/snmp"
)

// Reloader is satisfied by the supervisor. It is an interface so the
// standalone wizard, which has no running collector, can pass nil.
type Reloader interface {
	Reload(*config.Config) error
	Generation() int
}

// SetupServer backs the discovery wizard: it tests credentials, walks the
// device and writes the resulting selection to disk.
//
// The same handler is mounted both by `fgwan -setup` (no collector running)
// and by the live collector, so reconfiguring a running deployment is the same
// workflow as first-time setup and does not require stopping monitoring.
type SetupServer struct {
	cfgPath      string
	store        *secret.Store
	reloader     Reloader
	loopbackOnly bool

	mu      sync.Mutex
	lastRes *discover.Result
}

// NewSetup builds the setup handler. reloader may be nil, in which case a save
// only writes the files and the operator restarts the collector themselves.
func NewSetup(cfgPath string, store *secret.Store, reloader Reloader, loopbackOnly bool) *SetupServer {
	return &SetupServer{cfgPath: cfgPath, store: store, reloader: reloader, loopbackOnly: loopbackOnly}
}

// Register attaches the setup endpoints to a mux.
func (s *SetupServer) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/setup/state", s.guard(s.handleState))
	mux.HandleFunc("/api/setup/discover", s.guard(s.handleDiscover))
	mux.HandleFunc("/api/setup/save", s.guard(s.handleSave))
}

// guard optionally restricts the setup endpoints to loopback callers.
//
// These endpoints accept SNMPv3 passphrases in a plain HTTP body, so on a
// collector that has been bound to a routable address they are refused unless
// the operator has explicitly opted in.
func (s *SetupServer) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.loopbackOnly && !isLoopback(r.RemoteAddr) {
			writeJSON(w, map[string]any{
				"ok": false,
				"error": "setup is restricted to connections from this machine; " +
					"open the dashboard on the collector host itself, or start fgwan with -setup-from-anywhere",
			})
			return
		}
		h(w, r)
	}
}

func isLoopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sessionReq carries the connection parameters entered in the wizard.
// Passphrases arrive over this request and are never written to the config.
type sessionReq struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Username  string `json:"username"`
	Level     string `json:"security_level"`
	Auth      string `json:"auth_protocol"`
	Priv      string `json:"priv_protocol"`
	AuthPass  string `json:"auth_pass"`
	PrivPass  string `json:"priv_pass"`
	Context   string `json:"context"`
	VPNBase   string `json:"vpn_base_oid"`
	UseStored bool   `json:"use_stored"`
	TimeoutMS int    `json:"timeout_ms"`
}

// client builds an SNMP client from the request, optionally reusing the
// credential already in the key store so a returning operator can re-walk the
// device without retyping the passphrases.
func (s *SetupServer) client(r sessionReq) (*snmp.Client, error) {
	if r.UseStored {
		c, err := s.store.Load()
		if err != nil {
			return nil, err
		}
		if r.Username == "" {
			r.Username = c.Username
		}
		r.AuthPass, r.PrivPass = c.AuthPass, c.PrivPass
	}
	level, err := snmp.ParseSecurityLevel(r.Level)
	if err != nil {
		return nil, err
	}
	auth, err := snmp.ParseAuthProto(r.Auth)
	if err != nil {
		return nil, err
	}
	priv, err := snmp.ParsePrivProto(r.Priv)
	if err != nil {
		return nil, err
	}
	if r.Port == 0 {
		r.Port = 161
	}
	if r.TimeoutMS == 0 {
		r.TimeoutMS = 3000
	}
	return snmp.New(snmp.Config{
		Host:     r.Host,
		Port:     r.Port,
		Timeout:  time.Duration(r.TimeoutMS) * time.Millisecond,
		Retries:  1,
		Username: r.Username,
		Level:    level,
		Auth:     auth,
		Priv:     priv,
		AuthPass: r.AuthPass,
		PrivPass: r.PrivPass,
		Context:  r.Context,
	})
}

func (s *SetupServer) handleState(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"credential_backend": secret.Describe(),
		"credential_path":    s.store.Path(),
		"credential_stored":  s.store.Exists(),
		"config_path":        s.cfgPath,
		"live":               s.reloader != nil,
	}
	if s.reloader != nil {
		out["generation"] = s.reloader.Generation()
	}
	if c, err := s.store.Load(); err == nil {
		out["username"] = c.Username // the username is not secret
	}
	if cfg, err := config.Load(s.cfgPath); err == nil {
		out["config"] = map[string]any{
			"host":             cfg.Device.Host,
			"port":             cfg.Device.Port,
			"security_level":   cfg.Device.V3.SecurityLevel,
			"auth_protocol":    cfg.Device.V3.AuthProtocol,
			"priv_protocol":    cfg.Device.V3.PrivProtocol,
			"vpn_base_oid":     cfg.VPNTable.BaseOID,
			"poll_interval_ms": cfg.PollMS,
			"window_seconds":   cfg.WindowSec,
			"zones":            cfg.Zones,
		}
	}
	writeJSON(w, out)
}

// handleDiscover tests the credentials and returns the full device inventory.
func (s *SetupServer) handleDiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req sessionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if req.Host == "" {
		writeJSON(w, map[string]any{"ok": false, "error": "device address is required"})
		return
	}

	cl, err := s.client(req)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer cl.Close()

	res, err := discover.Run(cl, req.VPNBase)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error(), "hint": hintFor(err)})
		return
	}
	s.mu.Lock()
	s.lastRes = res
	s.mu.Unlock()

	writeJSON(w, map[string]any{"ok": true, "result": res})
}

// hintFor turns a raw SNMP failure into the next thing to check.
func hintFor(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"):
		return "No response. Check that SNMP is enabled on the interface you are reaching, that this host is in the FortiGate trusted-host list, and that UDP/161 is permitted."
	case strings.Contains(msg, "digest mismatch"):
		return "The response failed authentication: the auth passphrase or auth protocol does not match the FortiGate user."
	case strings.Contains(msg, "decrypt"), strings.Contains(msg, "scoped pdu"):
		return "Authentication succeeded but decryption failed: check the privacy passphrase and protocol (AES128 vs AES256)."
	case strings.Contains(msg, "report"):
		return "The agent rejected the request: usually an unknown username or a security level the user is not configured for."
	}
	return ""
}

// saveReq is the wizard's final submission.
type saveReq struct {
	Session sessionReq    `json:"session"`
	Zones   []config.Zone `json:"zones"`
	VPN     config.VPN    `json:"vpn_table"`
	PollMS  int           `json:"poll_interval_ms"`
	WindowS int           `json:"window_seconds"`
	Apply   bool          `json:"apply"`
}

// handleSave writes the credential to the key store and the selection to the
// config file, then optionally applies it to the running collector.
func (s *SetupServer) handleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req saveReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if len(req.Zones) == 0 {
		writeJSON(w, map[string]any{"ok": false, "error": "assign at least one interface to a zone"})
		return
	}

	// Verify the parameters actually work before persisting anything. On a
	// live collector this matters twice over: a bad save would otherwise be
	// applied straight into the running poller.
	cl, err := s.client(req.Session)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if _, err := discover.Probe(cl); err != nil {
		cl.Close()
		writeJSON(w, map[string]any{"ok": false, "error": "verification failed: " + err.Error(), "hint": hintFor(err)})
		return
	}
	cl.Close()

	if !req.Session.UseStored {
		cred := secret.Credential{
			Username: req.Session.Username,
			AuthPass: req.Session.AuthPass,
			PrivPass: req.Session.PrivPass,
		}
		if err := s.store.Save(cred); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		log.Printf("credential stored via %s at %s", secret.Describe(), s.store.Path())
	}

	cfg := &config.Config{
		Device: config.Device{
			Host:      req.Session.Host,
			Port:      req.Session.Port,
			TimeoutMS: req.Session.TimeoutMS,
			Retries:   1,
			V3: config.V3{
				Username:      req.Session.Username,
				SecurityLevel: req.Session.Level,
				AuthProtocol:  req.Session.Auth,
				PrivProtocol:  req.Session.Priv,
				Context:       req.Session.Context,
			},
		},
		PollMS:    req.PollMS,
		WindowSec: req.WindowS,
		VPNTable:  req.VPN,
		Zones:     req.Zones,
	}
	if err := config.Save(s.cfgPath, cfg); err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	n := 0
	for _, z := range cfg.Zones {
		n += len(z.Interfaces)
	}
	log.Printf("configuration written to %s (%d zones, %d interfaces)", s.cfgPath, len(cfg.Zones), n)

	resp := map[string]any{
		"ok":          true,
		"config_path": s.cfgPath,
		"credential":  fmt.Sprintf("%s at %s", secret.Describe(), s.store.Path()),
		"zones":       len(cfg.Zones),
		"interfaces":  n,
	}

	switch {
	case s.reloader == nil:
		resp["applied"] = false
		resp["message"] = "Saved. Start fgwan (or the service) to begin collecting."
	case !req.Apply:
		resp["applied"] = false
		resp["message"] = "Saved to disk but not applied; the collector is still running the previous layout."
	default:
		// Re-read from disk rather than trusting the in-memory struct, so what
		// gets applied is exactly what a restart would load.
		fresh, err := config.Load(s.cfgPath)
		if err != nil {
			resp["applied"] = false
			resp["message"] = "Saved, but the written file did not reload cleanly: " + err.Error()
			break
		}
		if err := s.reloader.Reload(fresh); err != nil {
			resp["applied"] = false
			resp["message"] = "Saved, but applying it failed: " + err.Error() +
				" — the collector is still running the previous layout."
			break
		}
		resp["applied"] = true
		resp["generation"] = s.reloader.Generation()
		resp["message"] = "Saved and applied. The dashboard is already showing the new layout."
	}
	writeJSON(w, resp)
}
