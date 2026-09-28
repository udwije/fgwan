// Command fgwan polls FortiGate WAN and IPsec interfaces over SNMPv3 and
// serves a live one-hour bandwidth dashboard.
//
// Modes:
//
//	fgwan                     run the collector and dashboard in the foreground
//	fgwan -service            run under the Windows Service Control Manager
//	fgwan -setup              browser wizard, standalone (no collector running)
//	fgwan -setup-console      terminal wizard, no browser required
//	fgwan -set-credentials    store SNMPv3 credentials from the console
//	fgwan -discover           print the interface inventory and exit
//	fgwan -walk OID           dump an OID subtree and exit
//	fgwan -sim                run with synthetic data, no SNMP traffic
//
// In collector mode the wizard is also served at /setup.html, so the interface
// selection can be changed at any time without stopping monitoring.
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"fgwan/internal/api"
	"fgwan/internal/ber"
	"fgwan/internal/config"
	"fgwan/internal/discover"
	"fgwan/internal/logfile"
	"fgwan/internal/secret"
	"fgwan/internal/snmp"
	"fgwan/internal/supervise"
	"fgwan/internal/term"
	"fgwan/internal/winsvc"
)

//go:embed web
var webFS embed.FS

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

// serviceName must match the name used when the service is registered.
const serviceName = "fgwan"

func main() {
	var (
		cfgPath  = flag.String("config", defaultConfigPath(), "path to the configuration file")
		credPath = flag.String("credentials", "", "path to the encrypted credential blob (default: alongside the config)")
		listen   = flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
		sim      = flag.Bool("sim", false, "run with synthetic data instead of polling the firewall")
		service  = flag.Bool("service", false, "run under the Windows Service Control Manager")
		logPath  = flag.String("log", "", "write logs to this file instead of the console (default in service mode)")
		logMB    = flag.Int("log-max-mb", 8, "rotate the log file once it exceeds this many megabytes")
		logKeep  = flag.Int("log-keep", 3, "how many rotated log files to retain")
		setup    = flag.Bool("setup", false, "run the browser wizard standalone, without starting the collector")
		setupCon = flag.Bool("setup-console", false, "run setup in the terminal, no browser required")
		noSetup  = flag.Bool("no-setup", false, "do not serve the reconfiguration wizard from the collector")
		anySetup = flag.Bool("setup-from-anywhere", false, "allow reconfiguration from non-loopback clients (not recommended)")
		setCred  = flag.Bool("set-credentials", false, "store SNMPv3 credentials from the console and exit")
		delCred  = flag.Bool("clear-credentials", false, "delete the stored credential and exit")
		disco    = flag.Bool("discover", false, "print the device interface inventory and exit")
		walk     = flag.String("walk", "", "walk an OID subtree, print it and exit")
		showVer  = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("fgwan ")

	if *showVer {
		fmt.Printf("fgwan %s\n", version)
		return
	}

	// A service has no console, so its diagnostics must go to a file before
	// anything else can fail. Foreground runs keep using stderr unless asked.
	if closeLog := setupLogging(*logPath, *service, *cfgPath, *logMB, *logKeep); closeLog != nil {
		defer closeLog()
	}

	credStore, err := secret.NewStore(*credPath)
	if err != nil {
		log.Fatal(err)
	}

	switch {
	case *setCred:
		if err := setCredentials(credStore); err != nil {
			log.Fatal(err)
		}
		return
	case *delCred:
		if err := credStore.Delete(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Stored credential deleted.")
		return
	case *setupCon:
		// Checked before -setup so the terminal path wins if both are given:
		// it is the one that works everywhere.
		if err := consoleSetup(*cfgPath, credStore); err != nil {
			log.Fatal(err)
		}
		return
	case *setup:
		if err := runSetup(*cfgPath, credStore, *listen, !*anySetup); err != nil {
			log.Fatal(err)
		}
		return
	}

	if *disco || *walk != "" {
		if err := runInspect(*cfgPath, credStore, *disco, *walk); err != nil {
			log.Fatal(err)
		}
		return
	}

	// ---- collector mode ----
	opts := collectorOpts{
		cfgPath:  *cfgPath,
		listen:   *listen,
		sim:      *sim,
		noSetup:  *noSetup,
		anySetup: *anySetup,
		store:    credStore,
	}

	if *service {
		// Under the SCM: hand over control and let it decide when we stop.
		err := winsvc.Run(serviceName, func(stop <-chan struct{}) {
			runCollector(opts, stop)
		})
		if errors.Is(err, winsvc.ErrNotService) {
			log.Print("-service was given but this process was not started by the service manager; " +
				"running in the foreground instead")
			runCollector(opts, consoleStop())
			return
		}
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	runCollector(opts, consoleStop())
}

// collectorOpts carries everything runCollector needs, so the same body serves
// both the foreground and the service paths.
type collectorOpts struct {
	cfgPath  string
	listen   string
	sim      bool
	noSetup  bool
	anySetup bool
	store    *secret.Store
}

// consoleStop returns a channel closed on Ctrl+C or SIGTERM.
func consoleStop() <-chan struct{} {
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		close(stop)
	}()
	return stop
}

// runCollector starts the poller and the HTTP server, and returns once stop is
// closed and everything has been shut down.
func runCollector(o collectorOpts, stop <-chan struct{}) {
	if !config.Exists(o.cfgPath) {
		log.Fatalf("no usable configuration at %s\n\nRun setup first:\n    fgwan -setup-console", o.cfgPath)
	}
	cfg, err := config.Load(o.cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	var factory supervise.SourceFactory
	if o.sim {
		log.Printf("SIMULATOR MODE: no SNMP traffic will be sent to %s", cfg.Device.Host)
		factory = supervise.SimFactory()
	} else {
		factory = supervise.SNMPFactory(func(c *config.Config) (*snmp.Client, error) {
			return newClient(c, o.store)
		})
	}

	sup, err := supervise.New(cfg, factory, o.sim)
	if err != nil {
		log.Fatal(err)
	}
	defer sup.Close()

	var setupSrv *api.SetupServer
	if o.noSetup {
		log.Print("reconfiguration wizard disabled (-no-setup)")
	} else {
		setupSrv = api.NewSetup(o.cfgPath, o.store, sup, !o.anySetup)
		if o.anySetup {
			log.Print("WARNING: reconfiguration is allowed from any client; " +
				"the wizard accepts passphrases over plain HTTP, so put a TLS-terminating proxy in front")
		}
	}

	ui, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Handler:           api.New(sup, ui, setupSrv).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Bind before reporting readiness, so a port clash fails loudly instead of
	// leaving a "running" service with no listener.
	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		log.Fatalf("cannot listen on %s: %v", o.listen, err)
	}

	go func() {
		log.Printf("fgwan %s listening on http://%s  (device %s, poll %dms, window %ds, %d samples)",
			version, o.listen, cfg.Device.Host, cfg.PollMS, cfg.WindowSec, cfg.Capacity())
		if setupSrv != nil {
			log.Printf("reconfigure at http://%s/setup.html (no restart needed)", o.listen)
		}
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("http server stopped: %v", err)
		}
	}()

	// SIGHUP re-reads the configuration file, for operators who would rather
	// edit JSON or drive this from a deployment tool than use the wizard.
	hup := make(chan os.Signal, 1)
	notifyReload(hup)
	go func() {
		for range hup {
			fresh, err := config.Load(o.cfgPath)
			if err != nil {
				log.Printf("reload on signal: %v (keeping the running configuration)", err)
				continue
			}
			if err := sup.Reload(fresh); err != nil {
				log.Printf("reload on signal: %v (keeping the running configuration)", err)
			}
		}
	}()

	<-stop
	log.Print("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// setupLogging points the logger at a rotating file when running as a service,
// or whenever -log is given. It returns a closer, or nil if nothing was opened.
func setupLogging(path string, service bool, cfgPath string, maxMB, keep int) func() {
	if path == "" {
		if !service {
			return nil // foreground: stderr is fine
		}
		path = filepath.Join(filepath.Dir(cfgPath), "logs", "fgwan.log")
	}
	w, err := logfile.New(path, int64(maxMB)<<20, keep)
	if err != nil {
		// Losing the log file is not a reason to refuse to start; the service
		// is still useful, it is just harder to diagnose.
		log.Printf("cannot open log file %s: %v (continuing with stderr)", path, err)
		return nil
	}
	if service {
		log.SetOutput(w)
	} else {
		log.SetOutput(io.MultiWriter(os.Stderr, w))
	}
	log.Printf("fgwan %s starting, logging to %s", version, path)
	return func() { w.Close() }
}

// defaultConfigPath puts the config next to the credential blob, which on
// Windows is %ProgramData%\fgwan.
func defaultConfigPath() string {
	d, err := secret.DefaultDir()
	if err != nil {
		return "config.json"
	}
	return filepath.Join(d, "config.json")
}

// runSetup serves the browser wizard with no collector behind it. This is one
// of the two first-run paths; once a configuration exists, the collector
// serves the same wizard itself.
func runSetup(cfgPath string, st *secret.Store, listen string, loopbackOnly bool) error {
	ui, err := fs.Sub(webFS, "web")
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              listen,
		Handler:           api.New(nil, ui, api.NewSetup(cfgPath, st, nil, loopbackOnly)).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("setup wizard on http://%s/setup.html", listen)
	log.Printf("configuration  %s", cfgPath)
	log.Printf("credentials    %s (%s)", st.Path(), secret.Describe())
	log.Print("press Ctrl+C when finished")

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-consoleStop()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

// setCredentials prompts for SNMPv3 credentials and stores them encrypted.
func setCredentials(st *secret.Store) error {
	fmt.Printf("Storing SNMPv3 credentials using %s\n", secret.Describe())
	fmt.Printf("Destination: %s\n\n", st.Path())

	user, err := term.ReadLine("SNMPv3 username: ")
	if err != nil {
		return err
	}
	if user == "" {
		return fmt.Errorf("username is required")
	}
	authPass, err := term.ReadSecretConfirmed("Auth passphrase")
	if err != nil {
		return err
	}
	privPass, err := term.ReadSecretConfirmed("Priv passphrase")
	if err != nil {
		return err
	}
	if err := st.Save(secret.Credential{Username: user, AuthPass: authPass, PrivPass: privPass}); err != nil {
		return err
	}
	fmt.Printf("\nStored. The passphrases are encrypted at rest and are never written to the config file.\n")
	return nil
}

// newClient builds the SNMP client from the config plus the stored credential.
// Environment variables override the key store, which keeps ad-hoc debugging
// possible without rewriting the stored credential.
func newClient(cfg *config.Config, st *secret.Store) (*snmp.Client, error) {
	level, err := snmp.ParseSecurityLevel(cfg.Device.V3.SecurityLevel)
	if err != nil {
		return nil, err
	}
	auth, err := snmp.ParseAuthProto(cfg.Device.V3.AuthProtocol)
	if err != nil {
		return nil, err
	}
	priv, err := snmp.ParsePrivProto(cfg.Device.V3.PrivProtocol)
	if err != nil {
		return nil, err
	}

	cred, loadErr := st.Load()
	username := cfg.Device.V3.Username
	if cred.Username != "" {
		username = cred.Username
	}
	authPass, privPass := cred.AuthPass, cred.PrivPass
	if v := os.Getenv("FGT_AUTH_PASS"); v != "" {
		authPass = v
	}
	if v := os.Getenv("FGT_PRIV_PASS"); v != "" {
		privPass = v
	}
	if level != snmp.NoAuthNoPriv && authPass == "" {
		if loadErr != nil {
			return nil, fmt.Errorf("%w\n\nRun:  fgwan -set-credentials   (or: fgwan -setup-console)", loadErr)
		}
		return nil, fmt.Errorf("no auth passphrase available for security level %s", cfg.Device.V3.SecurityLevel)
	}
	if level == snmp.AuthPriv && privPass == "" {
		return nil, fmt.Errorf("no priv passphrase available for security level authPriv")
	}

	cl, err := snmp.New(snmp.Config{
		Host:     cfg.Device.Host,
		Port:     cfg.Device.Port,
		Timeout:  cfg.Timeout(),
		Retries:  cfg.Device.Retries,
		Username: username,
		Level:    level,
		Auth:     auth,
		Priv:     priv,
		AuthPass: authPass,
		PrivPass: privPass,
		Context:  cfg.Device.V3.Context,
	})
	if err != nil {
		return nil, err
	}
	log.Printf("snmpv3 %s user=%q auth=%s priv=%s -> %s:%d (credential via %s)",
		cfg.Device.V3.SecurityLevel, username, auth, priv,
		cfg.Device.Host, cfg.Device.Port, secret.Describe())
	return cl, nil
}

// runInspect implements -discover and -walk.
func runInspect(cfgPath string, st *secret.Store, doDiscover bool, walkOID string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("%w\n\nRun setup first:  fgwan -setup-console", err)
	}
	cl, err := newClient(cfg, st)
	if err != nil {
		return err
	}
	defer cl.Close()

	if walkOID != "" {
		root, err := ber.ParseOIDString(walkOID)
		if err != nil {
			return err
		}
		vbs, err := cl.Walk(root)
		if err != nil && len(vbs) == 0 {
			return err
		}
		if err != nil {
			log.Printf("walk ended early: %v", err)
		}
		for _, vb := range vbs {
			fmt.Printf("%-44s %s\n", ber.String(vb.OID), render(vb))
		}
		fmt.Printf("\n%d rows\n", len(vbs))
		return nil
	}

	res, err := discover.Run(cl, cfg.VPNTable.BaseOID)
	if err != nil {
		return err
	}
	fmt.Printf("Device   %s\n", res.Identity.SysName)
	fmt.Printf("Descr    %s\n", truncate(res.Identity.SysDescr, 90))
	fmt.Printf("EngineID %s\n\n", res.Identity.EngineID)

	monitored := cfg.IfaceIDs()

	fmt.Printf("%-6s %-18s %-10s %-6s %-8s %-5s %s\n",
		"INDEX", "NAME", "TYPE", "STATE", "SPEED", "HC64", "ALIAS / NOTE")
	for _, f := range res.Interfaces {
		state := "down"
		if f.Up {
			state = "up"
		}
		hc := "no"
		if f.HasHC {
			hc = "yes"
		}
		mark := " "
		switch {
		case monitored["if_"+slug(f.Name)]:
			mark = "#" // already monitored
		case f.Suggested:
			mark = "*"
		}
		note := f.Alias
		if note == "" {
			note = f.Reason
		}
		fmt.Printf("%s%-5d %-18s %-10s %-6s %-8s %-5s %s\n",
			mark, f.Index, truncate(f.Name, 18), f.TypeName, state,
			speedLabel(f.SpeedMbps), hc, truncate(note, 40))
	}
	fmt.Printf("\n(# = currently monitored, * = suggested)\n")

	fmt.Printf("\nIPsec tunnel table %s\n", res.VPN.BaseOID)
	fmt.Printf("  columns: name=%d in=%d out=%d status=%d  confident=%v\n",
		res.VPN.Name, res.VPN.In, res.VPN.Out, res.VPN.Status, res.VPN.Confident)
	if res.VPN.Notes != "" {
		fmt.Printf("  %s\n", res.VPN.Notes)
	}
	for _, t := range res.Tunnels {
		state := "down"
		if t.Up {
			state = "up"
		}
		mark := " "
		if monitored["vpn_"+slug(t.Name)] {
			mark = "#"
		}
		fmt.Printf("%s %-28s idx=%-5d %-5s in=%-14d out=%d\n", mark, t.Name, t.Index, state, t.In, t.Out)
	}
	for _, w := range res.Warnings {
		fmt.Printf("\nwarning: %s\n", w)
	}
	fmt.Printf("\nTo change what is monitored: open http://<listen>/setup.html on the\n" +
		"running collector, or stop it and run `fgwan -setup-console`.\n")
	return nil
}

// slug mirrors the id scheme the wizards use, so -discover can mark the rows
// that are already being monitored.
func slug(s string) string {
	var b strings.Builder
	lastUnderscore := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastUnderscore = false
		case !lastUnderscore:
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "x"
	}
	return out
}

func speedLabel(mbps int) string {
	switch {
	case mbps == 0:
		return "-"
	case mbps >= 1000:
		return fmt.Sprintf("%dG", mbps/1000)
	default:
		return fmt.Sprintf("%dM", mbps)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "\u2026"
}

func render(vb snmp.VarBind) string {
	switch vb.Tag {
	case ber.TagOctetStr:
		if printable(vb.Raw) {
			return fmt.Sprintf("STRING: %s", vb.Str())
		}
		return fmt.Sprintf("HEX: %x", vb.Raw)
	case ber.TagInteger:
		return fmt.Sprintf("INTEGER: %d", vb.Int())
	case ber.TagCounter32:
		return fmt.Sprintf("Counter32: %d", vb.Uint())
	case ber.TagCounter64:
		return fmt.Sprintf("Counter64: %d", vb.Uint())
	case ber.TagGauge32:
		return fmt.Sprintf("Gauge32: %d", vb.Uint())
	case ber.TagTimeTicks:
		return fmt.Sprintf("Timeticks: %d", vb.Uint())
	case ber.TagOID:
		return fmt.Sprintf("OID: %s", ber.String(ber.ParseOID(vb.Raw)))
	case ber.TagIPAddress:
		parts := make([]string, len(vb.Raw))
		for i, b := range vb.Raw {
			parts[i] = fmt.Sprint(b)
		}
		return "IpAddress: " + strings.Join(parts, ".")
	case ber.TagNoSuchObject:
		return "No Such Object"
	case ber.TagNoSuchInstance:
		return "No Such Instance"
	}
	return fmt.Sprintf("tag 0x%02x: %x", vb.Tag, vb.Raw)
}

func printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
