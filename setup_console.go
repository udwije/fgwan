package main

// Console setup: the same job as the browser wizard, driven entirely from a
// terminal.
//
// The browser wizard is the nicer experience, but it is unusable on a server
// that has no browser — Server Core has none at all, and Desktop Experience
// installs ship with IE Enhanced Security Configuration blocking localhost by
// default. Exposing the wizard to the network instead is not an acceptable
// substitute, because it accepts SNMPv3 passphrases in a plain HTTP body.
//
// So this mode exists for headless deployment: prompt, walk, choose, write.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"fgwan/internal/config"
	"fgwan/internal/discover"
	"fgwan/internal/secret"
	"fgwan/internal/snmp"
	"fgwan/internal/term"
)

// consoleSetup runs the whole first-time configuration from the terminal and
// writes both the credential and the configuration file.
func consoleSetup(cfgPath string, st *secret.Store) error {
	fmt.Println()
	fmt.Println("  fgwan setup")
	fmt.Println("  ===========")
	fmt.Println()
	fmt.Printf("  Configuration will be written to : %s\n", cfgPath)
	fmt.Printf("  Credentials will be stored in    : %s\n", st.Path())
	fmt.Printf("  Credential protection            : %s\n", secret.Describe())
	fmt.Println()

	existing, _ := config.Load(cfgPath)
	if existing != nil {
		fmt.Printf("  A configuration already exists (device %s, %d zone(s)).\n",
			existing.Device.Host, len(existing.Zones))
		ok, err := askYesNo("  Replace it?", false)
		if err != nil || !ok {
			fmt.Println("  Left unchanged.")
			return err
		}
		fmt.Println()
	}

	// ---- 1. session parameters -------------------------------------------
	fmt.Println("  1. Device and SNMPv3 parameters")
	fmt.Println("  -------------------------------")

	host, err := askRequired("  Device address", valOr(existing, func(c *config.Config) string {
		return c.Device.Host
	}))
	if err != nil {
		return err
	}
	port, err := askInt("  SNMP port", 161)
	if err != nil {
		return err
	}
	user, err := askRequired("  SNMPv3 username", firstNonEmpty(valOr(existing, func(c *config.Config) string {
		return c.Device.V3.Username
	}), "fgt-monitor"))
	if err != nil {
		return err
	}
	level, err := askChoice("  Security level", []string{"authPriv", "authNoPriv", "noAuthNoPriv"}, 0)
	if err != nil {
		return err
	}

	authProto, privProto := "", ""
	if level != "noAuthNoPriv" {
		if authProto, err = askChoice("  Auth protocol", []string{"SHA256", "SHA1", "SHA512", "MD5"}, 0); err != nil {
			return err
		}
	}
	if level == "authPriv" {
		if privProto, err = askChoice("  Priv protocol", []string{"AES128", "AES256"}, 0); err != nil {
			return err
		}
		// Caught later by the USM layer too, but failing here is far clearer
		// than a key-length error after the passphrases have been typed.
		if privProto == "AES256" && (authProto == "SHA1" || authProto == "MD5") {
			return fmt.Errorf("AES256 needs a 32-byte localized key, which %s cannot produce; "+
				"pair it with SHA256 or longer", authProto)
		}
	}

	// ---- 2. credentials ---------------------------------------------------
	var authPass, privPass string
	reuse := false
	if st.Exists() {
		fmt.Println()
		if cred, err := st.Load(); err == nil {
			fmt.Printf("  A credential for %q is already stored on this machine.\n", cred.Username)
			if reuse, err = askYesNo("  Reuse it?", true); err != nil {
				return err
			}
			if reuse {
				authPass, privPass = cred.AuthPass, cred.PrivPass
				if user == "" {
					user = cred.Username
				}
			}
		}
	}
	if !reuse && level != "noAuthNoPriv" {
		fmt.Println()
		fmt.Println("  2. Passphrases (nothing is echoed as you type)")
		fmt.Println("  ---------------------------------------------")
		if authPass, err = term.ReadSecretConfirmed("  Auth passphrase"); err != nil {
			return err
		}
		if level == "authPriv" {
			if privPass, err = term.ReadSecretConfirmed("  Priv passphrase"); err != nil {
				return err
			}
		}
	}

	// ---- 3. walk ----------------------------------------------------------
	fmt.Println()
	fmt.Printf("  3. Connecting to %s:%d ...\n", host, port)

	secLevel, err := snmp.ParseSecurityLevel(level)
	if err != nil {
		return err
	}
	auth, err := snmp.ParseAuthProto(authProto)
	if err != nil {
		return err
	}
	priv, err := snmp.ParsePrivProto(privProto)
	if err != nil {
		return err
	}

	cl, err := snmp.New(snmp.Config{
		Host: host, Port: port, Timeout: 4 * time.Second, Retries: 1,
		Username: user, Level: secLevel, Auth: auth, Priv: priv,
		AuthPass: authPass, PrivPass: privPass,
	})
	if err != nil {
		return err
	}
	defer cl.Close()

	id, err := discover.Probe(cl)
	if err != nil {
		return fmt.Errorf("%w\n\n  %s", err, consoleHint(err))
	}
	fmt.Printf("     connected: %s\n", id.SysName)
	if d := strings.TrimSpace(id.SysDescr); d != "" {
		fmt.Printf("     %s\n", truncate(d, 72))
	}

	fmt.Println("     walking the interface table ...")
	res, err := discover.Run(cl, "")
	if err != nil {
		return err
	}

	// ---- 4. choose --------------------------------------------------------
	rows := buildConsoleRows(res)
	if len(rows) == 0 {
		return fmt.Errorf("the device reported nothing that can be monitored")
	}

	zones, err := chooseZones(rows)
	if err != nil {
		return err
	}
	if len(zones) == 0 {
		return fmt.Errorf("no interfaces were selected")
	}

	// ---- 5. write ---------------------------------------------------------
	pollMS, err := askInt("\n  Poll interval in milliseconds", 5000)
	if err != nil {
		return err
	}
	windowS, err := askInt("  Window in seconds", 3600)
	if err != nil {
		return err
	}

	cfg := &config.Config{
		Device: config.Device{
			Host: host, Port: port, TimeoutMS: 2000, Retries: 1,
			V3: config.V3{
				Username:      user,
				SecurityLevel: level,
				AuthProtocol:  authProto,
				PrivProtocol:  privProto,
			},
		},
		PollMS:    pollMS,
		WindowSec: windowS,
		VPNTable: config.VPN{
			BaseOID:   res.VPN.BaseOID,
			ColName:   res.VPN.Name,
			ColIn:     res.VPN.In,
			ColOut:    res.VPN.Out,
			ColStatus: res.VPN.Status,
			UpValue:   res.VPN.UpValue,
		},
		Zones: zones,
	}

	fmt.Println()
	fmt.Println("  5. Review")
	fmt.Println("  ---------")
	total := 0
	for _, z := range cfg.Zones {
		names := make([]string, 0, len(z.Interfaces))
		for _, f := range z.Interfaces {
			names = append(names, f.Match)
			total++
		}
		fmt.Printf("     %-20s %s\n", z.Name, strings.Join(names, ", "))
	}
	fmt.Printf("\n     %d zone(s), %d interface(s), polled every %d ms\n",
		len(cfg.Zones), total, cfg.PollMS)

	ok, err := askYesNo("\n  Save this configuration?", true)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Println("  Nothing was written.")
		return nil
	}

	if !reuse && level != "noAuthNoPriv" {
		if err := st.Save(secret.Credential{
			Username: user, AuthPass: authPass, PrivPass: privPass,
		}); err != nil {
			return err
		}
		fmt.Printf("  Credential stored  : %s\n", st.Path())
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		return err
	}
	fmt.Printf("  Configuration saved: %s\n", cfgPath)
	fmt.Println()
	fmt.Println("  Next: register the service")
	fmt.Println("      .\\Manage-Fgwan.ps1 -Action Install")
	fmt.Println()
	return nil
}

// consoleRow is one selectable line of the inventory.
type consoleRow struct {
	key       string
	kind      string
	match     string
	index     int
	note      string
	typeName  string
	up        bool
	hasCtr    bool
	speed     int
	suggested bool
}

// buildConsoleRows flattens the walk into selectable rows, physical first.
func buildConsoleRows(res *discover.Result) []consoleRow {
	var rows []consoleRow
	for _, f := range res.Interfaces {
		// Interfaces with no usable counters cannot be measured, so offering
		// them would only invite a selection that silently never plots.
		if !f.HasHC {
			continue
		}
		note := f.Alias
		if note == "" {
			note = f.Reason
		}
		rows = append(rows, consoleRow{
			key: "if_" + slug(f.Name), kind: "phys", match: f.Name, index: f.Index,
			note: note, typeName: f.TypeName, up: f.Up, hasCtr: true,
			speed: f.SpeedMbps, suggested: f.Suggested,
		})
	}
	for _, t := range res.Tunnels {
		rows = append(rows, consoleRow{
			key: "vpn_" + slug(t.Name), kind: "tunnel", match: t.Name, index: t.Index,
			note: "ipsec phase-2", typeName: "ipsec", up: t.Up, hasCtr: true,
			suggested: t.Up,
		})
	}
	return rows
}

// printRows renders the inventory with selection numbers.
func printRows(rows []consoleRow, taken map[int]string) {
	fmt.Println()
	fmt.Printf("     %-4s %-3s %-20s %-10s %-6s %-8s %s\n",
		"#", "", "NAME", "TYPE", "STATE", "SPEED", "NOTE")
	fmt.Printf("     %s\n", strings.Repeat("-", 76))
	for i, r := range rows {
		state := "down"
		if r.up {
			state = "up"
		}
		speed := "-"
		if r.speed >= 1000 {
			speed = fmt.Sprintf("%dG", r.speed/1000)
		} else if r.speed > 0 {
			speed = fmt.Sprintf("%dM", r.speed)
		}
		mark := " "
		if r.suggested {
			mark = "*"
		}
		note := r.note
		if z, ok := taken[i]; ok {
			note = "-> " + z
			mark = "+"
		}
		fmt.Printf("     %-4d %-3s %-20s %-10s %-6s %-8s %s\n",
			i+1, mark, truncate(r.match, 20), r.typeName, state, speed, truncate(note, 24))
	}
	fmt.Println()
	fmt.Println("     * = suggested    + = already assigned")
}

// chooseZones walks the operator through building one or more zones.
func chooseZones(rows []consoleRow) ([]config.Zone, error) {
	taken := map[int]string{} // row index -> zone name
	var zones []config.Zone

	fmt.Println()
	fmt.Println("  4. Choose what to monitor")
	fmt.Println("  -------------------------")
	fmt.Println("     A zone is one chart on the dashboard. Any interface may go in any")
	fmt.Println("     zone, and physical interfaces and tunnels can be mixed freely.")

	for {
		printRows(rows, taken)

		zoneName, err := askRequired(fmt.Sprintf("  Name for zone %d", len(zones)+1), defaultZoneName(len(zones)))
		if err != nil {
			return nil, err
		}

		fmt.Println("     Select by number: ranges and lists are fine, e.g.  1-3,7,9")
		fmt.Println("     Enter 'suggested' to take everything marked *, or blank to skip.")
		sel, err := term.ReadLine("  Interfaces: ")
		if err != nil {
			return nil, err
		}

		var picked []int
		if strings.EqualFold(strings.TrimSpace(sel), "suggested") {
			for i, r := range rows {
				if r.suggested {
					if _, used := taken[i]; !used {
						picked = append(picked, i)
					}
				}
			}
		} else if strings.TrimSpace(sel) != "" {
			if picked, err = parseSelection(sel, len(rows)); err != nil {
				fmt.Printf("     %v\n", err)
				continue
			}
		}

		if len(picked) == 0 {
			fmt.Println("     Nothing selected for this zone.")
		} else {
			zone := config.Zone{
				ID:   fmt.Sprintf("z%d", len(zones)+1),
				Name: zoneName,
			}
			for _, i := range picked {
				if z, used := taken[i]; used {
					fmt.Printf("     %s is already in %q; skipped.\n", rows[i].match, z)
					continue
				}
				r := rows[i]
				speed := r.speed
				// SNMP reports no capacity for a tunnel, so a utilisation bar
				// is only possible if the operator supplies one.
				if r.kind == "tunnel" {
					if v, err := askInt(fmt.Sprintf("     Capacity in Mbit/s for %s (0 = unknown)", r.match), 0); err == nil {
						speed = v
					}
				}
				zone.Interfaces = append(zone.Interfaces, config.Iface{
					ID: r.key, Match: r.match, Label: r.note, Kind: r.kind,
					Speed: speed, Color: consolePalette[len(zone.Interfaces)%len(consolePalette)],
				})
				taken[i] = zoneName
			}
			if len(zone.Interfaces) > 0 {
				zones = append(zones, zone)
				fmt.Printf("     Zone %q: %d interface(s).\n", zoneName, len(zone.Interfaces))
			}
		}

		more, err := askYesNo("  Add another zone?", false)
		if err != nil {
			return nil, err
		}
		if !more {
			break
		}
	}
	return zones, nil
}

// consolePalette mirrors the dashboard palette so console-built configurations
// look the same as wizard-built ones.
var consolePalette = []string{
	"#4FC3F7", "#FFB300", "#AB47BC", "#66BB6A",
	"#EC407A", "#9CCC65", "#5C6BC0", "#FF7043",
}

func defaultZoneName(n int) string {
	switch n {
	case 0:
		return "WAN"
	case 1:
		return "IPsec"
	}
	return fmt.Sprintf("Zone %d", n+1)
}

// parseSelection turns "1-3,7,9" into zero-based indexes, rejecting anything
// outside the printed range rather than silently ignoring it.
func parseSelection(s string, max int) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi := 0, 0
		if a, b, ok := strings.Cut(part, "-"); ok {
			var err error
			if lo, err = strconv.Atoi(strings.TrimSpace(a)); err != nil {
				return nil, fmt.Errorf("%q is not a number or range", part)
			}
			if hi, err = strconv.Atoi(strings.TrimSpace(b)); err != nil {
				return nil, fmt.Errorf("%q is not a number or range", part)
			}
		} else {
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("%q is not a number or range", part)
			}
			lo, hi = n, n
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		if lo < 1 || hi > max {
			return nil, fmt.Errorf("%q is outside 1-%d", part, max)
		}
		for n := lo; n <= hi; n++ {
			if !seen[n-1] {
				seen[n-1] = true
				out = append(out, n-1)
			}
		}
	}
	sort.Ints(out)
	return out, nil
}

// consoleHint mirrors the browser wizard's diagnosis for terminal users.
func consoleHint(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"):
		return "No response. On a newly deployed server this is usually the FortiGate\n" +
			"  trusted-host list: it must include THIS machine's address. Also check\n" +
			"  that SNMP is enabled on the interface being reached and UDP/161 is open."
	case strings.Contains(msg, "digest mismatch"):
		return "The response failed authentication: the auth passphrase or auth protocol\n" +
			"  does not match the FortiGate user."
	case strings.Contains(msg, "decrypt"), strings.Contains(msg, "scoped pdu"):
		return "Authentication succeeded but decryption failed: check the privacy\n" +
			"  passphrase and whether the user is AES128 or AES256."
	case strings.Contains(msg, "report"):
		return "The agent rejected the request: usually an unknown username, or a\n" +
			"  security level the user is not configured for."
	}
	return "Check the device address, credentials and network path."
}

// ---- small prompt helpers ------------------------------------------------

func askRequired(prompt, def string) (string, error) {
	for {
		p := prompt
		if def != "" {
			p += " [" + def + "]"
		}
		v, err := term.ReadLine(p + ": ")
		if err != nil {
			return "", err
		}
		v = strings.TrimSpace(v)
		if v == "" {
			v = def
		}
		if v != "" {
			return v, nil
		}
		fmt.Println("     Required.")
	}
}

func askInt(prompt string, def int) (int, error) {
	v, err := term.ReadLine(fmt.Sprintf("%s [%d]: ", prompt, def))
	if err != nil {
		return 0, err
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		fmt.Printf("     %q is not a number; using %d.\n", v, def)
		return def, nil
	}
	return n, nil
}

func askYesNo(prompt string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	v, err := term.ReadLine(fmt.Sprintf("%s [%s]: ", prompt, hint))
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return def, nil
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	}
	return def, nil
}

func askChoice(prompt string, options []string, def int) (string, error) {
	fmt.Printf("%s:\n", prompt)
	for i, o := range options {
		mark := " "
		if i == def {
			mark = "*"
		}
		fmt.Printf("     %s %d) %s\n", mark, i+1, o)
	}
	n, err := askInt("     choose", def+1)
	if err != nil {
		return "", err
	}
	if n < 1 || n > len(options) {
		n = def + 1
	}
	return options[n-1], nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// valOr reads a field from a possibly-nil configuration.
func valOr(c *config.Config, f func(*config.Config) string) string {
	if c == nil {
		return ""
	}
	return f(c)
}
