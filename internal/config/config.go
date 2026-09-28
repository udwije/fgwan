// Package config loads, validates and writes the fgwan configuration.
//
// The configuration file holds only non-secret settings. SNMPv3 passphrases
// are never stored here; they live in the platform key store (see
// internal/secret).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config is the top-level configuration document.
type Config struct {
	Device      Device `json:"device"`
	PollMS      int    `json:"poll_interval_ms"`
	WindowSec   int    `json:"window_seconds"`
	VPNTable    VPN    `json:"vpn_table"`
	Zones       []Zone `json:"zones"`
	RediscoverS int    `json:"rediscover_seconds"`
	SpikeGuardX int    `json:"spike_guard_multiplier"`
	EnableSysUp *bool  `json:"track_sysuptime,omitempty"`
}

// Device describes the FortiGate and its non-secret SNMPv3 parameters.
type Device struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	TimeoutMS int    `json:"timeout_ms"`
	Retries   int    `json:"retries"`
	V3        V3     `json:"v3"`
}

// V3 holds the non-secret USM settings. The username is recorded here for
// display; the authoritative copy travels with the stored credential.
type V3 struct {
	Username      string `json:"username"`
	SecurityLevel string `json:"security_level"`
	AuthProtocol  string `json:"auth_protocol"`
	PrivProtocol  string `json:"priv_protocol"`
	Context       string `json:"context"`
}

// VPN describes the Fortinet IPsec tunnel table layout. Column numbers differ
// between FortiOS branches and are normally filled in by the setup wizard.
type VPN struct {
	Enabled   bool   `json:"enabled"`
	BaseOID   string `json:"base_oid"`
	ColName   uint32 `json:"col_phase2_name"`
	ColIn     uint32 `json:"col_in_octets"`
	ColOut    uint32 `json:"col_out_octets"`
	ColStatus uint32 `json:"col_status"`
	UpValue   int64  `json:"status_up_value"`
}

// Zone is a free-form presentation grouping: one zone becomes one chart on the
// dashboard. Any interface kind may appear in any zone, and an installation
// may define as many zones as it likes.
type Zone struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Subtitle   string  `json:"subtitle"`
	Interfaces []Iface `json:"interfaces"`
}

// Iface is a single monitored interface or tunnel.
type Iface struct {
	ID    string `json:"id"`
	Match string `json:"match"` // ifName for phys, phase-2 name for tunnel
	Label string `json:"label"`
	Kind  string `json:"kind"` // "phys" | "tunnel"
	Speed int    `json:"speed_mbps"`
	Color string `json:"color"`
}

// Load reads, defaults and validates a configuration file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var c Config
	if err := json.NewDecoder(newCommentStripper(b)).Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save writes the configuration atomically. A partially written config would
// leave the collector unable to restart, so the temp-file-and-rename dance
// matters more here than it looks.
func Save(path string, c *Config) error {
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	header := "// Written by the fgwan setup wizard.\n" +
		"// SNMPv3 passphrases are NOT stored here - they are held in the platform\n" +
		"// key store. Reconfigure from the dashboard (Configure) or run `fgwan -setup`.\n"
	b = append([]byte(header), b...)
	b = append(b, '\n')

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// Exists reports whether a usable configuration file is present.
func Exists(path string) bool {
	_, err := Load(path)
	return err == nil
}

func (c *Config) applyDefaults() {
	if c.Device.Port == 0 {
		c.Device.Port = 161
	}
	if c.Device.TimeoutMS == 0 {
		c.Device.TimeoutMS = 2000
	}
	if c.Device.Retries == 0 {
		c.Device.Retries = 1
	}
	if c.PollMS == 0 {
		c.PollMS = 5000
	}
	if c.WindowSec == 0 {
		c.WindowSec = 3600
	}
	if c.RediscoverS == 0 {
		c.RediscoverS = 300
	}
	if c.SpikeGuardX == 0 {
		c.SpikeGuardX = 10
	}
	if c.VPNTable.BaseOID == "" {
		c.VPNTable.BaseOID = "1.3.6.1.4.1.12356.101.12.2.2.1"
	}
	if c.VPNTable.UpValue == 0 {
		c.VPNTable.UpValue = 2
	}
	// A zone holding any tunnel needs the tunnel table walked.
	for _, z := range c.Zones {
		for _, f := range z.Interfaces {
			if f.Kind == "tunnel" {
				c.VPNTable.Enabled = true
			}
		}
	}
}

func (c *Config) validate() error {
	if c.Device.Host == "" {
		return fmt.Errorf("config: device.host is required")
	}
	if len(c.Zones) == 0 {
		return fmt.Errorf("config: at least one zone is required")
	}
	seenZone := map[string]bool{}
	seenIface := map[string]bool{}
	total := 0
	for _, z := range c.Zones {
		if z.ID == "" {
			return fmt.Errorf("config: zone is missing an id")
		}
		if seenZone[z.ID] {
			return fmt.Errorf("config: duplicate zone id %q", z.ID)
		}
		seenZone[z.ID] = true
		for _, f := range z.Interfaces {
			if f.ID == "" || f.Match == "" {
				return fmt.Errorf("config: interface in zone %q needs both id and match", z.ID)
			}
			if seenIface[f.ID] {
				return fmt.Errorf("config: interface id %q appears more than once; "+
					"an interface may belong to only one zone", f.ID)
			}
			seenIface[f.ID] = true
			if f.Kind != "phys" && f.Kind != "tunnel" {
				return fmt.Errorf("config: interface %q has kind %q (want phys or tunnel)", f.ID, f.Kind)
			}
			total++
		}
	}
	if total == 0 {
		return fmt.Errorf("config: no interfaces selected in any zone")
	}
	return nil
}

// PollInterval returns the configured poll period.
func (c *Config) PollInterval() time.Duration { return time.Duration(c.PollMS) * time.Millisecond }

// Timeout returns the configured SNMP timeout.
func (c *Config) Timeout() time.Duration {
	return time.Duration(c.Device.TimeoutMS) * time.Millisecond
}

// Capacity returns the number of samples retained in the ring buffer.
func (c *Config) Capacity() int {
	n := c.WindowSec * 1000 / c.PollMS
	if n < 2 {
		n = 2
	}
	return n
}

// AllIfaces flattens every configured interface across zones.
func (c *Config) AllIfaces() []Iface {
	var out []Iface
	for _, z := range c.Zones {
		out = append(out, z.Interfaces...)
	}
	return out
}

// IfaceIDs returns the set of configured interface ids, used when carrying
// history across a reconfiguration.
func (c *Config) IfaceIDs() map[string]bool {
	out := map[string]bool{}
	for _, f := range c.AllIfaces() {
		out[f.ID] = true
	}
	return out
}

// TrackSysUptime reports whether sysUpTime-based reset detection is enabled.
func (c *Config) TrackSysUptime() bool {
	return c.EnableSysUp == nil || *c.EnableSysUp
}

// SessionChanged reports whether the SNMP session parameters differ, i.e.
// whether a reconfiguration needs a brand new SNMP client rather than just a
// new interface selection.
func (c *Config) SessionChanged(o *Config) bool {
	return c.Device.Host != o.Device.Host ||
		c.Device.Port != o.Device.Port ||
		c.Device.TimeoutMS != o.Device.TimeoutMS ||
		c.Device.Retries != o.Device.Retries ||
		c.Device.V3 != o.Device.V3
}
