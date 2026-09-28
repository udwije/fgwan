package config

import "testing"

// Zones are an arbitrary presentation grouping: any interface kind may appear
// in any zone, and an installation may define as many zones as it likes.
func TestValidateAcceptsMixedAndManyZones(t *testing.T) {
	c := &Config{
		Device: Device{Host: "10.0.0.1"},
		Zones: []Zone{
			{ID: "z1", Name: "Colombo", Interfaces: []Iface{
				{ID: "a", Match: "port1", Kind: "phys"},
				{ID: "b", Match: "VPN-DR", Kind: "tunnel"},
			}},
			{ID: "z2", Name: "Kandy", Interfaces: []Iface{
				{ID: "c", Match: "VPN-BR1", Kind: "tunnel"},
			}},
			{ID: "z3", Name: "Spare", Interfaces: []Iface{
				{ID: "d", Match: "port9", Kind: "phys"},
			}},
		},
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		t.Fatalf("mixed-kind, multi-zone config rejected: %v", err)
	}
	if !c.VPNTable.Enabled {
		t.Error("a tunnel in any zone should enable the VPN table walk")
	}
	if n := len(c.AllIfaces()); n != 4 {
		t.Errorf("AllIfaces = %d, want 4", n)
	}
}

func TestValidateRejectsInterfaceInTwoZones(t *testing.T) {
	c := &Config{
		Device: Device{Host: "10.0.0.1"},
		Zones: []Zone{
			{ID: "z1", Interfaces: []Iface{{ID: "dup", Match: "port1", Kind: "phys"}}},
			{ID: "z2", Interfaces: []Iface{{ID: "dup", Match: "port1", Kind: "phys"}}},
		},
	}
	c.applyDefaults()
	if err := c.validate(); err == nil {
		t.Fatal("an interface in two zones must be rejected, or zone totals double-count")
	}
}

func TestValidateRejectsEmptySelection(t *testing.T) {
	c := &Config{
		Device: Device{Host: "10.0.0.1"},
		Zones:  []Zone{{ID: "z1", Name: "empty"}},
	}
	c.applyDefaults()
	if err := c.validate(); err == nil {
		t.Fatal("a config with zones but no interfaces must be rejected")
	}
}

func TestCapacity(t *testing.T) {
	c := &Config{Device: Device{Host: "h"}, PollMS: 5000, WindowSec: 3600}
	if got := c.Capacity(); got != 720 {
		t.Errorf("Capacity = %d, want 720", got)
	}
}

// A reload only needs a fresh SNMP session when the device or credentials
// change; editing the interface selection must not force a re-handshake.
func TestSessionChanged(t *testing.T) {
	base := func() *Config {
		return &Config{
			Device: Device{Host: "10.0.0.1", Port: 161, TimeoutMS: 2000, Retries: 1,
				V3: V3{Username: "u", SecurityLevel: "authPriv",
					AuthProtocol: "SHA256", PrivProtocol: "AES128"}},
			Zones: []Zone{{ID: "z", Interfaces: []Iface{{ID: "a", Match: "p1", Kind: "phys"}}}},
		}
	}
	a, b := base(), base()
	b.Zones[0].Interfaces = append(b.Zones[0].Interfaces, Iface{ID: "b", Match: "p2", Kind: "phys"})
	if a.SessionChanged(b) {
		t.Error("changing only the interface selection must not invalidate the session")
	}

	c := base()
	c.Device.V3.Username = "other"
	if !a.SessionChanged(c) {
		t.Error("a different username must invalidate the session")
	}

	d := base()
	d.Device.Host = "10.0.0.2"
	if !a.SessionChanged(d) {
		t.Error("a different host must invalidate the session")
	}
}

func TestIfaceIDs(t *testing.T) {
	c := &Config{
		Device: Device{Host: "h"},
		Zones: []Zone{
			{ID: "z1", Interfaces: []Iface{{ID: "a", Match: "p1", Kind: "phys"}}},
			{ID: "z2", Interfaces: []Iface{{ID: "b", Match: "p2", Kind: "phys"}}},
		},
	}
	ids := c.IfaceIDs()
	if !ids["a"] || !ids["b"] || len(ids) != 2 {
		t.Errorf("IfaceIDs = %v", ids)
	}
}
