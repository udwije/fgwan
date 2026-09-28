package discover

import "testing"

func TestIfTypeName(t *testing.T) {
	for typ, want := range map[int]string{6: "ethernet", 131: "tunnel", 24: "loopback", 161: "lag"} {
		if got := ifTypeName(typ); got != want {
			t.Errorf("ifTypeName(%d) = %s, want %s", typ, got, want)
		}
	}
}

func TestAnnotateSuggestsPhysicalUpInterfaces(t *testing.T) {
	cases := []struct {
		in        Interface
		suggested bool
	}{
		{Interface{Name: "port1", Type: 6, Up: true, HasHC: true}, true},
		{Interface{Name: "port9", Type: 6, Up: false, HasHC: true}, false},
		{Interface{Name: "VPN-ACPL", Type: 131, Up: true, HasHC: false}, false},
		{Interface{Name: "lo", Type: 24, Up: true, HasHC: true}, false},
		{Interface{Name: "ssl.root", Type: 53, Up: true, HasHC: true}, false},
		{Interface{Name: "fortilink", Type: 6, Up: true, HasHC: true}, false},
		{Interface{Name: "agg1", Type: 161, Up: true, HasHC: true}, true},
	}
	for _, c := range cases {
		f := c.in
		annotate(&f)
		if f.Suggested != c.suggested {
			t.Errorf("%s: suggested = %v, want %v (reason %q)", f.Name, f.Suggested, c.suggested, f.Reason)
		}
		if f.Reason == "" {
			t.Errorf("%s: annotate left an empty reason", f.Name)
		}
	}
}

func TestPrintable(t *testing.T) {
	if !printable([]byte("VPN-ACPL")) {
		t.Error("ASCII name should be printable")
	}
	if printable([]byte{0x00, 0x01, 0xff}) {
		t.Error("binary should not be printable")
	}
}
