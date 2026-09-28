package ber

import (
	"encoding/hex"
	"testing"
)

func TestOIDEncoding(t *testing.T) {
	cases := []struct {
		oid  string
		want string
	}{
		{"1.3.6.1.2.1.1.3.0", "2b06010201010300"},
		{"1.3.6.1.2.1.31.1.1.1.6", "2b060102011f01010106"},
		{"1.3.6.1.4.1.12356.101.12.2.2.1", "2b06010401e044650c020201"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(OIDContent(MustParseOIDString(c.oid)))
		if got != c.want {
			t.Errorf("%s encoded as %s, want %s", c.oid, got, c.want)
		}
		if round := String(ParseOID(OIDContent(MustParseOIDString(c.oid)))); round != c.oid {
			t.Errorf("%s round-tripped as %s", c.oid, round)
		}
	}
}

func TestIntegerEncoding(t *testing.T) {
	cases := []struct {
		v    int64
		want string
	}{
		{0, "00"}, {127, "7f"}, {128, "0080"}, {255, "00ff"},
		{-1, "ff"}, {-128, "80"}, {-129, "ff7f"}, {65507, "00ffe3"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(intContent(c.v))
		if got != c.want {
			t.Errorf("intContent(%d) = %s, want %s", c.v, got, c.want)
		}
		if back := ParseInt(intContent(c.v)); back != c.v {
			t.Errorf("ParseInt round trip for %d gave %d", c.v, back)
		}
	}
}

func TestLengthEncoding(t *testing.T) {
	for _, c := range []struct {
		n    int
		want string
	}{{0, "00"}, {127, "7f"}, {128, "8180"}, {300, "82012c"}} {
		if got := hex.EncodeToString(encodeLen(c.n)); got != c.want {
			t.Errorf("encodeLen(%d) = %s, want %s", c.n, got, c.want)
		}
	}
}

func TestNextRoundTrip(t *testing.T) {
	msg := Seq(Int(3), OctetStr([]byte("hello")), OID(MustParseOIDString("1.3.6.1")))
	outer, rest, err := Expect(msg, TagSequence)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes: %d", len(rest))
	}
	e, body, err := Expect(outer.Content, TagInteger)
	if err != nil || ParseInt(e.Content) != 3 {
		t.Fatalf("version: %v %v", e, err)
	}
	e, body, err = Expect(body, TagOctetStr)
	if err != nil || string(e.Content) != "hello" {
		t.Fatalf("octet string: %v %v", e, err)
	}
	e, _, err = Expect(body, TagOID)
	if err != nil || String(ParseOID(e.Content)) != "1.3.6.1" {
		t.Fatalf("oid: %v %v", e, err)
	}
}

func TestHasPrefix(t *testing.T) {
	root := MustParseOIDString("1.3.6.1.2.1.31.1.1.1.6")
	if !HasPrefix(Concat(root, 12), root) {
		t.Error("child should match prefix")
	}
	if HasPrefix(root, MustParseOIDString("1.3.6.1.2.1.31.1.1.1.10")) {
		t.Error("sibling should not match prefix")
	}
}
