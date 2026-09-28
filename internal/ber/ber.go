// Package ber implements the minimal subset of ASN.1 BER needed for SNMP.
package ber

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ASN.1 / SNMP tags.
const (
	TagInteger  byte = 0x02
	TagOctetStr byte = 0x04
	TagNull     byte = 0x05
	TagOID      byte = 0x06
	TagSequence byte = 0x30

	TagIPAddress byte = 0x40
	TagCounter32 byte = 0x41
	TagGauge32   byte = 0x42
	TagTimeTicks byte = 0x43
	TagOpaque    byte = 0x44
	TagCounter64 byte = 0x46

	TagNoSuchObject   byte = 0x80
	TagNoSuchInstance byte = 0x81
	TagEndOfMibView   byte = 0x82

	PDUGet      byte = 0xA0
	PDUGetNext  byte = 0xA1
	PDUResponse byte = 0xA2
	PDUGetBulk  byte = 0xA5
	PDUReport   byte = 0xA8
)

func encodeLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

// TLV wraps content in a tag/length/value triple.
func TLV(tag byte, content []byte) []byte {
	out := make([]byte, 0, len(content)+5)
	out = append(out, tag)
	out = append(out, encodeLen(len(content))...)
	out = append(out, content...)
	return out
}

func intContent(v int64) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	neg := v < 0
	u := uint64(v)
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(u >> uint((7-i)*8))
	}
	i := 0
	for i < 7 {
		if !neg && b[i] == 0x00 && b[i+1]&0x80 == 0 {
			i++
			continue
		}
		if neg && b[i] == 0xff && b[i+1]&0x80 != 0 {
			i++
			continue
		}
		break
	}
	return b[i:]
}

// Int encodes a signed INTEGER.
func Int(v int64) []byte { return TLV(TagInteger, intContent(v)) }

// OctetStr encodes an OCTET STRING.
func OctetStr(b []byte) []byte { return TLV(TagOctetStr, b) }

// Null encodes a NULL value.
func Null() []byte { return []byte{TagNull, 0x00} }

// Seq encodes a SEQUENCE from already-encoded members.
func Seq(parts ...[]byte) []byte {
	var c []byte
	for _, p := range parts {
		c = append(c, p...)
	}
	return TLV(TagSequence, c)
}

func base128(v uint32) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	var tmp []byte
	for v > 0 {
		tmp = append([]byte{byte(v & 0x7f)}, tmp...)
		v >>= 7
	}
	for i := 0; i < len(tmp)-1; i++ {
		tmp[i] |= 0x80
	}
	return tmp
}

// OIDContent encodes an OID body (no tag/length).
func OIDContent(o []uint32) []byte {
	if len(o) < 2 {
		return nil
	}
	out := base128(o[0]*40 + o[1])
	for _, v := range o[2:] {
		out = append(out, base128(v)...)
	}
	return out
}

// OID encodes a full OBJECT IDENTIFIER TLV.
func OID(o []uint32) []byte { return TLV(TagOID, OIDContent(o)) }

// Elem is a decoded tag/value pair.
type Elem struct {
	Tag     byte
	Content []byte
}

// Next decodes one TLV from b, returning the element and the remaining bytes.
func Next(b []byte) (Elem, []byte, error) {
	if len(b) < 2 {
		return Elem{}, nil, errors.New("ber: truncated header")
	}
	tag := b[0]
	l := int(b[1])
	off := 2
	if l&0x80 != 0 {
		n := int(l & 0x7f)
		if n == 0 || n > 4 {
			return Elem{}, nil, fmt.Errorf("ber: unsupported length form (%d octets)", n)
		}
		if len(b) < 2+n {
			return Elem{}, nil, errors.New("ber: truncated length")
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[2+i])
		}
		off = 2 + n
	}
	if len(b) < off+l {
		return Elem{}, nil, errors.New("ber: truncated content")
	}
	return Elem{Tag: tag, Content: b[off : off+l]}, b[off+l:], nil
}

// Expect decodes one TLV and asserts its tag.
func Expect(b []byte, tag byte) (Elem, []byte, error) {
	e, rest, err := Next(b)
	if err != nil {
		return e, rest, err
	}
	if e.Tag != tag {
		return e, rest, fmt.Errorf("ber: expected tag 0x%02x, got 0x%02x", tag, e.Tag)
	}
	return e, rest, nil
}

// ParseInt decodes a two's-complement INTEGER body.
func ParseInt(c []byte) int64 {
	if len(c) == 0 {
		return 0
	}
	var v int64
	if c[0]&0x80 != 0 {
		v = -1
	}
	for _, x := range c {
		v = v<<8 | int64(x)
	}
	return v
}

// ParseUint decodes an unsigned big-endian body (Counter32/64, Gauge32).
func ParseUint(c []byte) uint64 {
	var v uint64
	for _, x := range c {
		v = v<<8 | uint64(x)
	}
	return v
}

// ParseOID decodes an OID body.
func ParseOID(c []byte) []uint32 {
	var out []uint32
	if len(c) == 0 {
		return out
	}
	out = append(out, uint32(c[0])/40, uint32(c[0])%40)
	var v uint32
	for _, x := range c[1:] {
		v = v<<7 | uint32(x&0x7f)
		if x&0x80 == 0 {
			out = append(out, v)
			v = 0
		}
	}
	return out
}

// MustParseOIDString parses dotted-decimal notation, panicking on malformed input.
func MustParseOIDString(s string) []uint32 {
	o, err := ParseOIDString(s)
	if err != nil {
		panic(err)
	}
	return o
}

// ParseOIDString parses dotted-decimal notation such as "1.3.6.1.2.1.1.3.0".
func ParseOIDString(s string) ([]uint32, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), ".")
	if s == "" {
		return nil, errors.New("ber: empty OID")
	}
	parts := strings.Split(s, ".")
	out := make([]uint32, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("ber: bad OID arc %q: %w", p, err)
		}
		out = append(out, uint32(v))
	}
	if len(out) < 2 {
		return nil, errors.New("ber: OID too short")
	}
	return out, nil
}

// String renders an OID in dotted-decimal notation.
func String(o []uint32) string {
	parts := make([]string, len(o))
	for i, v := range o {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, ".")
}

// HasPrefix reports whether oid sits under prefix.
func HasPrefix(oid, prefix []uint32) bool {
	if len(oid) < len(prefix) {
		return false
	}
	for i, v := range prefix {
		if oid[i] != v {
			return false
		}
	}
	return true
}

// Concat appends arcs to a base OID without aliasing the base slice.
func Concat(base []uint32, arcs ...uint32) []uint32 {
	out := make([]uint32, 0, len(base)+len(arcs))
	out = append(out, base...)
	return append(out, arcs...)
}
