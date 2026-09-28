package snmp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"fgwan/internal/ber"
)

// SecurityLevel is the USM security level.
type SecurityLevel int

// Security levels.
const (
	NoAuthNoPriv SecurityLevel = iota
	AuthNoPriv
	AuthPriv
)

// ParseSecurityLevel maps a config string onto a SecurityLevel.
func ParseSecurityLevel(s string) (SecurityLevel, error) {
	switch normalize(s) {
	case "noauthnopriv":
		return NoAuthNoPriv, nil
	case "authnopriv":
		return AuthNoPriv, nil
	case "authpriv":
		return AuthPriv, nil
	}
	return NoAuthNoPriv, fmt.Errorf("snmp: unknown security level %q", s)
}

// Config describes an SNMPv3 session.
type Config struct {
	Host     string
	Port     int
	Timeout  time.Duration
	Retries  int
	Username string
	Level    SecurityLevel
	Auth     AuthProto
	Priv     PrivProto
	AuthPass string
	PrivPass string
	Context  string
}

// VarBind is a decoded variable binding.
type VarBind struct {
	OID []uint32
	Tag byte
	Raw []byte
}

// Uint returns the value as an unsigned integer.
func (v VarBind) Uint() uint64 { return ber.ParseUint(v.Raw) }

// Int returns the value as a signed integer.
func (v VarBind) Int() int64 { return ber.ParseInt(v.Raw) }

// Str returns the value as a string.
func (v VarBind) Str() string { return string(v.Raw) }

// Exists reports whether the agent actually returned a value.
func (v VarBind) Exists() bool {
	switch v.Tag {
	case ber.TagNoSuchObject, ber.TagNoSuchInstance, ber.TagEndOfMibView, ber.TagNull:
		return false
	}
	return true
}

// Stats are cumulative transport counters, surfaced on /healthz.
type Stats struct {
	Requests    uint64
	Timeouts    uint64
	AuthFails   uint64
	Resyncs     uint64
	Rediscovers uint64
}

// Client is an SNMPv3 client for a single agent. It is safe for concurrent use,
// though requests are serialized on one UDP socket.
type Client struct {
	cfg  Config
	addr *net.UDPAddr

	mu       sync.Mutex
	conn     *net.UDPConn
	engineID []byte
	boots    int32
	timeBase int32
	timeSync time.Time
	authKey  []byte
	privKey  []byte
	reqID    int32
	msgID    int32
	salt     uint64
	stats    Stats
}

// New dials (unconnected) and prepares a client. Discovery is deferred to the
// first request so construction never blocks on the network.
func New(cfg Config) (*Client, error) {
	if cfg.Port == 0 {
		cfg.Port = 161
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port)))
	if err != nil {
		return nil, fmt.Errorf("snmp: resolve %s: %w", cfg.Host, err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("snmp: dial %s: %w", addr, err)
	}
	c := &Client{cfg: cfg, addr: addr, conn: conn}
	c.reqID = int32(randUint32() & 0x7fffffff)
	c.msgID = int32(randUint32() & 0x7fffffff)
	c.salt = uint64(randUint32())<<32 | uint64(randUint32())
	return c, nil
}

// Close releases the socket.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Stats returns a snapshot of transport counters.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// EngineID returns the discovered authoritative engine ID.
func (c *Client) EngineID() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.engineID...)
}

func randUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}

func (c *Client) nextReqID() int32 {
	c.reqID++
	if c.reqID <= 0 {
		c.reqID = 1
	}
	return c.reqID
}

func (c *Client) nextMsgID() int32 {
	c.msgID++
	if c.msgID <= 0 {
		c.msgID = 1
	}
	return c.msgID
}

func (c *Client) nextSalt() []byte {
	c.salt++
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, c.salt)
	return b
}

// engineTimeNow projects engine time forward from the last sync.
func (c *Client) engineTimeNow() int32 {
	if c.timeSync.IsZero() {
		return c.timeBase
	}
	return c.timeBase + int32(time.Since(c.timeSync)/time.Second)
}

// ---------------------------------------------------------------------------
// message construction
// ---------------------------------------------------------------------------

type pduData struct {
	Type     byte
	ReqID    int32
	NonRep   int64 // error-status on non-bulk PDUs
	MaxRep   int64 // error-index on non-bulk PDUs
	VarBinds [][]uint32
}

func encodePDU(p pduData) []byte {
	var vbs []byte
	for _, o := range p.VarBinds {
		vbs = append(vbs, ber.Seq(ber.OID(o), ber.Null())...)
	}
	var body []byte
	body = append(body, ber.Int(int64(p.ReqID))...)
	body = append(body, ber.Int(p.NonRep)...)
	body = append(body, ber.Int(p.MaxRep)...)
	body = append(body, ber.TLV(ber.TagSequence, vbs)...)
	return ber.TLV(p.Type, body)
}

// buildMessage serializes a full SNMPv3 message, applying auth and priv.
// It must be called with c.mu held.
func (c *Client) buildMessage(msgID int32, scoped []byte, level SecurityLevel, user string,
	engineID []byte, boots, etime int32) ([]byte, error) {

	flags := byte(0x04) // reportable
	switch level {
	case AuthNoPriv:
		flags |= 0x01
	case AuthPriv:
		flags |= 0x03
	}

	msgData := scoped
	privParams := []byte{}
	if level == AuthPriv {
		salt := c.nextSalt()
		ct, err := encryptAES(c.privKey, boots, etime, salt, scoped)
		if err != nil {
			return nil, err
		}
		msgData = ber.OctetStr(ct)
		privParams = salt
	}

	// A random marker reserves the authentication parameters slot; it is
	// located and overwritten once the message length is final.
	var marker []byte
	if level != NoAuthNoPriv {
		marker = make([]byte, c.cfg.Auth.tagLen())
		if _, err := rand.Read(marker); err != nil {
			return nil, err
		}
	}

	secParams := ber.Seq(
		ber.OctetStr(engineID),
		ber.Int(int64(boots)),
		ber.Int(int64(etime)),
		ber.OctetStr([]byte(user)),
		ber.OctetStr(marker),
		ber.OctetStr(privParams),
	)

	msg := ber.Seq(
		ber.Int(3),
		ber.Seq(
			ber.Int(int64(msgID)),
			ber.Int(65507),
			ber.OctetStr([]byte{flags}),
			ber.Int(3),
		),
		ber.OctetStr(secParams),
		msgData,
	)

	if level == NoAuthNoPriv {
		return msg, nil
	}

	at := bytes.Index(msg, marker)
	if at < 0 {
		return nil, errors.New("snmp: internal error locating auth parameters")
	}
	for i := range marker {
		msg[at+i] = 0
	}
	copy(msg[at:at+len(marker)], authDigest(c.cfg.Auth, c.authKey, msg))
	return msg, nil
}

// parsed holds the decoded fields of an inbound message.
type parsed struct {
	msgID      int32
	flags      byte
	engineID   []byte
	boots      int32
	etime      int32
	authParams []byte
	privParams []byte
	pduType    byte
	reqID      int32
	errStatus  int64
	errIndex   int64
	vbs        []VarBind
}

// parseMessage decodes and (when authenticated) verifies an inbound message.
// It must be called with c.mu held.
func (c *Client) parseMessage(raw []byte) (*parsed, error) {
	outer, _, err := ber.Expect(raw, ber.TagSequence)
	if err != nil {
		return nil, err
	}
	body := outer.Content

	ver, body, err := ber.Expect(body, ber.TagInteger)
	if err != nil {
		return nil, err
	}
	if ber.ParseInt(ver.Content) != 3 {
		return nil, fmt.Errorf("snmp: unexpected version %d", ber.ParseInt(ver.Content))
	}

	gd, body, err := ber.Expect(body, ber.TagSequence)
	if err != nil {
		return nil, err
	}
	p := &parsed{}
	g := gd.Content
	e, g, err := ber.Expect(g, ber.TagInteger)
	if err != nil {
		return nil, err
	}
	p.msgID = int32(ber.ParseInt(e.Content))
	if _, g, err = ber.Expect(g, ber.TagInteger); err != nil { // msgMaxSize
		return nil, err
	}
	e, g, err = ber.Expect(g, ber.TagOctetStr)
	if err != nil {
		return nil, err
	}
	if len(e.Content) > 0 {
		p.flags = e.Content[0]
	}

	sp, body, err := ber.Expect(body, ber.TagOctetStr)
	if err != nil {
		return nil, err
	}
	spSeq, _, err := ber.Expect(sp.Content, ber.TagSequence)
	if err != nil {
		return nil, err
	}
	s := spSeq.Content
	if e, s, err = ber.Expect(s, ber.TagOctetStr); err != nil {
		return nil, err
	}
	p.engineID = e.Content
	if e, s, err = ber.Expect(s, ber.TagInteger); err != nil {
		return nil, err
	}
	p.boots = int32(ber.ParseInt(e.Content))
	if e, s, err = ber.Expect(s, ber.TagInteger); err != nil {
		return nil, err
	}
	p.etime = int32(ber.ParseInt(e.Content))
	if _, s, err = ber.Expect(s, ber.TagOctetStr); err != nil { // msgUserName
		return nil, err
	}
	if e, s, err = ber.Expect(s, ber.TagOctetStr); err != nil {
		return nil, err
	}
	p.authParams = e.Content
	if e, _, err = ber.Expect(s, ber.TagOctetStr); err != nil {
		return nil, err
	}
	p.privParams = e.Content

	// Verify the HMAC by blanking the authentication parameters in a copy.
	if p.flags&0x01 != 0 && len(c.authKey) > 0 && len(p.authParams) > 0 {
		at := bytes.Index(raw, p.authParams)
		if at < 0 {
			return nil, errors.New("snmp: cannot locate auth parameters for verification")
		}
		check := append([]byte(nil), raw...)
		for i := range p.authParams {
			check[at+i] = 0
		}
		want := authDigest(c.cfg.Auth, c.authKey, check)
		if !bytes.Equal(want, p.authParams) {
			c.stats.AuthFails++
			return nil, errors.New("snmp: authentication digest mismatch (wrong auth passphrase or protocol)")
		}
	}

	scoped := body
	if p.flags&0x02 != 0 {
		ct, _, err := ber.Expect(body, ber.TagOctetStr)
		if err != nil {
			return nil, err
		}
		if len(c.privKey) == 0 {
			return nil, errors.New("snmp: encrypted response but no privacy key")
		}
		if scoped, err = decryptAES(c.privKey, p.boots, p.etime, p.privParams, ct.Content); err != nil {
			return nil, fmt.Errorf("snmp: decrypt: %w", err)
		}
	}

	sc, _, err := ber.Expect(scoped, ber.TagSequence)
	if err != nil {
		return nil, fmt.Errorf("snmp: scoped PDU: %w (wrong priv passphrase or protocol?)", err)
	}
	d := sc.Content
	if _, d, err = ber.Expect(d, ber.TagOctetStr); err != nil { // contextEngineID
		return nil, err
	}
	if _, d, err = ber.Expect(d, ber.TagOctetStr); err != nil { // contextName
		return nil, err
	}
	pdu, _, err := ber.Next(d)
	if err != nil {
		return nil, err
	}
	p.pduType = pdu.Tag
	q := pdu.Content
	if e, q, err = ber.Expect(q, ber.TagInteger); err != nil {
		return nil, err
	}
	p.reqID = int32(ber.ParseInt(e.Content))
	if e, q, err = ber.Expect(q, ber.TagInteger); err != nil {
		return nil, err
	}
	p.errStatus = ber.ParseInt(e.Content)
	if e, q, err = ber.Expect(q, ber.TagInteger); err != nil {
		return nil, err
	}
	p.errIndex = ber.ParseInt(e.Content)
	vbl, _, err := ber.Expect(q, ber.TagSequence)
	if err != nil {
		return nil, err
	}
	rest := vbl.Content
	for len(rest) > 0 {
		var one ber.Elem
		if one, rest, err = ber.Expect(rest, ber.TagSequence); err != nil {
			return nil, err
		}
		oidE, vRest, err := ber.Expect(one.Content, ber.TagOID)
		if err != nil {
			return nil, err
		}
		val, _, err := ber.Next(vRest)
		if err != nil {
			return nil, err
		}
		p.vbs = append(p.vbs, VarBind{OID: ber.ParseOID(oidE.Content), Tag: val.Tag, Raw: val.Content})
	}
	return p, nil
}

// ---------------------------------------------------------------------------
// transport
// ---------------------------------------------------------------------------

func (c *Client) roundTrip(msg []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.cfg.Retries; attempt++ {
		c.stats.Requests++
		if err := c.conn.SetDeadline(time.Now().Add(c.cfg.Timeout)); err != nil {
			return nil, err
		}
		if _, err := c.conn.Write(msg); err != nil {
			lastErr = err
			continue
		}
		buf := make([]byte, 65535)
		n, err := c.conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				c.stats.Timeouts++
				lastErr = fmt.Errorf("snmp: timeout after %s", c.cfg.Timeout)
				continue
			}
			lastErr = err
			continue
		}
		return buf[:n], nil
	}
	return nil, lastErr
}

// usmStats OIDs reported by an agent when discovery or time sync is needed.
var (
	oidNotInTimeWindows = ber.MustParseOIDString("1.3.6.1.6.3.15.1.1.2.0")
	oidUnknownEngineID  = ber.MustParseOIDString("1.3.6.1.6.3.15.1.1.4.0")
)

// discover performs engine ID discovery and time synchronization.
// It must be called with c.mu held.
func (c *Client) discover() error {
	probe := encodePDU(pduData{Type: ber.PDUGet, ReqID: c.nextReqID()})
	scoped := ber.Seq(ber.OctetStr(nil), ber.OctetStr(nil), probe)
	msg, err := c.buildMessage(c.nextMsgID(), scoped, NoAuthNoPriv, "", nil, 0, 0)
	if err != nil {
		return err
	}
	raw, err := c.roundTrip(msg)
	if err != nil {
		return fmt.Errorf("snmp: engine discovery: %w", err)
	}
	p, err := c.parseMessage(raw)
	if err != nil {
		return fmt.Errorf("snmp: engine discovery: %w", err)
	}
	if len(p.engineID) == 0 {
		return errors.New("snmp: agent returned an empty engine ID")
	}
	c.engineID = p.engineID
	c.boots, c.timeBase, c.timeSync = p.boots, p.etime, time.Now()
	c.stats.Rediscovers++

	if c.cfg.Level != NoAuthNoPriv {
		if c.authKey, c.privKey, err = deriveKeys(
			c.cfg.Auth, c.cfg.Priv, c.cfg.AuthPass, c.cfg.PrivPass, c.engineID); err != nil {
			return err
		}
	}
	return nil
}

// reportOID returns the usmStats counter cited by a Report PDU, if any.
func reportOID(p *parsed) []uint32 {
	if p.pduType != ber.PDUReport || len(p.vbs) == 0 {
		return nil
	}
	return p.vbs[0].OID
}

func oidEq(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// request sends one PDU, handling discovery, time resync and Report PDUs.
func (c *Client) request(p pduData) ([]VarBind, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.engineID) == 0 {
		if err := c.discover(); err != nil {
			return nil, err
		}
	}

	for attempt := 0; attempt < 3; attempt++ {
		p.ReqID = c.nextReqID()
		scoped := ber.Seq(ber.OctetStr(c.engineID), ber.OctetStr([]byte(c.cfg.Context)), encodePDU(p))
		msg, err := c.buildMessage(c.nextMsgID(), scoped, c.cfg.Level, c.cfg.Username,
			c.engineID, c.boots, c.engineTimeNow())
		if err != nil {
			return nil, err
		}
		raw, err := c.roundTrip(msg)
		if err != nil {
			return nil, err
		}
		resp, err := c.parseMessage(raw)
		if err != nil {
			return nil, err
		}

		if ro := reportOID(resp); ro != nil {
			switch {
			case oidEq(ro, oidNotInTimeWindows):
				c.boots, c.timeBase, c.timeSync = resp.boots, resp.etime, time.Now()
				c.stats.Resyncs++
				continue
			case oidEq(ro, oidUnknownEngineID):
				c.engineID = nil
				if err := c.discover(); err != nil {
					return nil, err
				}
				continue
			}
			return nil, fmt.Errorf("snmp: agent report %s (check username and security level)", ber.String(ro))
		}

		if resp.reqID != p.ReqID {
			continue // stale datagram; try again
		}
		if resp.errStatus != 0 {
			return nil, fmt.Errorf("snmp: error-status %d at index %d", resp.errStatus, resp.errIndex)
		}
		return resp.vbs, nil
	}
	return nil, errors.New("snmp: exchange did not converge after 3 attempts")
}

// Get fetches the given OIDs in a single GetRequest.
func (c *Client) Get(oids [][]uint32) ([]VarBind, error) {
	if len(oids) == 0 {
		return nil, nil
	}
	return c.request(pduData{Type: ber.PDUGet, VarBinds: oids})
}

// Walk retrieves the whole subtree under root using GETBULK.
func (c *Client) Walk(root []uint32) ([]VarBind, error) {
	var out []VarBind
	cur := root
	for i := 0; i < 4096; i++ {
		vbs, err := c.request(pduData{
			Type:     ber.PDUGetBulk,
			NonRep:   0,
			MaxRep:   25,
			VarBinds: [][]uint32{cur},
		})
		if err != nil {
			return out, err
		}
		if len(vbs) == 0 {
			return out, nil
		}
		for _, vb := range vbs {
			if vb.Tag == ber.TagEndOfMibView || !ber.HasPrefix(vb.OID, root) {
				return out, nil
			}
			out = append(out, vb)
		}
		next := vbs[len(vbs)-1].OID
		if oidEq(next, cur) {
			return out, nil
		}
		cur = next
	}
	return out, errors.New("snmp: walk exceeded iteration limit")
}
