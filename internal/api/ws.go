package api

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// wsGUID is the RFC 6455 handshake constant.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsConn is a minimal server-side WebSocket connection: text frames out,
// ping/close handling in. That is the whole protocol surface this tool needs.
type wsConn struct {
	c  net.Conn
	br *bufio.Reader

	mu     sync.Mutex
	closed bool
}

// upgrade completes the RFC 6455 handshake on a hijacked connection.
func upgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		return nil, errors.New("ws: not an upgrade request")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("ws: missing Sec-WebSocket-Key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("ws: response writer does not support hijacking")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return &wsConn{c: conn, br: brw.Reader}, nil
}

// writeFrame emits a single unfragmented, unmasked frame.
func (w *wsConn) writeFrame(opcode byte, payload []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("ws: closed")
	}
	var hdr []byte
	hdr = append(hdr, 0x80|opcode)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n < 65536:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(n))
		hdr = append(hdr, 126, b[0], b[1])
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		hdr = append(hdr, 127)
		hdr = append(hdr, b[:]...)
	}
	if err := w.c.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err := w.c.Write(hdr); err != nil {
		return err
	}
	_, err := w.c.Write(payload)
	return err
}

// WriteText sends a text frame.
func (w *wsConn) WriteText(b []byte) error { return w.writeFrame(0x1, b) }

// Close sends a close frame and tears down the socket.
func (w *wsConn) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.mu.Unlock()
	w.c.SetWriteDeadline(time.Now().Add(time.Second))
	w.c.Write([]byte{0x88, 0x00})
	return w.c.Close()
}

// readLoop drains client frames, answering pings and detecting close.
// It returns when the peer goes away, which is how the writer learns to stop.
func (w *wsConn) readLoop(done chan<- struct{}) {
	defer close(done)
	for {
		if err := w.c.SetReadDeadline(time.Now().Add(120 * time.Second)); err != nil {
			return
		}
		var h [2]byte
		if _, err := io.ReadFull(w.br, h[:]); err != nil {
			return
		}
		opcode := h[0] & 0x0f
		masked := h[1]&0x80 != 0
		n := int(h[1] & 0x7f)
		switch n {
		case 126:
			var e [2]byte
			if _, err := io.ReadFull(w.br, e[:]); err != nil {
				return
			}
			n = int(binary.BigEndian.Uint16(e[:]))
		case 127:
			var e [8]byte
			if _, err := io.ReadFull(w.br, e[:]); err != nil {
				return
			}
			n = int(binary.BigEndian.Uint64(e[:]))
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(w.br, mask[:]); err != nil {
				return
			}
		}
		if n < 0 || n > 1<<20 {
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(w.br, payload); err != nil {
			return
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		switch opcode {
		case 0x8: // close
			return
		case 0x9: // ping
			if err := w.writeFrame(0xA, payload); err != nil {
				return
			}
		}
	}
}
