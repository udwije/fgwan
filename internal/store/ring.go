// Package store keeps a fixed-size sliding window of rate samples in memory.
package store

import "sync"

// Point is one interface's rate at one instant. A nil *Point marks a gap
// (interface down, failed poll, or a discarded counter reset).
type Point struct {
	Rx float64 `json:"rx"`
	Tx float64 `json:"tx"`
}

// Frame is one poll tick across every monitored interface.
type Frame struct {
	TS int64             `json:"ts"`
	V  map[string]*Point `json:"v"`
}

// Ring is a fixed-capacity circular buffer of frames.
type Ring struct {
	mu   sync.RWMutex
	buf  []Frame
	head int
	n    int
	cap  int
}

// New allocates a ring of the given capacity.
func New(capacity int) *Ring {
	if capacity < 2 {
		capacity = 2
	}
	return &Ring{buf: make([]Frame, capacity), cap: capacity}
}

// Push appends a frame, evicting the oldest when full.
func (r *Ring) Push(f Frame) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.head] = f
	r.head = (r.head + 1) % r.cap
	if r.n < r.cap {
		r.n++
	}
}

// Len returns the number of buffered frames.
func (r *Ring) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.n
}

// Cap returns the ring capacity.
func (r *Ring) Cap() int { return r.cap }

// Snapshot returns up to the last max frames in chronological order.
func (r *Ring) Snapshot(max int) []Frame {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if max <= 0 || max > r.n {
		max = r.n
	}
	out := make([]Frame, 0, max)
	start := r.head - max
	for i := 0; i < max; i++ {
		idx := ((start+i)%r.cap + r.cap) % r.cap
		out = append(out, r.buf[idx])
	}
	return out
}

// Last returns the most recent frame.
func (r *Ring) Last() (Frame, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.n == 0 {
		return Frame{}, false
	}
	idx := ((r.head-1)%r.cap + r.cap) % r.cap
	return r.buf[idx], true
}

// Rebuild returns a new ring of the given capacity, carrying over the history
// of every interface id in keep.
//
// This is what makes reconfiguration non-destructive: when the operator edits
// the zone layout, interfaces they did not touch keep their accumulated window
// instead of restarting from an empty chart. Interfaces that were removed are
// dropped, and newly added ones simply have no history yet.
func (r *Ring) Rebuild(capacity int, keep map[string]bool) *Ring {
	out := New(capacity)
	for _, f := range r.Snapshot(capacity) {
		nf := Frame{TS: f.TS, V: make(map[string]*Point, len(keep))}
		for id, p := range f.V {
			if keep[id] {
				nf.V[id] = p
			}
		}
		out.Push(nf)
	}
	return out
}
