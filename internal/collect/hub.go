package collect

import (
	"sync"

	"fgwan/internal/store"
)

// Hub fans each published frame out to every live subscriber.
type Hub struct {
	mu   sync.RWMutex
	subs map[int]chan store.Frame
	next int
}

// NewHub creates an empty hub.
func NewHub() *Hub { return &Hub{subs: map[int]chan store.Frame{}} }

// Subscribe registers a client and returns its channel plus a cancel func.
func (h *Hub) Subscribe() (<-chan store.Frame, func()) {
	ch := make(chan store.Frame, 8)
	h.mu.Lock()
	id := h.next
	h.next++
	h.subs[id] = ch
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if c, ok := h.subs[id]; ok {
			delete(h.subs, id)
			close(c)
		}
		h.mu.Unlock()
	}
}

// Broadcast publishes a frame, dropping it for any client that has fallen behind.
func (h *Hub) Broadcast(f store.Frame) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, ch := range h.subs {
		select {
		case ch <- f:
		default:
		}
	}
}

// Count returns the number of connected subscribers.
func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}
