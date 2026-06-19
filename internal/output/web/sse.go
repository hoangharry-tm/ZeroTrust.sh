package web

import (
	"fmt"
	"net/http"
	"sync"
)

// hub manages connected SSE clients and broadcasts HTML fragments to all of them.
type hub struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
}

func newHub() *hub {
	return &hub{clients: make(map[chan string]struct{})}
}

// register creates and registers a new client channel.
func (h *hub) register() chan string {
	ch := make(chan string, 32)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

// deregister removes the client channel and closes it.
func (h *hub) deregister(ch chan string) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
	close(ch)
}

// broadcast sends a named SSE event with the given HTML fragment to all clients.
// Slow clients whose channel is full are dropped silently.
func (h *hub) broadcast(event, fragment string) {
	msg := fmt.Sprintf("event: %s\ndata: %s\n\n", event, fragment)
	h.mu.Lock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default:
		}
	}
	h.mu.Unlock()
}

// ServeHTTP streams SSE to a single client until they disconnect.
func (h *hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	rc := http.NewResponseController(w)

	ch := h.register()
	defer h.deregister(ch)

	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if _, err := fmt.Fprint(w, msg); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}
