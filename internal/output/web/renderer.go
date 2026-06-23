// Copyright 2026 hoangharry-tm
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package web implements the live HTML dashboard renderer for ZeroTrust.sh.
//
// WebRenderer starts a local HTTP server, prints the URL to stdout, and fans
// pipeline events to connected browsers via Server-Sent Events (SSE). The
// browser receives HTML fragments and inserts them directly via the native
// EventSource API — no external framework required.
//
// Output (stdout):
//
//	  open → http://localhost:54321
//
// The server listens on a random free port and shuts down cleanly after the
// pipeline signals EventDone or the scan context is cancelled.
package web

import (
	"context"
	"embed"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/output"
)

//go:embed ui/index.html
var uiFS embed.FS

// WebRenderer implements output.Renderer by serving the live HTML dashboard.
type WebRenderer struct {
	exitCode int
}

// NewRenderer returns a WebRenderer that selects a random free port at Render time.
func NewRenderer() *WebRenderer {
	return &WebRenderer{}
}

// ExitCode implements output.Renderer.
func (r *WebRenderer) ExitCode() int { return r.exitCode }

// Render implements output.Renderer. It starts the HTTP server, prints the URL,
// fans events to browser clients, then shuts down after EventDone or ctx cancel.
func (r *WebRenderer) Render(ctx context.Context, ch <-chan output.Event) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("web renderer: listen: %w", err)
	}

	h := newHub()
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		data, err := uiFS.ReadFile("ui/index.html")
		if err != nil {
			http.Error(w, "ui not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data) //nolint:errcheck
	})

	mux.Handle("/events", h)

	mux.HandleFunc("/report", func(w http.ResponseWriter, req *http.Request) {
		// proxy the HTML report file so it's accessible from the dashboard
		// reportPath comes through the done event — serve it if it exists
		http.NotFound(w, req)
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln) //nolint:errcheck

	fmt.Fprintf(os.Stdout, "\n  open → http://%s\n\n", ln.Addr())

	// Fan events from the pipeline into the SSE hub.
	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			srv.Shutdown(shutdownCtx) //nolint:errcheck
			return ctx.Err()

		case e, ok := <-ch:
			if !ok {
				// Channel closed — drain any buffered events then stop.
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				srv.Shutdown(shutdownCtx) //nolint:errcheck
				return nil
			}
			r.handle(e, h, srv)
			if e.Kind == output.EventDone {
				// Keep the server alive briefly so the browser can display final state.
				select {
				case <-time.After(30 * time.Second):
				case <-ctx.Done():
				}
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				srv.Shutdown(shutdownCtx) //nolint:errcheck
				return nil
			}
		}
	}
}

// handle processes one event: updates exit code and broadcasts to SSE clients.
func (r *WebRenderer) handle(e output.Event, h *hub, srv *http.Server) {
	switch e.Kind {
	case output.EventError:
		r.exitCode = 2
	case output.EventDone:
		if e.Done != nil {
			if e.Done.BySeverity[finding.SeverityBlock] > 0 || e.Done.BySeverity[finding.SeverityHigh] > 0 {
				if r.exitCode == 0 {
					r.exitCode = 1
				}
			}
			// wire up the report file path into the /report handler (best-effort)
			if e.Done.ReportPath != "" {
				absReport, _ := filepath.Abs(e.Done.ReportPath)
				srv.Handler.(*http.ServeMux).HandleFunc("/report", func(w http.ResponseWriter, req *http.Request) {
					http.ServeFile(w, req, absReport)
				})
			}
		}
	}

	name, fragment := eventToSSE(e)
	if name != "" {
		h.broadcast(name, fragment)
	}
}
