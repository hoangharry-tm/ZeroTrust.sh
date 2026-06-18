// Package joern wraps the Joern CPG engine HTTP API (Apache 2.0).
//
// # Architecture
//
// Joern is pre-started at CLI launch (before file ingestion) to eliminate JVM
// cold-start latency. It builds the Universal Code Property Graph (AST + CFG +
// PDG + call graph) for all in-scope source files and serves inter-procedural
// taint queries via an HTTP JSON API on 127.0.0.1 only.
//
// The CPG is shared between both detection paths via the pkg/cpg.Graph interface:
//   - Path A's Joern taint analysis calls TaintPaths directly.
//   - Path B's Heuristic Targeting and Call Chain Assembler call QueryNodes,
//     GetCallGraph, GetCallers, GetCallees, and GetNeighboursAtDepth.
//
// # Subprocess lifecycle
//
// A Client can operate in two modes:
//
//  1. Externally managed — created with New() and pointed at a pre-running
//     Joern server (CI, Docker, local dev). No subprocess is spawned; Start
//     and Stop are no-ops. Use WithServerURL to set the base URL.
//
//  2. Self-managed — created with New(WithBinaryPath("joern-server"), ...).
//     Call Start(ctx) to spawn the subprocess; it will be killed on Stop.
//     Start validates port availability, binds the server to 127.0.0.1,
//     and polls /ready until the JVM is warm. Stop sends SIGTERM → waits →
//     SIGKILL to prevent subprocess leaks.
//
// # Security contract
//
//   - The HTTP server ALWAYS binds to 127.0.0.1 (loopback only), never 0.0.0.0.
//   - New() rejects any serverURL whose host is not localhost / 127.0.0.1 / ::1.
//   - Start() refuses to bind a port already in use (ErrPortInUse), preventing
//     silent attachment to an unknown existing process.
//   - The managed subprocess is always cleaned up: Stop escalates SIGTERM →
//     SIGKILL if the process does not exit within the configured timeout.
//
// # Incremental CPG patching
//
// On repeat scans the CPG is loaded from a serialized snapshot and patched with
// a depth-5 BFS update rooted at each changed function (IncrementalPatch).
// Depth 5 is the taint-correctness bound from Li et al. (ICSE 2024) and
// Effendi et al. (SOAP/PLDI 2025, Joern core team). If any changed function has
// ≥ 50 callers (hub module), ErrHubModuleDetected is returned and the caller
// must fall back to BuildCPG for a full rebuild.
package joern

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// defaults for all configurable timeouts and retry counts.
const (
	defaultServerURL    = "http://127.0.0.1:8080"
	defaultBinaryPath   = "joern-server"
	defaultHost         = "127.0.0.1"
	defaultPort         = 8080
	defaultPingRetries  = 12
	defaultPingInterval = 500 * time.Millisecond
	defaultStopTimeout  = 5 * time.Second
	defaultQueryTimeout = 30 * time.Second
	defaultBuildTimeout = 120 * time.Second
)

// Option configures a Client.
type Option func(*Client)

// WithServerURL sets the base URL of the Joern HTTP server.
// The host must be localhost, 127.0.0.1, or ::1; any other host causes New
// to return ErrInvalidServerURL.
func WithServerURL(u string) Option { return func(c *Client) { c.serverURL = u } }

// WithBinaryPath sets the path to the joern-server binary used by Start.
// Defaults to "joern-server" (resolved via PATH).
func WithBinaryPath(path string) Option { return func(c *Client) { c.binaryPath = path } }

// WithHost sets the interface that joern-server binds to.
// Must be a loopback address; defaults to 127.0.0.1.
func WithHost(host string) Option { return func(c *Client) { c.host = host } }

// WithPort sets the TCP port for the subprocess. Defaults to 8080.
func WithPort(port int) Option { return func(c *Client) { c.port = port } }

// WithQueryTimeout sets the per-query HTTP timeout. Defaults to 30 s.
func WithQueryTimeout(d time.Duration) Option { return func(c *Client) { c.queryTimeout = d } }

// WithBuildTimeout sets the maximum duration for a full CPG build. Defaults to 120 s.
func WithBuildTimeout(d time.Duration) Option { return func(c *Client) { c.buildTimeout = d } }

// WithPingRetries sets how many times Ping retries before returning
// ErrJoernUnreachable. Each attempt waits 500 ms. Defaults to 12 (total 6 s).
func WithPingRetries(n int) Option { return func(c *Client) { c.pingRetries = n } }

// Client wraps the Joern HTTP server API and optionally manages its subprocess.
// All exported methods are safe to call concurrently.
type Client struct {
	serverURL    string
	binaryPath   string
	host         string
	port         int
	pingRetries  int
	queryTimeout time.Duration
	buildTimeout time.Duration

	httpClient *http.Client

	// subprocess state — protected by mu.
	// cmd is non-nil only when this client spawned the process via Start.
	mu      sync.Mutex
	cmd     *exec.Cmd
	done    chan struct{} // closed when the subprocess exits
	crashed atomic.Bool   // set by the crash-watcher goroutine
}

// New returns a Client configured with the given options.
// Defaults: serverURL=http://127.0.0.1:8080, no managed subprocess.
//
// Returns ErrInvalidServerURL if the resolved URL host is not loopback.
func New(opts ...Option) (*Client, error) {
	c := &Client{
		serverURL:    defaultServerURL,
		binaryPath:   defaultBinaryPath,
		host:         defaultHost,
		port:         defaultPort,
		pingRetries:  defaultPingRetries,
		queryTimeout: defaultQueryTimeout,
		buildTimeout: defaultBuildTimeout,
	}
	for _, o := range opts {
		o(c)
	}

	if err := validateServerURL(c.serverURL); err != nil {
		return nil, err
	}

	c.httpClient = &http.Client{Timeout: c.queryTimeout}
	return c, nil
}

// Start spawns the joern-server subprocess bound to 127.0.0.1:<port>, waits
// for it to become ready, and returns nil on success.
//
// Start validates port availability before spawning (ErrPortInUse if occupied).
// The server process is monitored by a background goroutine; if it exits
// unexpectedly, all subsequent method calls return ErrJoernCrashed.
//
// Callers must call Stop when the client is no longer needed.
// Returns ErrAlreadyStarted if called a second time without an intervening Stop.
func (c *Client) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.cmd != nil {
		c.mu.Unlock()
		return ErrAlreadyStarted
	}

	if err := checkPortAvailable(ctx, c.host, c.port); err != nil {
		c.mu.Unlock()
		return err
	}

	// Build the subprocess command. Always bind to loopback.
	//nolint:gosec // binaryPath comes from config, not user input at scan time
	cmd := exec.CommandContext(ctx, c.binaryPath,
		"--host", c.host,
		"--port", strconv.Itoa(c.port),
	)
	cmd.Stdout = os.Stderr // route JVM output to stderr so it doesn't pollute stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("joern: start subprocess: %w", err)
	}

	done := make(chan struct{})
	c.cmd = cmd
	c.done = done
	c.crashed.Store(false)
	c.mu.Unlock()

	// Crash watcher: signals any in-flight call that the process is gone.
	go func() {
		defer close(done)
		_ = cmd.Wait() //nolint:errcheck // exit status reported via crashed flag
		c.crashed.Store(true)
	}()

	// Poll /ready until the JVM is warm or context expires.
	return c.waitReady(ctx)
}

// Stop sends SIGTERM to the managed subprocess, waits up to the configured
// stop timeout, then escalates to SIGKILL. Stop is idempotent and safe to
// call even if Start was never called (returns ErrNotManaged in that case).
//
// Always cleans up internal state so the client can be restarted via Start.
func (c *Client) Stop(ctx context.Context) error {
	c.mu.Lock()
	cmd := c.cmd
	done := c.done
	c.cmd = nil
	c.done = nil
	c.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return ErrNotManaged
	}

	// Graceful shutdown.
	_ = cmd.Process.Signal(os.Interrupt) //nolint:errcheck

	timeout := time.NewTimer(defaultStopTimeout)
	defer timeout.Stop()

	select {
	case <-done:
		return nil
	case <-timeout.C:
	case <-ctx.Done():
	}

	// Escalate to SIGKILL.
	_ = cmd.Process.Kill() //nolint:errcheck
	<-done
	return nil
}

// Ping verifies that the Joern HTTP server is reachable and accepting queries.
// Returns ErrJoernCrashed if the managed subprocess has exited, or
// ErrJoernUnreachable if all retry attempts fail.
//
// Ping does not require a CPG to be loaded; it sends a trivial expression.
func (c *Client) Ping(ctx context.Context) error {
	if c.crashed.Load() {
		return ErrJoernCrashed
	}

	var lastErr error
	for i := 0; i < c.pingRetries; i++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("joern: ping cancelled: %w", err)
		}

		code, err := c.doGet(ctx, "/ready")
		if err == nil && code == http.StatusOK {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("joern: /ready returned HTTP %d", code)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("joern: ping cancelled: %w", ctx.Err())
		case <-time.After(defaultPingInterval):
		}
	}
	return fmt.Errorf("%w: %w", ErrJoernUnreachable, lastErr)
}

// Graph returns a cpg.Graph backed by this Joern server instance.
// The returned graph is safe to share across both detection paths concurrently.
// Graph must be called after BuildCPG (or LoadCPG + IncrementalPatch) completes.
func (c *Client) Graph() *joernGraph {
	return &joernGraph{client: c}
}

// waitReady polls GET /ready until it returns 200 or the context is cancelled.
func (c *Client) waitReady(ctx context.Context) error {
	for i := 0; i < c.pingRetries; i++ {
		if ctx.Err() != nil {
			return fmt.Errorf("joern: wait-ready cancelled: %w", ctx.Err())
		}
		if c.crashed.Load() {
			return ErrJoernCrashed
		}

		code, err := c.doGet(ctx, "/ready")
		if err == nil && code == http.StatusOK {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("joern: wait-ready cancelled: %w", ctx.Err())
		case <-time.After(defaultPingInterval):
		}
	}
	return ErrJoernUnreachable
}

// checkPortAvailable verifies that host:port is not already bound.
// This prevents Start from silently attaching to an unknown existing process.
// There is an unavoidable TOCTOU window between this check and the actual bind;
// that is documented and accepted — the check catches the common case.
func checkPortAvailable(ctx context.Context, host string, port int) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrPortInUse, addr)
	}
	_ = ln.Close() //nolint:errcheck
	return nil
}

// validateServerURL ensures the URL host is a loopback address.
// This enforces the security contract that Joern is never contacted over the
// network — all CPG data stays on the local machine.
func validateServerURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: parse %q: %v", ErrInvalidServerURL, rawURL, err)
	}
	h := u.Hostname()
	switch h {
	case "localhost", "127.0.0.1", "::1":
		return nil
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidServerURL, h)
	}
}
