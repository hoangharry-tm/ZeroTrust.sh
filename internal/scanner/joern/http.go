// Copyright 2026 Minh Hoang Ton
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

package joern

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/tuning"
)

// queryRequest is the JSON body sent to POST /query.
type queryRequest struct {
	Query string `json:"query"`
}

// querySubmitResponse is the JSON body returned by POST /query.
// The server returns only success+uuid immediately; the result must be
// fetched separately via GET /result/{uuid}.
type querySubmitResponse struct {
	UUID    string `json:"uuid"`
	Success bool   `json:"success"`
}

// queryResultResponse is the JSON body returned by GET /result/{uuid}.
// Stdout is the ANSI-annotated REPL output; for queries ending in .toList.toJson
// it contains a JSON array string wrapped in a Scala string literal.
type queryResultResponse struct {
	UUID    string `json:"uuid"`
	Success bool   `json:"success"`
	Stdout  string `json:"stdout"`
	Stderr  string `json:"stderr"`
}

// resultPollInterval is how long to wait between GET /result/{uuid} retries.
const resultPollInterval = tuning.JoernResultPollInterval

// doQuery sends a Joern DSL expression to POST /query, then polls
// GET /result/{uuid} until the result is ready. Returns the raw stdout bytes
// suitable for further JSON decoding.
//
// Returns ErrJoernCrashed if the subprocess has exited, ErrMalformedResponse
// if either HTTP response cannot be parsed, and a wrapped error if the server
// reports success=false.
func (c *Client) doQuery(ctx context.Context, query string) ([]byte, error) {
	if c.crashed.Load() {
		return nil, ErrJoernCrashed
	}
	slog.Debug("joern: doQuery submitting", "query", query)

	// Apply per-query deadline so a single slow traversal can't stall the scan.
	qctx, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()

	uuid, err := c.postQuery(qctx, query)
	if err != nil {
		return nil, err
	}
	raw, err := c.fetchResult(qctx, uuid)
	if err != nil {
		return nil, err
	}
	slog.Debug("joern: doQuery result", "uuid", uuid, "stdout", string(raw))
	return raw, nil
}

// postQuery submits the query and returns its UUID.
func (c *Client) postQuery(ctx context.Context, query string) (string, error) {
	body, err := json.Marshal(queryRequest{Query: query})
	if err != nil {
		return "", fmt.Errorf("joern: marshal query: %w", err)
	}
	slog.Debug("joern: POST /query body", "body", string(body))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.serverURL+"/query", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("joern: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("joern: POST /query: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10)) // 64 KB
	if err != nil {
		return "", fmt.Errorf("joern: read POST /query body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%w: POST /query HTTP %d — %s",
			ErrMalformedResponse, resp.StatusCode, truncate(raw, 256))
	}

	var sub querySubmitResponse
	if err := json.Unmarshal(raw, &sub); err != nil {
		return "", fmt.Errorf("%w: POST /query parse: %w — body: %s",
			ErrMalformedResponse, err, truncate(raw, 256))
	}
	if !sub.Success {
		return "", fmt.Errorf("joern: POST /query returned success=false — body: %s", truncate(raw, 256))
	}
	if sub.UUID == "" {
		return "", fmt.Errorf("%w: POST /query returned empty uuid", ErrMalformedResponse)
	}
	return sub.UUID, nil
}

// fetchResult polls GET /result/{uuid} until the server returns a completed
// result (success=true with non-empty stdout) or the context is cancelled.
//
// The Joern server completes simple queries (~1 ms) immediately but CPG
// traversals may take seconds. We poll at resultPollInterval until done.
func (c *Client) fetchResult(ctx context.Context, uuid string) ([]byte, error) {
	url := c.serverURL + "/result/" + uuid //nolint:gocritic // not a net/url — simple string concat

	start := time.Now()
	idleStart := time.Now()  // reset each time we see a non-202/204 response
	lastLogAt := time.Now()  // throttle progress logs to every 30s

	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("joern: fetch result cancelled: %w", err)
		}
		if c.crashed.Load() {
			return nil, ErrJoernCrashed
		}
		// Idle-freeze detection: if we've been receiving only 202/204 for
		// longer than JoernIdleTimeout, Joern is likely frozen (GC deadlock,
		// OOM without crash). Surface ErrBuildTimeout so callers can decide.
		if time.Since(idleStart) > tuning.JoernIdleTimeout {
			slog.Warn("joern: fetchResult idle timeout — Joern appears frozen",
				slog.Duration("idle", time.Since(idleStart)),
				slog.Duration("elapsed", time.Since(start)),
			)
			return nil, ErrBuildTimeout
		}
		// Progress heartbeat every 30s so operators can see Joern is alive.
		if time.Since(lastLogAt) > 30*time.Second {
			slog.Info("joern: fetchResult waiting for Joern",
				slog.Duration("elapsed", time.Since(start)),
				slog.Duration("idle", time.Since(idleStart)),
			)
			lastLogAt = time.Now()
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("joern: build GET /result request: %w", err)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			// Server may transiently return errors while processing — keep polling.
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("joern: fetch result cancelled: %w", ctx.Err())
			case <-time.After(resultPollInterval):
				continue
			}
		}

		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MB cap
		_ = resp.Body.Close()                                        //nolint:errcheck
		if readErr != nil {
			return nil, fmt.Errorf("joern: read GET /result body: %w", readErr)
		}

		if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
			// 202/204 means still processing — poll again.
			// idleStart is not reset here; consecutive 202s accumulate idle time.
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("joern: fetch result cancelled: %w", ctx.Err())
			case <-time.After(resultPollInterval):
				continue
			}
		}
		// Any non-202/204 response (including 200 in-progress states) resets idle clock.
		idleStart = time.Now()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("%w: GET /result HTTP %d — %s",
				ErrMalformedResponse, resp.StatusCode, truncate(raw, 256))
		}

		var qr queryResultResponse
		if err := json.Unmarshal(raw, &qr); err != nil {
			return nil, fmt.Errorf("%w: GET /result parse: %w — body: %s",
				ErrMalformedResponse, err, truncate(raw, 256))
		}
		// Joern returns success=false with empty stdout+stderr for ~30s during
		// cold-start REPL initialization. Treat this as "still processing".
		if !qr.Success && qr.Stdout == "" && qr.Stderr == "" {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("joern: fetch result cancelled: %w", ctx.Err())
			case <-time.After(resultPollInterval):
				continue
			}
		}
		if !qr.Success {
			return nil, fmt.Errorf("joern: query failed: %s", truncate([]byte(qr.Stderr), 512))
		}

		// Empty stdout on 200 means the server hasn't finished processing yet.
		// Poll again after a short delay.
		if qr.Stdout == "" {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("joern: fetch result cancelled: %w", ctx.Err())
			case <-time.After(resultPollInterval):
				continue
			}
		}

		stdout := parseStdout(qr.Stdout)
		if isJoernConsoleError(stdout) {
			return nil, fmt.Errorf("joern: console error: %s", truncate([]byte(stdout), 512))
		}
		slog.Debug("joern: fetchResult complete", "uuid", uuid, "elapsed", time.Since(start))
		return []byte(stdout), nil
	}
}

// isJoernConsoleError reports whether s is a Joern REPL error message that
// should be surfaced as an error rather than passed through as valid output.
//
// Joern's HTTP API returns success=true even when the query fails internally
// (e.g. missing goastgen binary, no CPG loaded). These are detected by their
// Scala exception prefix rather than the HTTP-level success field.
func isJoernConsoleError(s string) bool {
	return strings.HasPrefix(s, "io.joern.console.Error:") ||
		strings.HasPrefix(s, "io.joern.console.ConsoleException:")
}

// doQueryPing sends a trivial query to verify the server is alive and accepting
// requests. Used by Ping and waitReady instead of GET /ready (which Joern does
// not expose).
//
// Returns nil if the server responds successfully, ErrJoernUnreachable if the
// POST fails (connection refused), or any other error on unexpected failures.
func (c *Client) doQueryPing(ctx context.Context) error {
	_, err := c.doQuery(ctx, "1+1")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJoernUnreachable, err)
	}
	return nil
}

// parseStdout extracts the JSON payload from a Joern stdout string.
// Joern's HTTP server may return:
//
//   - A bare JSON value:         [{"id":"1",...}]
//   - A Scala string literal:    "[{\"id\":\"1\",...}]"  (with outer quotes)
//   - A REPL-annotated value:    val res0: String = "[{...}]"
//   - ANSI-annotated REPL text:  val [36mres0[0m: String = "[{...}]"
//
// parseStdout normalises all forms to the bare JSON value.
func parseStdout(s string) string {
	s = strings.TrimSpace(s)

	// Strip ANSI escape sequences before further processing.
	s = stripANSI(s)

	// REPL annotation: "resN: Type = <value>" — strip prefix up to " = ".
	// Use ` = "` instead of ` = ` to avoid matching ` = ` inside JSON code
	// values (e.g. Java "x = y"). The REPL string value always starts with '"'.
	if idx := strings.LastIndex(s, ` = "`); idx != -1 {
		// Use LastIndex to find the assignment closest to the actual value,
		// skipping any preamble from the REPL session.
		candidate := strings.TrimSpace(s[idx+3:])
		if len(candidate) > 0 && (candidate[0] == '[' || candidate[0] == '{' || candidate[0] == '"') {
			s = candidate
		}
	}

	// Scala string literal: outer double-quotes with escaped inner quotes
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		var inner string
		if err := json.Unmarshal([]byte(s), &inner); err == nil {
			return inner
		}
	}

	return s
}

// stripANSI removes ANSI CSI escape sequences (colour codes, cursor movement, etc.)
// from s. This is a simple state-machine approach sufficient for Joern REPL output.
func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inEscape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inEscape {
			// CSI sequences end with a letter in [A-Za-z]
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				inEscape = false
			}
			continue
		}
		if c == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			inEscape = true
			i++ // skip the '['
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// truncate returns up to n bytes of b as a string, appending "…" if truncated.
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
