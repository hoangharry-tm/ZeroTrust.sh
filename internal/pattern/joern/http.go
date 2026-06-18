package joern

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// queryRequest is the JSON body sent to POST /query.
type queryRequest struct {
	Query string `json:"query"`
}

// queryResponse is the JSON body returned by POST /query.
// The Stdout field contains the string representation of the evaluated
// Joern/Scala expression — for queries ending in .toList.toJson this will be
// a JSON array or object string; for simple expressions it may be a raw scalar.
type queryResponse struct {
	UUID    string `json:"uuid"`
	Success bool   `json:"success"`
	Stdout  string `json:"stdout"`
	Stderr  string `json:"stderr"`
}

// doQuery sends a Joern DSL expression to POST /query and returns the raw
// stdout bytes. The caller is responsible for further JSON decoding.
//
// Returns ErrJoernCrashed if the subprocess has exited, ErrMalformedResponse
// if the HTTP response cannot be parsed, and a wrapped error if the server
// reports success=false. All non-2xx HTTP statuses are treated as errors.
func (c *Client) doQuery(ctx context.Context, query string) ([]byte, error) {
	if c.crashed.Load() {
		return nil, ErrJoernCrashed
	}

	body, err := json.Marshal(queryRequest{Query: query})
	if err != nil {
		return nil, fmt.Errorf("joern: marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.serverURL+"/query", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("joern: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("joern: HTTP request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MB cap
	if err != nil {
		return nil, fmt.Errorf("joern: read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: HTTP %d — %s",
			ErrMalformedResponse, resp.StatusCode, truncate(raw, 256))
	}

	var qr queryResponse
	if err := json.Unmarshal(raw, &qr); err != nil {
		return nil, fmt.Errorf("%w: %w — raw body: %s",
			ErrMalformedResponse, err, truncate(raw, 256))
	}

	if !qr.Success {
		return nil, fmt.Errorf("joern: query failed: %s", truncate([]byte(qr.Stderr), 512))
	}

	return []byte(parseStdout(qr.Stdout)), nil
}

// doGet performs a GET request to the given path and returns the status code.
// Used exclusively for health checks (GET /ready).
func (c *Client) doGet(ctx context.Context, path string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+path, nil)
	if err != nil {
		return 0, fmt.Errorf("joern: build GET request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("joern: GET %s: %w", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// parseStdout extracts the JSON payload from a Joern stdout string.
// Joern's HTTP server may return:
//   - A bare JSON value:         [{"id":"1",...}]
//   - A Scala string literal:    "[{\"id\":\"1\",...}]"  (with outer quotes)
//   - A REPL-annotated value:    res0: String = "[{...}]"
//
// parseStdout normalises all three forms to the bare JSON value.
func parseStdout(s string) string {
	s = strings.TrimSpace(s)

	// REPL annotation: "res0: Type = <value>" — strip prefix up to " = "
	if idx := strings.Index(s, " = "); idx != -1 {
		s = strings.TrimSpace(s[idx+3:])
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

// truncate returns up to n bytes of b as a string, appending "…" if truncated.
func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
