package output

import "context"

// Renderer consumes pipeline events and drives the CLI display for one scan.
// Implementations: MinimalRenderer, TreeRenderer, TUIRenderer.
type Renderer interface {
	// Render blocks until ch is closed (scan complete) or ctx is cancelled.
	Render(ctx context.Context, ch <-chan Event) error
	// ExitCode returns the process exit code after Render returns.
	//   0 — no BLOCK or HIGH findings
	//   1 — one or more BLOCK/HIGH findings (CI gate)
	//   2 — scan error (tool failure, pipeline error)
	ExitCode() int
}
