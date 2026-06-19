package main

import (
	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/output/web"
)

// selectRenderer returns the Renderer for the given --output flag value.
//
// Rules:
//   - "minimal"     → MinimalRenderer (always, CI-safe plain text)
//   - "web"         → WebRenderer (always, live HTML dashboard)
//   - "" (auto)     → WebRenderer when stdout is a TTY; MinimalRenderer otherwise
//   - anything else → MinimalRenderer (safe fallback)
func selectRenderer(mode string) output.Renderer {
	switch mode {
	case "minimal":
		return output.NewMinimalRenderer()
	case "web":
		return web.NewRenderer()
	default:
		if output.IsTTY() {
			return web.NewRenderer()
		}
		return output.NewMinimalRenderer()
	}
}
