package main

import (
	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/output/tui"
)

// selectRenderer returns the Renderer for the given --output flag value.
//
// Rules:
//   - "minimal"     → MinimalRenderer (always)
//   - "tree"        → TreeRenderer (always)
//   - "tui"         → TUIRenderer (always)
//   - "" (auto)     → TreeRenderer when stdout is a TTY; MinimalRenderer otherwise
//   - anything else → MinimalRenderer (safe fallback)
func selectRenderer(mode string) output.Renderer {
	switch mode {
	case "minimal":
		return output.NewMinimalRenderer()
	case "tree":
		return output.NewTreeRenderer()
	case "tui":
		return tui.NewTUIRenderer()
	default:
		if output.IsTTY() {
			return output.NewTreeRenderer()
		}
		return output.NewMinimalRenderer()
	}
}
