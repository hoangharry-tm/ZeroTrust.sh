// Package tui implements the Bubble Tea interactive TUI for zerotrust.
// It is selected via --output tui and renders a two-panel layout:
//   - Left panel:  pipeline stage progress (always visible)
//   - Right panel: tabbed content (log, findings, summary, suppressed, patches)
//
// Two states:
//   - scanning: live progress + log stream
//   - done:     navigable findings list + detail pane
package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/output"
)

const (
	tabLog        = 0
	tabFindings   = 1
	tabSummary    = 2
	tabSuppressed = 3
	tabPatches    = 4
	tabCount      = 5
)

// stageStatus tracks one pipeline stage.
type stageStatus struct {
	name    string
	state   string // "pending" | "running" | "done"
	detail  string
	elapsed time.Duration
}

// model is the Bubble Tea model.
type model struct {
	// scan state
	scanning bool
	done     bool
	events   <-chan output.Event

	// display
	activeTab int
	width     int
	height    int

	// stage progress (left panel)
	stages []stageStatus

	// tab content
	logLines   []string
	findings   []finding.Finding
	suppressed []finding.Finding
	summary    *output.ScanSummary

	// findings tab navigation
	cursor int

	// timing
	startTime time.Time
	elapsed   time.Duration

	// spinner frame (cycles during scan)
	spinFrame int

	exitCode int
}

// tickMsg fires on the 100 ms ticker to update elapsed + spinner.
type tickMsg time.Time

// eventMsg wraps a pipeline event received from the event channel.
type eventMsg struct{ e output.Event }

// doneMsg is sent when the event channel closes.
type doneMsg struct{}

// New returns an initialised Bubble Tea model wired to the pipeline event channel.
func New(events <-chan output.Event) model {
	return model{
		scanning:  true,
		events:    events,
		activeTab: tabLog,
		startTime: time.Now(),
		stages: []stageStatus{
			{name: "ingestion", state: "pending"},
			{name: "path a", state: "pending"},
			{name: "path b", state: "pending"},
		},
	}
}

// TUIRenderer wraps the Bubble Tea program and implements output.Renderer.
type TUIRenderer struct {
	events   <-chan output.Event
	exitCode int
}

// NewTUIRenderer constructs a TUIRenderer. Call Render to start the Bubble Tea loop.
func NewTUIRenderer() *TUIRenderer {
	// events channel is wired in by the caller via Render; placeholder nil here.
	return &TUIRenderer{}
}

// ExitCode implements output.Renderer.
func (r *TUIRenderer) ExitCode() int { return r.exitCode }

// Render implements output.Renderer. It starts the Bubble Tea event loop and
// blocks until the user quits or the scan finishes.
func (r *TUIRenderer) Render(_ context.Context, ch <-chan output.Event) error {
	m := New(ch)
	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("tui: %w", err)
	}
	if fm, ok := finalModel.(model); ok {
		r.exitCode = fm.exitCode
	}
	return nil
}
