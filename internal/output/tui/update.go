package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/output"
)

var spinFrames = []string{"⠋", "⠙", "⠸", "⠴", "⠦", "⠇"}

// Init starts the ticker and begins draining the event channel.
func (m model) Init() tea.Cmd {
	return tea.Batch(tick(), drainEvents(m.events))
}

// Update handles all Bubble Tea messages.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		m.elapsed = time.Since(m.startTime)
		m.spinFrame = (m.spinFrame + 1) % len(spinFrames)
		return m, tick()

	case eventMsg:
		m = m.applyEvent(msg.e)
		return m, drainEvents(m.events)

	case doneMsg:
		m.scanning = false
		m.done = true
		if m.exitCode == 0 {
			if m.countBySeverity(finding.SeverityBlock) > 0 || m.countBySeverity(finding.SeverityHigh) > 0 {
				m.exitCode = 1
			}
		}
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (model, tea.Cmd) {
	switch msg.String() {
	case "q", "Q":
		return m, tea.Quit
	case "esc":
		if m.scanning {
			return m, tea.Quit
		}
	case "1":
		m.activeTab = tabLog
	case "2":
		m.activeTab = tabFindings
	case "3":
		m.activeTab = tabSummary
	case "4":
		m.activeTab = tabSuppressed
	case "5":
		m.activeTab = tabPatches
	case "tab":
		m.activeTab = (m.activeTab + 1) % tabCount
	case "up", "k":
		if m.activeTab == tabFindings && m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.activeTab == tabFindings && m.cursor < len(m.findings)-1 {
			m.cursor++
		}
	}
	return m, nil
}

func (m model) applyEvent(e output.Event) model {
	// Always append to log.
	m.logLines = append(m.logLines, formatLogLine(e))

	switch e.Kind {
	case output.EventStageStart:
		m = m.setStageState(e.Stage, "running", "")

	case output.EventStageEnd:
		detail := ""
		if e.Summary != nil {
			detail = e.Summary.Detail
		}
		m = m.setStageState(e.Stage, "done", detail)

	case output.EventFinding:
		if e.Finding != nil {
			if e.Finding.SeverityLabel == finding.SeveritySuppressed {
				m.suppressed = append(m.suppressed, *e.Finding)
			} else {
				m.findings = append(m.findings, *e.Finding)
			}
		}

	case output.EventError:
		if e.Err != nil {
			m.exitCode = 2
		}

	case output.EventDone:
		if e.Done != nil {
			m.summary = e.Done
		}
	}

	return m
}

func (m model) setStageState(name, state, detail string) model {
	for i := range m.stages {
		if m.stages[i].name == name {
			m.stages[i].state = state
			m.stages[i].detail = detail
			return m
		}
	}
	// Stage not pre-registered — append it.
	m.stages = append(m.stages, stageStatus{name: name, state: state, detail: detail})
	return m
}

func (m model) countBySeverity(sev finding.SeverityLabel) int {
	count := 0
	for _, f := range m.findings {
		if f.SeverityLabel == sev {
			count++
		}
	}
	return count
}

func tick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// drainEvents reads one event from ch without blocking and returns it as a Cmd.
// When ch is closed it returns doneMsg.
func drainEvents(ch <-chan output.Event) tea.Cmd {
	return func() tea.Msg {
		e, ok := <-ch
		if !ok {
			return doneMsg{}
		}
		return eventMsg{e}
	}
}

func formatLogLine(e output.Event) string {
	ts := e.Time.Format("15:04:05")
	switch e.Kind {
	case output.EventStageStart:
		return ts + "  [" + e.Stage + "]  started"
	case output.EventStageEnd:
		if e.Summary != nil {
			return ts + "  [" + e.Stage + "]  " + e.Summary.Detail
		}
		return ts + "  [" + e.Stage + "]  done"
	case output.EventFinding:
		if e.Finding != nil {
			return ts + "  [finding]  " + string(e.Finding.SeverityLabel) + "  " + e.Finding.Path
		}
	case output.EventLog:
		return ts + "  " + e.Log
	case output.EventError:
		if e.Err != nil {
			return ts + "  [error]  " + e.Err.Error()
		}
	case output.EventDone:
		return ts + "  [done]  scan complete"
	}
	return ts + "  " + string(e.Kind)
}
