package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/output"
)

const leftPanelWidth = 32

// Styles.
var (
	styleTitle    = lipgloss.NewStyle().Bold(true)
	styleBorder   = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleTabActive   = lipgloss.NewStyle().Bold(true).Underline(true)
	styleTabInactive = lipgloss.NewStyle().Faint(true)

	styleSevBlock = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	styleSevHigh  = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleSevMed   = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	styleSevLow   = lipgloss.NewStyle()
	styleSevSupp  = lipgloss.NewStyle().Faint(true)

	styleDone    = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	styleRunning = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	stylePending = lipgloss.NewStyle().Faint(true)
	styleSelected = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
)

// View renders the full terminal frame.
func (m model) View() string {
	if m.width == 0 {
		return "loading…"
	}

	left := m.renderLeft()
	right := m.renderRight()

	// Join panels side by side.
	leftLines := strings.Split(left, "\n")
	rightLines := strings.Split(right, "\n")

	maxLines := max(len(leftLines), len(rightLines))
	for len(leftLines) < maxLines {
		leftLines = append(leftLines, strings.Repeat(" ", leftPanelWidth))
	}
	for len(rightLines) < maxLines {
		rightLines = append(rightLines, "")
	}

	var sb strings.Builder
	for i := 0; i < maxLines; i++ {
		left := leftLines[i]
		// Pad left panel to fixed width (strip ANSI for width calc via lipgloss).
		padded := lipgloss.NewStyle().Width(leftPanelWidth).Render(left)
		sb.WriteString(padded)
		sb.WriteString("  ")
		sb.WriteString(rightLines[i])
		sb.WriteString("\n")
	}

	// Status bar at bottom.
	statusLine := m.renderStatusBar()
	return sb.String() + "\n" + statusLine
}

// renderLeft builds the left pipeline-progress panel.
func (m model) renderLeft() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("ZeroTrust.sh v0.1.0") + "\n")
	sb.WriteString(styleBorder.Render(strings.Repeat("─", leftPanelWidth-2)) + "\n\n")

	for _, s := range m.stages {
		var marker, detail string
		switch s.state {
		case "done":
			marker = styleDone.Render("✓")
			detail = s.detail
		case "running":
			marker = styleRunning.Render(spinFrames[m.spinFrame])
			detail = "running…"
		default:
			marker = stylePending.Render("·")
		}
		line := fmt.Sprintf("%s %-14s %s", marker, s.name, stylePending.Render(detail))
		sb.WriteString(line + "\n")
	}

	sb.WriteString("\n")

	if m.done {
		sb.WriteString(styleDone.Render("DONE") + "  " + m.elapsed.Round(1e6).String() + "\n\n")
		sb.WriteString(fmt.Sprintf("%d findings\n", len(m.findings)))
		sb.WriteString(fmt.Sprintf("%d BLOCK\n", m.countBySeverity(finding.SeverityBlock)))
		sb.WriteString(fmt.Sprintf("%d HIGH\n", m.countBySeverity(finding.SeverityHigh)))
		sb.WriteString(fmt.Sprintf("%d MEDIUM\n", m.countBySeverity(finding.SeverityMedium)))
		sb.WriteString(fmt.Sprintf("%d LOW\n", m.countBySeverity(finding.SeverityLow)))
		if m.summary != nil && m.summary.ReportPath != "" {
			sb.WriteString("\nreport →\n" + stylePending.Render(m.summary.ReportPath) + "\n")
		}
	} else {
		progress := m.renderProgressBar()
		sb.WriteString("\n" + progress + "\n")
	}

	return sb.String()
}

// renderProgressBar returns a simple ASCII progress bar (0–100).
func (m model) renderProgressBar() string {
	width := leftPanelWidth - 4
	filled := (m.spinFrame * width) / len(spinFrames) // animate during scan
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return styleBorder.Render("[") + styleRunning.Render(bar) + styleBorder.Render("]")
}

// renderRight builds the right tabbed panel.
func (m model) renderRight() string {
	rightWidth := m.width - leftPanelWidth - 4
	if rightWidth < 20 {
		rightWidth = 20
	}

	header := m.renderTabHeader()
	divider := styleBorder.Render(strings.Repeat("─", rightWidth))

	var content string
	switch m.activeTab {
	case tabLog:
		content = m.renderLog(rightWidth)
	case tabFindings:
		content = m.renderFindings(rightWidth)
	case tabSummary:
		content = m.renderSummary(rightWidth)
	case tabSuppressed:
		content = m.renderSuppressed(rightWidth)
	case tabPatches:
		content = m.renderPatches(rightWidth)
	}

	return header + "\n" + divider + "\n" + content
}

func (m model) renderTabHeader() string {
	tabs := []struct {
		key   string
		label string
		idx   int
	}{
		{"1", "log", tabLog},
		{"2", "findings", tabFindings},
		{"3", "summary", tabSummary},
		{"4", "suppressed", tabSuppressed},
		{"5", "patches", tabPatches},
	}

	var parts []string
	for _, t := range tabs {
		label := fmt.Sprintf("[%s:%s]", t.key, t.label)
		if t.idx == m.activeTab {
			parts = append(parts, styleTabActive.Render(label))
		} else {
			parts = append(parts, styleTabInactive.Render(label))
		}
	}
	return strings.Join(parts, " ")
}

func (m model) renderLog(width int) string {
	if len(m.logLines) == 0 {
		return stylePending.Render("no log entries yet…")
	}
	// Show tail of log lines that fit in the panel.
	maxLines := m.height - 6
	if maxLines < 1 {
		maxLines = 10
	}
	lines := m.logLines
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	var sb strings.Builder
	for _, l := range lines {
		if len(l) > width {
			l = l[:width]
		}
		sb.WriteString(l + "\n")
	}
	return sb.String()
}

func (m model) renderFindings(width int) string {
	if len(m.findings) == 0 {
		if m.scanning {
			return stylePending.Render("scanning…")
		}
		return styleDone.Render("no findings")
	}

	var sb strings.Builder
	for i, f := range m.findings {
		icon, sev := severityStyle(f.SeverityLabel)
		loc := fmt.Sprintf("%s:%d", f.Path, f.LineRange.Start)
		line := fmt.Sprintf("%s  %-8s %-35s %s", icon, sev, loc, f.RuleID)
		if len(line) > width {
			line = line[:width]
		}
		if i == m.cursor {
			sb.WriteString(styleSelected.Render("> "+line) + "\n")
		} else {
			sb.WriteString("  " + line + "\n")
		}
	}

	// Detail pane for selected finding.
	if m.cursor < len(m.findings) {
		f := m.findings[m.cursor]
		sb.WriteString("\n" + styleBorder.Render(strings.Repeat("─", width)) + "\n")
		sb.WriteString(fmt.Sprintf("> %s:%d  %s  confidence %.2f\n", f.Path, f.LineRange.Start, f.CWE, f.Confidence))
		if f.MatchedCode != "" {
			sb.WriteString("\n" + stylePending.Render(f.MatchedCode) + "\n")
		}
		if f.Justification != "" {
			sb.WriteString("\n" + f.Justification + "\n")
		}
		sb.WriteString("\n" + stylePending.Render("[p] view patch   [s] suppress   [o] open in report") + "\n")
	}

	return sb.String()
}

func (m model) renderSummary(_ int) string {
	if m.summary == nil {
		return stylePending.Render("scan in progress…")
	}
	s := m.summary
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("duration     %s\n", s.Elapsed.Round(1e6)))
	sb.WriteString(fmt.Sprintf("total        %d findings\n", s.TotalFindings))
	for _, sev := range []finding.SeverityLabel{
		finding.SeverityBlock, finding.SeverityHigh, finding.SeverityMedium,
		finding.SeverityLow, finding.SeveritySuppressed,
	} {
		if n := s.BySeverity[sev]; n > 0 {
			sb.WriteString(fmt.Sprintf("  %-12s %d\n", strings.ToLower(string(sev)), n))
		}
	}
	if s.ReportPath != "" {
		sb.WriteString("\nreport → " + s.ReportPath + "\n")
	}
	return sb.String()
}

func (m model) renderSuppressed(_ int) string {
	if len(m.suppressed) == 0 {
		return styleDone.Render("no suppressed findings")
	}
	var sb strings.Builder
	for _, f := range m.suppressed {
		sb.WriteString(fmt.Sprintf("%-12s %s:%d  %s\n",
			string(f.SuppressReason), f.Path, f.LineRange.Start, f.CWE))
	}
	return sb.String()
}

func (m model) renderPatches(_ int) string {
	return stylePending.Render("patches generated after scan completes (L4)")
}

func (m model) renderStatusBar() string {
	var right string
	if m.scanning {
		right = "esc cancel · q quit"
	} else {
		right = "↑↓ navigate · p patch · s suppress · tab switch · q quit"
	}
	elapsed := m.elapsed.Round(1e6).String()
	state := "scanning"
	if m.done {
		state = "done"
	}
	return stylePending.Render(fmt.Sprintf("%s · %s", state, elapsed)) +
		"   " + stylePending.Render(right)
}

func severityStyle(sev finding.SeverityLabel) (icon, label string) {
	switch sev {
	case finding.SeverityBlock:
		return styleSevBlock.Render("✖"), styleSevBlock.Render("BLOCK")
	case finding.SeverityHigh:
		return styleSevHigh.Render("●"), styleSevHigh.Render("HIGH ")
	case finding.SeverityMedium:
		return styleSevMed.Render("●"), styleSevMed.Render("MED  ")
	case finding.SeverityLow:
		return styleSevLow.Render("○"), "LOW  "
	default:
		return styleSevSupp.Render("–"), styleSevSupp.Render("SUPP ")
	}
}

// renderSummary helper for output.ScanSummary nil-safety.
func renderScanSummaryNil(s *output.ScanSummary) string {
	if s == nil {
		return ""
	}
	return s.ReportPath
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
