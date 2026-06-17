package output

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// TreeRenderer writes a tree-structured, coloured log stream to stdout.
// It is the default mode when stdout is a TTY. Unlike the TUI it does not use
// an alternate screen — output scrolls naturally in the terminal.
//
// Layout:
//
//	zerotrust v0.1.0 — <project>
//
//	  ┌ ingestion
//	  │  ✓ model     qwen2.5-3b · sha256:a3f9e1 · verified
//	  │  ✓ diff      4 changed · 18 unchanged
//	  └
//
//	  ┌ findings
//	  │  ✖ BLOCK   UserController.java:42    sql-injection-jdbc    CWE-89
//	  │  ● HIGH    config.py:11              hardcoded-ai-api-key  CWE-798
//	  └
//
//	  4 findings · 1 BLOCK · 2 HIGH · 1 MEDIUM · 2.3s
//	  report → build/report.html
type TreeRenderer struct {
	exitCode    int
	startTime   time.Time
	bySeverity  map[finding.SeverityLabel]int
	reportPath  string
	inSection   bool // true while inside a ┌…└ block
	sectionName string
}

// lipgloss styles — defined at package level so they're initialised once.
var (
	styleSectionHeader = lipgloss.NewStyle().Bold(true)
	styleBoxLine       = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleBlock         = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	styleHigh          = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	styleMedium        = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	styleLow           = lipgloss.NewStyle()
	styleSuppressed    = lipgloss.NewStyle().Faint(true)
	styleCheck         = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	styleDim           = lipgloss.NewStyle().Faint(true)
)

// NewTreeRenderer constructs a TreeRenderer.
func NewTreeRenderer() *TreeRenderer {
	return &TreeRenderer{
		startTime:  time.Now(),
		bySeverity: make(map[finding.SeverityLabel]int),
	}
}

// ExitCode implements Renderer.
func (r *TreeRenderer) ExitCode() int { return r.exitCode }

// Render implements Renderer.
func (r *TreeRenderer) Render(ctx context.Context, ch <-chan Event) error {
	r.printf("zerotrust v0.1.0\n\n")

	for {
		select {
		case <-ctx.Done():
			if r.inSection {
				r.closeSection()
			}
			return ctx.Err()
		case e, ok := <-ch:
			if !ok {
				if r.inSection {
					r.closeSection()
				}
				r.printSummary()
				return nil
			}
			r.handle(e)
		}
	}
}

func (r *TreeRenderer) handle(e Event) {
	switch e.Kind {
	case EventStageStart:
		if r.inSection {
			r.closeSection()
		}
		r.openSection(e.Stage)

	case EventStageEnd:
		if e.Summary != nil && e.Summary.Detail != "" {
			r.printLine(styleCheck.Render("✓")+" "+fmt.Sprintf("%-10s", e.Stage), e.Summary.Detail)
		}

	case EventLog:
		r.printLine(styleDim.Render("·"), e.Log)

	case EventFinding:
		if e.Finding == nil {
			return
		}
		f := e.Finding
		r.bySeverity[f.SeverityLabel]++
		if !r.inSection || r.sectionName != "findings" {
			if r.inSection {
				r.closeSection()
			}
			r.openSection("findings")
		}
		icon, sev := r.severityParts(f.SeverityLabel)
		loc := fmt.Sprintf("%s:%d", f.Path, f.LineRange.Start)
		r.printLine(icon+" "+sev, fmt.Sprintf("%-40s %s  %s", loc, f.RuleID, styleDim.Render(f.CWE)))

	case EventError:
		if e.Err != nil {
			r.printLine(lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render("✖"), e.Err.Error())
			r.exitCode = 2
		}

	case EventDone:
		if e.Done != nil {
			r.reportPath = e.Done.ReportPath
		}
	}
}

func (r *TreeRenderer) openSection(name string) {
	r.inSection = true
	r.sectionName = name
	header := styleSectionHeader.Render(name)
	r.printf("  %s %s\n", styleBoxLine.Render("┌"), header)
}

func (r *TreeRenderer) closeSection() {
	r.printf("  %s\n\n", styleBoxLine.Render("└"))
	r.inSection = false
	r.sectionName = ""
}

func (r *TreeRenderer) printLine(prefix, content string) {
	r.printf("  %s  %s %s\n", styleBoxLine.Render("│"), prefix, content)
}

func (r *TreeRenderer) printSummary() {
	total := 0
	for _, n := range r.bySeverity {
		total += n
	}
	elapsed := time.Since(r.startTime).Round(time.Millisecond)

	parts := []string{fmt.Sprintf("%d findings", total)}
	for _, sev := range []finding.SeverityLabel{
		finding.SeverityBlock,
		finding.SeverityHigh,
		finding.SeverityMedium,
		finding.SeverityLow,
		finding.SeveritySuppressed,
	} {
		if n := r.bySeverity[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(string(sev))))
		}
	}
	parts = append(parts, elapsed.String())
	r.printf("  %s\n", strings.Join(parts, " · "))

	if r.reportPath != "" {
		r.printf("  report → %s\n", r.reportPath)
	}

	if r.exitCode == 0 {
		if r.bySeverity[finding.SeverityBlock] > 0 || r.bySeverity[finding.SeverityHigh] > 0 {
			r.exitCode = 1
		}
	}
}

func (r *TreeRenderer) printf(format string, a ...any) {
	fmt.Fprintf(os.Stdout, format, a...)
}

func (r *TreeRenderer) severityParts(sev finding.SeverityLabel) (icon, label string) {
	switch sev {
	case finding.SeverityBlock:
		return styleBlock.Render("✖"), styleBlock.Render("BLOCK ")
	case finding.SeverityHigh:
		return styleHigh.Render("●"), styleHigh.Render("HIGH  ")
	case finding.SeverityMedium:
		return styleMedium.Render("●"), styleMedium.Render("MEDIUM")
	case finding.SeverityLow:
		return styleLow.Render("○"), "LOW   "
	default:
		return styleSuppressed.Render("–"), styleSuppressed.Render("SUPPRESSED")
	}
}
