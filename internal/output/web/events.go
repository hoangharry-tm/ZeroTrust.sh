package web

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/output"
)

// eventToSSE converts a pipeline Event to a (sseEventName, htmlFragment) pair.
// Returns ("", "") for event kinds that produce no browser update.
func eventToSSE(e output.Event) (string, string) {
	switch e.Kind {
	case output.EventStageStart:
		return "stage", stageStartHTML(e.Stage)
	case output.EventStageEnd:
		if e.Summary != nil && e.Summary.Detail != "" {
			return "stage", stageLineHTML(e.Summary.Stage, e.Summary.Detail, e.Summary.Elapsed)
		}
		return "", ""
	case output.EventFinding:
		if e.Finding == nil {
			return "", ""
		}
		return "finding", findingCardHTML(e.Finding)
	case output.EventLog:
		if e.Log == "" {
			return "", ""
		}
		return "log", logRowHTML("info", "scan", e.Log, nil)
	case output.EventError:
		if e.Err == nil {
			return "", ""
		}
		return "log", logRowHTML("err", "scan", e.Err.Error(), nil)
	case output.EventDone:
		if e.Done == nil {
			return "", ""
		}
		return "summary", summaryHTML(e.Done)
	}
	return "", ""
}

func stageStartHTML(name string) string {
	return fmt.Sprintf(
		`<div class="stage-block"><div class="stage-header"><span class="arrow">=&gt;</span> %s</div></div>`,
		html.EscapeString(name),
	)
}

func stageLineHTML(name, detail string, elapsed time.Duration) string {
	return fmt.Sprintf(
		`<div class="stage-line"><span class="ok">✓</span><span class="key">%s</span><span class="val">%s · %s</span></div>`,
		html.EscapeString(name),
		html.EscapeString(detail),
		elapsed.Round(time.Millisecond),
	)
}

func findingCardHTML(f *finding.Finding) string {
	sevClass := sevCSS(f.SeverityLabel)
	label := strings.ToUpper(string(f.SeverityLabel))
	loc := fmt.Sprintf("%s:%d", f.Path, f.LineRange.Start)
	return fmt.Sprintf(
		`<div class="finding-card fade-in" data-sev="%s" onclick="toggleFinding(this)"><div class="finding-main"><div class="sev-bar sev-%s"></div><div class="finding-meta"><div class="finding-top"><span class="sev-label %s">%s</span><span class="finding-rule">%s</span></div><div class="finding-loc">%s</div></div><span class="finding-cwe">%s</span></div><div class="finding-detail" onclick="event.stopPropagation()"><div class="detail-row"><span class="detail-key">path</span><span class="detail-val highlight">%s</span></div><div class="detail-row"><span class="detail-key">cwe</span><span class="detail-val">%s</span></div><div class="detail-row"><span class="detail-key">confidence</span><span class="detail-val">%.2f</span></div><div class="detail-row"><span class="detail-key">detail</span><span class="detail-val">%s</span></div></div></div>`,
		sevClass, sevClass, sevClass, label,
		html.EscapeString(f.RuleID),
		html.EscapeString(loc),
		html.EscapeString(f.CWE),
		html.EscapeString(loc),
		html.EscapeString(f.CWE),
		f.Confidence,
		html.EscapeString(f.Justification),
	)
}

// logRowHTML produces a .log-row element matching the terminal-noir style from the design.
// attrs is a flat key→value map of slog structured fields.
func logRowHTML(level, component, msg string, attrs map[string]string) string {
	lvLabel := map[string]string{
		"debug": "DBG",
		"info":  "─",
		"warn":  "WRN",
		"err":   "ERR",
	}[level]
	if lvLabel == "" {
		lvLabel = "─"
	}

	ts := time.Now().Format("15:04:05")

	var attrsHTML strings.Builder
	for k, v := range attrs {
		fmt.Fprintf(&attrsHTML,
			`<span class="log-kv"><span class="log-key">%s</span><span class="log-val">%s</span></span>`,
			html.EscapeString(k), html.EscapeString(v),
		)
	}

	return fmt.Sprintf(
		`<div class="log-row log-row--%s fade-in" role="log"><span class="log-lv">%s</span><span class="log-ts">%s</span><span class="log-comp">%s</span><span class="log-body">%s%s</span></div>`,
		level, lvLabel, ts,
		html.EscapeString(component),
		html.EscapeString(msg),
		attrsHTML.String(),
	)
}

func summaryHTML(s *output.ScanSummary) string {
	parts := []string{}
	for _, sev := range []finding.SeverityLabel{
		finding.SeverityBlock,
		finding.SeverityHigh,
		finding.SeverityMedium,
		finding.SeverityLow,
	} {
		if n := s.BySeverity[sev]; n > 0 {
			cls := sevCSS(sev)
			parts = append(parts, fmt.Sprintf(`<span class="stat"><span class="stat-num %s">%d</span> %s</span>`, cls, n, strings.ToUpper(string(sev))))
		}
	}
	elapsed := s.Elapsed.Round(time.Millisecond)
	left := strings.Join(parts, `<span class="sep">·</span>`)
	right := ""
	if s.ReportPath != "" {
		right = fmt.Sprintf(`<a class="report-link" href="/report">report → %s</a>`, html.EscapeString(s.ReportPath))
	}
	// JSON-encoded as a struct so the browser JS can update both sides.
	return fmt.Sprintf(`{"left":%q,"right":%q,"elapsed":%q}`, left, right, elapsed.String())
}

func sevCSS(sev finding.SeverityLabel) string {
	switch sev {
	case finding.SeverityBlock:
		return "block"
	case finding.SeverityHigh:
		return "high"
	case finding.SeverityMedium:
		return "medium"
	case finding.SeverityLow:
		return "low"
	default:
		return "low"
	}
}
