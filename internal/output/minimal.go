// Copyright 2026 hoangharry-tm
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

package output

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/mattn/go-isatty"
)

// MinimalRenderer writes plain-text progress and findings to stdout.
// ANSI colours are emitted only when stdout is a TTY; stripped otherwise,
// making this safe for CI pipelines, pipes, and file redirection.
//
// Output format:
//
//	zerotrust v0.1.0  <project>  <mode>
//
//	» ingestion
//	  model   qwen2.5-3b · verified
//	  diff    4 files changed
//
//	» findings
//	  BLOCK  CWE-89  UserController.java:42  sql-injection-jdbc
//
//	4 findings  (1 BLOCK · 2 HIGH · 1 MEDIUM)  2.3s
//	report → build/report.html
type MinimalRenderer struct {
	exitCode   int
	hasColor   bool
	startTime  time.Time
	bySeverity map[finding.SeverityLabel]int
	reportPath string
}

// NewMinimalRenderer constructs a MinimalRenderer. Color is enabled only when
// stdout is a real TTY.
func NewMinimalRenderer() *MinimalRenderer {
	return &MinimalRenderer{
		hasColor:   isatty.IsTerminal(os.Stdout.Fd()),
		startTime:  time.Now(),
		bySeverity: make(map[finding.SeverityLabel]int),
	}
}

// ExitCode implements Renderer.
func (r *MinimalRenderer) ExitCode() int { return r.exitCode }

// Render implements Renderer. It blocks until ch is closed or ctx is cancelled.
func (r *MinimalRenderer) Render(ctx context.Context, ch <-chan Event) error {
	// Disable color globally for this renderer when not a TTY.
	if !r.hasColor {
		color.NoColor = true
	}

	r.printf("zerotrust v0.1.0\n\n")

	currentStage := ""

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-ch:
			if !ok {
				r.printSummary()
				return nil
			}
			r.handle(e, &currentStage)
		}
	}
}

func (r *MinimalRenderer) handle(e Event, currentStage *string) {
	switch e.Kind {
	case EventStageStart:
		if *currentStage != "" {
			r.printf("\n")
		}
		*currentStage = e.Stage
		r.printf("» %s\n", e.Stage)

	case EventStageEnd:
		if e.Summary != nil && e.Summary.Detail != "" {
			r.printf("  %-10s %s\n", e.Stage, e.Summary.Detail)
		}

	case EventLog:
		r.printf("  %s\n", e.Log)

	case EventFinding:
		if e.Finding == nil {
			return
		}
		f := e.Finding
		r.bySeverity[f.SeverityLabel]++
		loc := fmt.Sprintf("%s:%d", f.Path, f.LineRange.Start)
		label := r.severityLabel(f.SeverityLabel)
		r.printf("  %-10s %-8s %-40s %s\n", label, f.CWE, loc, f.RuleID)

	case EventError:
		if e.Err != nil {
			r.printf("  error: %s\n", e.Err)
			r.exitCode = 2
		}

	case EventDone:
		if e.Done != nil {
			r.reportPath = e.Done.ReportPath
		}
	}
}

func (r *MinimalRenderer) printSummary() {
	total := 0
	for _, n := range r.bySeverity {
		total += n
	}

	elapsed := time.Since(r.startTime).Round(time.Millisecond)

	parts := []string{}
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

	r.printf("\n")
	if len(parts) > 0 {
		r.printf("%d findings  (%s)  %s\n", total, strings.Join(parts, " · "), elapsed)
	} else {
		r.printf("0 findings  %s\n", elapsed)
	}

	if r.reportPath != "" {
		r.printf("report → %s\n", r.reportPath)
	}

	// Set exit code: 1 if any BLOCK or HIGH finding exists.
	if r.exitCode == 0 {
		if r.bySeverity[finding.SeverityBlock] > 0 || r.bySeverity[finding.SeverityHigh] > 0 {
			r.exitCode = 1
		}
	}
}

func (r *MinimalRenderer) printf(format string, a ...any) {
	fmt.Fprintf(os.Stdout, format, a...)
}

// severityLabel returns an optionally coloured severity string.
func (r *MinimalRenderer) severityLabel(sev finding.SeverityLabel) string {
	if !r.hasColor {
		return string(sev)
	}
	switch sev {
	case finding.SeverityBlock:
		return color.New(color.FgRed, color.Bold).Sprint(string(sev))
	case finding.SeverityHigh:
		return color.New(color.FgRed).Sprint(string(sev))
	case finding.SeverityMedium:
		return color.New(color.FgYellow).Sprint(string(sev))
	case finding.SeverityLow:
		return string(sev)
	default:
		return color.New(color.Faint).Sprint(string(sev))
	}
}
