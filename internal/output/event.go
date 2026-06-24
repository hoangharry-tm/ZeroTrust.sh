// Copyright 2026 Minh Hoang Ton
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

// Package output defines the event bus and renderer interface shared by all
// CLI output modes (minimal, tree, TUI). The pipeline writes Events onto a
// buffered channel; the active Renderer drains it and drives the display.
package output

import (
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// EventKind identifies what happened in the pipeline.
type EventKind string

const (
	// EventStageStart fires when a named pipeline stage begins.
	EventStageStart EventKind = "stage_start"
	// EventStageEnd fires when a named pipeline stage completes.
	EventStageEnd EventKind = "stage_end"
	// EventFinding fires once per finding emitted from either detection path.
	EventFinding EventKind = "finding"
	// EventLog fires for any free-text diagnostic message.
	EventLog EventKind = "log"
	// EventError fires when the pipeline encounters a non-fatal or fatal error.
	EventError EventKind = "error"
	// EventDone fires exactly once when the full scan (including report write) completes.
	EventDone EventKind = "done"
)

// StageSummary carries the completion statistics for one pipeline stage.
type StageSummary struct {
	Stage    string
	Elapsed  time.Duration
	Findings int
	// Detail is a short human-readable note, e.g. "42 rules · 3 findings".
	Detail string
}

// ScanSummary is the final scan-level summary emitted with EventDone.
type ScanSummary struct {
	Elapsed       time.Duration
	TotalFindings int
	BySeverity    map[finding.SeverityLabel]int
	ReportPath    string
}

// Event is a pipeline notification consumed by a Renderer.
// Only the fields relevant to Kind are set; the rest are zero values.
type Event struct {
	Kind    EventKind
	Stage   string    // set for EventStageStart / EventStageEnd
	Time    time.Time // always set
	Finding *finding.Finding
	Summary *StageSummary
	Done    *ScanSummary
	Log     string
	Err     error
}

// Emit sends e on ch without blocking. If ch is full the event is dropped
// rather than stalling the pipeline goroutine.
func Emit(ch chan<- Event, e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	select {
	case ch <- e:
	default:
	}
}
