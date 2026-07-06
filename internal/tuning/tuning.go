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

// Package tuning holds time.Duration constants that cannot be expressed in JSON
// without custom marshaling. All numeric thresholds, batch sizes, and scoring
// parameters live in internal/config instead.
package tuning

import "time"

// ── Joern subprocess timeouts ────────────────────────────────────────────────

const (
	JoernPingInterval       = 500 * time.Millisecond
	JoernPingTimeout        = 30 * time.Second
	JoernStopTimeout        = 5 * time.Second
	JoernQueryTimeout       = 30 * time.Second
	JoernBuildTimeout       = 900 * time.Second
	JoernResultPollInterval = 200 * time.Millisecond
	JoernScanStopTimeout    = 10 * time.Second
)

// JoernIdleTimeout is the max consecutive 202-polling duration with no
// state change before we treat Joern as frozen and surface ErrBuildTimeout.
// Set below JoernQueryTimeout (30 s) so freeze detection fires before the
// per-query context deadline — if Joern returns 202 for 20+ consecutive
// seconds it is likely in a GC-deadlock or OOM state.
const JoernIdleTimeout = 90 * time.Second

// ── Network / worker timeouts ────────────────────────────────────────────────

const (
	OllamaHTTPTimeout        = 120 * time.Second
	RekorHTTPTimeout         = 3 * time.Second
	KEVCacheTTL              = 24 * time.Hour
	SSVCNetTimeout           = 3 * time.Second
	WorkerStartPingTimeout   = 5 * time.Second
	WorkerRestartPingTimeout = 3 * time.Second
	WorkerShutdownTimeout    = 2 * time.Second
)
