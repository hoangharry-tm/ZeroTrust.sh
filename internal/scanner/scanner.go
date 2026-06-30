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

// Package scanner defines the Scanner interface implemented by each tool driver.
package scanner

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/detector"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// Scanner is the contract every tool driver must satisfy.
// Implementations live in sub-packages (opengrep, gitleaks, osv).
//
// This dispatcher contract is the architectural framework for the Post-MVP
// Option 1 "Mason-style" local tool binary manager: each Scanner wraps a
// binary that Mason will download, verify, and pin. The orchestrator stays
// binary-agnostic — it only calls Name/Supports/Scan.
type Scanner interface {
	// Name returns a short stable identifier used in logs and metrics.
	Name() string
	// Supports reports whether this scanner applies to the given stack.
	// Return false to skip invocation; the orchestrator will not call Scan.
	Supports(stack detector.StackProfile) bool
	// Scan runs the tool against target and returns structured findings.
	// Implementations must respect ctx cancellation/deadline.
	Scan(ctx context.Context, target string) ([]finding.Finding, error)
}
