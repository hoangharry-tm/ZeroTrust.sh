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

package contracts

import (
	"strings"
	"testing"
)

// TestNoZeroSafetyAnchorCollisions catches the specific failure mode that hit
// CWE-94/CWE-78 during the language-expansion pass: a CWE with no SafeNodes
// (any anchor match is an unconditional Violation, per the verdict tie-break
// which unconditionally prefers Violation over Safe) whose anchor is a
// substring of another CWE's anchor silently overrides that CWE's correct
// verdict. This is a permanent regression guard, not a one-off script.
func TestNoZeroSafetyAnchorCollisions(t *testing.T) {
	for cweA, invA := range Rulebook {
		if !invA.NoSinkModel && len(invA.SafeNodes) > 0 {
			continue // only zero-safety CWEs can catastrophically override another verdict
		}
		for _, anchorA := range invA.SinkAnchors {
			for cweB, invB := range Rulebook {
				if cweA == cweB {
					continue
				}
				for _, anchorB := range invB.SinkAnchors {
					if anchorA == anchorB {
						continue // exact duplicates across CWEs are a separate, non-catastrophic concern
					}
					if strings.Contains(anchorB, anchorA) {
						t.Errorf("%s anchor %q (zero-safety CWE) is a substring of %s anchor %q — "+
							"any %s match will also match %s and, since %s has no SafeNodes, silently "+
							"override %s's verdict with an unconditional Violation",
							cweA, anchorA, cweB, anchorB, cweB, cweA, cweA, cweB)
					}
				}
			}
		}
	}
}
