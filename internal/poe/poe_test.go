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

package poe

import (
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

func TestParseSeverityLabel_KnownNames(t *testing.T) {
	cases := map[string]finding.SeverityLabel{
		"BLOCK":      finding.SeverityBlock,
		"HIGH":       finding.SeverityHigh,
		"MEDIUM":     finding.SeverityMedium,
		"LOW":        finding.SeverityLow,
		"SUPPRESSED": finding.SeveritySuppressed,
	}
	for name, want := range cases {
		got, ok := parseSeverityLabel(name)
		if !ok || got != want {
			t.Errorf("parseSeverityLabel(%q) = (%v, %v), want (%v, true)", name, got, ok, want)
		}
	}
}

func TestParseSeverityLabel_UnknownName_ReturnsFalse(t *testing.T) {
	// Must not silently return SeverityBlock (the zero value) for garbage input.
	if _, ok := parseSeverityLabel("NOT_A_SEVERITY"); ok {
		t.Fatal("parseSeverityLabel(garbage) = true, want false")
	}
	if _, ok := parseSeverityLabel(""); ok {
		t.Fatal("parseSeverityLabel(\"\") = true, want false")
	}
}

func TestPartitionEligible_RespectsConfiguredMinSeverity(t *testing.T) {
	orig := config.C
	defer func() { config.C = orig }()
	config.C.PoEMinSeverity = "BLOCK" // stricter than the compile-time default (HIGH)
	config.C.PoESupportedLanguages = []string{"java"}

	findings := []finding.Finding{
		{Path: "A.java", SeverityLabel: finding.SeverityBlock},
		{Path: "B.java", SeverityLabel: finding.SeverityHigh}, // now ineligible under the stricter policy
	}
	eligible, ineligible := partitionEligible(findings)

	if len(eligible) != 1 || eligible[0] != 0 {
		t.Fatalf("expected only index 0 eligible, got %v", eligible)
	}
	if ineligible[1] != finding.PoENotAttempted {
		t.Errorf("expected index 1 marked PoENotAttempted under BLOCK-only policy, got %v", ineligible[1])
	}
}

func TestPartitionEligible_RespectsConfiguredLanguageList(t *testing.T) {
	orig := config.C
	defer func() { config.C = orig }()
	config.C.PoEMinSeverity = "HIGH"
	config.C.PoESupportedLanguages = []string{"go"} // narrower than the compile-time default

	findings := []finding.Finding{
		{Path: "main.go", SeverityLabel: finding.SeverityHigh},
		{Path: "app.py", SeverityLabel: finding.SeverityHigh},
	}
	eligible, ineligible := partitionEligible(findings)

	if len(eligible) != 1 || eligible[0] != 0 {
		t.Fatalf("expected only the .go finding eligible, got %v", eligible)
	}
	if ineligible[1] != finding.PoELanguageUnsupported {
		t.Errorf("expected the .py finding marked PoELanguageUnsupported, got %v", ineligible[1])
	}
}
