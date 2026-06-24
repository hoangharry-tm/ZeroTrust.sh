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

// Surface priority ranking (T1).
//
// Priority formula:  w1×(cvss/10) + w2×(1−confidence) + w3×(1/depth)
//
// Rationale for each term:
//   - CVSS/10: normalises raw CVSS (0–10) to 0–1 so weights are comparable.
//   - 1−confidence: high uncertainty increases priority — the LLM adds the most
//     value where the classifier is least certain.
//   - 1/depth: surfaces closer to external-input nodes (lower depth) are more
//     reachable by an attacker; they should be scanned first.

package budget

import (
	"github.com/hoangharry-tm/zerotrust/internal/semantic/summarizer"
	"github.com/hoangharry-tm/zerotrust/internal/tuning"
)

// computePriority applies the surface ranking formula.
// callGraphDepth ≤ 0 is treated as 1 (unknown reachability → maximum weight).
func computePriority(cvss, classifierConf float64, callGraphDepth int, w1, w2, w3 float64) float64 {
	depth := callGraphDepth
	if depth <= 0 {
		depth = 1
	}
	return w1*(cvss/10.0) + w2*(1.0-classifierConf) + w3*(1.0/float64(depth))
}

// estimateTokens returns a rough LLM prompt token estimate for one summary.
// Uses 0.3 tokens/char for English technical text plus 50 tokens of structural overhead.
func estimateTokens(s summarizer.Summary) int {
	chars := len(s.FunctionID) + len(s.SurfaceID) +
		len(s.TaintFlow.SinkType) + len(string(s.AuthGuard.CheckLocation)) +
		len(s.LogicFlaw.ResourceIDSource) + len(s.LogicFlaw.DBSink)
	for _, src := range s.TaintFlow.UntrustedSources {
		chars += len(src)
	}
	for _, san := range s.TaintFlow.SanitizerNodes {
		chars += len(san)
	}
	return int(float64(chars)*tuning.TokenEstCharsPerTok) + tuning.TokenEstOverhead
}
