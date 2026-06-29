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

// Token budget enforcement (T2).
//
// rank scores every input, sorts by priority descending, then greedily
// assigns surfaces to the ranked set until the token cap is reached.
// Surfaces that do not fit are returned in the exhausted slice, in priority
// order. The caller must emit a SUPPRESSED finding for each exhausted surface.

package budget

import (
	"cmp"
	"log/slog"
	"slices"
)

// rank is the shared implementation for Rank and RankWithStats.
func (c *Controller) rank(inputs []Input) (ranked []RankedSurface, exhausted []Input, stats Stats) {
	stats.Total = len(inputs)
	slog.Debug("budget: ranking", slog.Int("total", len(inputs)), slog.Int("token_cap", c.tokenCap))
	if len(inputs) == 0 {
		return nil, nil, stats
	}

	// Compute priority once per input; sort indices descending.
	priorities := make([]float64, len(inputs))
	for i, inp := range inputs {
		priorities[i] = computePriority(inp.CVSSScore, inp.ClassifierConfidence, inp.CallGraphDepth, c.w1, c.w2, c.w3)
	}
	order := make([]int, len(inputs))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int {
		return cmp.Compare(priorities[b], priorities[a]) // descending
	})

	used := 0
	capHit := false
	for _, idx := range order {
		inp := inputs[idx]
		tokens := estimateTokens(inp.Summary)
		if capHit || used+tokens > c.tokenCap {
			capHit = true
			exhausted = append(exhausted, inp)
			stats.Exhausted++
			continue
		}
		ranked = append(ranked, RankedSurface{
			Summary:              inp.Summary,
			File:                 inp.File,
			Priority:             priorities[idx],
			EstimatedTokens:      tokens,
			ClassifierConfidence: inp.ClassifierConfidence,
		})
		used += tokens
		stats.Ranked++
		stats.TokensUsed += tokens
	}
	slog.Debug("budget: ranked", slog.Int("ranked", len(ranked)), slog.Int("exhausted", len(exhausted)), slog.Int("tokens_used", stats.TokensUsed))
	return ranked, exhausted, stats
}
