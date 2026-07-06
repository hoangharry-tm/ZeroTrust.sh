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

// IDOR detection — structural call graph analysis.
//
// A surface is an IDOR candidate when it:
//  1. Can reach a sink (already guaranteed — it's in the surface set).
//  2. Cannot transitively reach any auth-boundary function before the sink.
//
// "Can reach auth" is pre-computed by the caller as a reverse-BFS from all
// auth-boundary seeds (functions in files that import auth/session packages).
// This is O(V+E) and requires no method-name matching.
//
// Reference: BolaRay (CCS 2024) zero-trust resource ID model.
package targeting

// identifyIDOR returns the subset of surfaces that are IDOR candidates.
//
// canReachAuth is the set of node IDs that can transitively reach at least
// one auth-boundary function (pre-computed via reverse BFS from auth seeds).
// A surface absent from canReachAuth has no auth check on any call path —
// making it an IDOR candidate.
//
// Auth-boundary surfaces themselves are excluded: they are by definition
// performing an ownership check.
func identifyIDOR(surfaces map[string]Surface, canReachAuth map[string]bool) []Surface {
	var out []Surface
	for id, s := range surfaces {
		if s.Kind == SurfaceAuthBoundary {
			continue
		}
		if canReachAuth[id] {
			continue // auth present on some path — not an IDOR candidate
		}
		candidate := s
		candidate.Kind = SurfaceIDORCandidate
		candidate.IsIDORCandidate = true
		out = append(out, candidate)
	}
	return out
}
