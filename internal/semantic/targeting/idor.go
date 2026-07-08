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

import "strings"

// idorSignals are substrings that indicate a function or file is likely
// involved in accessing a specific resource or user record. Case-insensitive
// matching is applied against the surface's function name and file path.
var idorSignals = []string{
	"getById", "findById", "loadById", "fetchById",
	"getBy", "findBy", "fetchBy",
	"byId", "byUsername", "byEmail", "byUser",
	"resource", "profile", "account",
	"order", "invoice", "document", "record", "item", "asset",
}

// identifyIDOR returns the subset of surfaces that are IDOR candidates.
//
// canReachAuth is the set of node IDs that can transitively reach at least
// one auth-boundary function (pre-computed via reverse BFS from auth seeds).
//
// A surface is promoted to SurfaceIDORCandidate only when BOTH conditions hold:
//   (a) the surface does NOT canReachAuth, AND
//   (b) the surface's function name or file path contains an IDOR-relevant signal.
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
		if !hasIDORSignal(s) {
			continue // no IDOR-relevant signal in function name or file path
		}
		candidate := s
		candidate.Kind = SurfaceIDORCandidate
		candidate.IsIDORCandidate = true
		out = append(out, candidate)
	}
	return out
}

// hasIDORSignal checks whether the surface's function name or file path
// contains any of the known IDOR-relevant substrings (case-insensitive).
func hasIDORSignal(s Surface) bool {
	lowerFunc := strings.ToLower(s.FunctionName)
	lowerFile := strings.ToLower(s.File)
	for _, signal := range idorSignals {
		if strings.Contains(lowerFunc, signal) {
			return true
		}
		if strings.Contains(lowerFile, signal) {
			return true
		}
	}
	return false
}
