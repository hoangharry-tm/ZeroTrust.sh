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

// IDOR heuristic based on the BOLAZ/BolaRay zero-trust resource ID model.
// Reference: Rotem Bar et al., "BolaRay: Automated Detection of BOLA Vulnerabilities
// via Property Graphs", CCS 2024. P-API sources + C-API anchors + storage sinks.
package targeting

import (
	"context"
	"strings"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// IDORConfig defines the P-API sources and C-API anchors used by the BOLAZ
// zero-trust resource ID heuristic. Configurable so callers can extend
// patterns without recompiling.
type IDORConfig struct {
	// PAPISources are call-name substrings that introduce an external resource ID
	// (HTTP path params, query params, request body field accessors).
	PAPISources []string
	// CAPIAnchors are call-name substrings that constitute an ownership check
	// (session user ID, JWT sub-claim, @AuthenticationPrincipal, constant literals).
	CAPIAnchors []string
	// StorageSinks are call-name substrings for object-fetch operations
	// (DB query, cache lookup, file access).
	StorageSinks []string
}

// DefaultIDORConfig returns the built-in P-API / C-API / sink patterns.
func DefaultIDORConfig() IDORConfig {
	return IDORConfig{
		PAPISources: []string{
			"getParameter", "pathVariable", "QueryParam", "PathParam",
			"getBody", "FormValue", "PostFormValue", "URL.Query",
		},
		CAPIAnchors: []string{
			"getUserId", "getSubject", "getPrincipal", "AuthenticationPrincipal",
			"currentUser", "sessionUser", "jwt.sub", "claims.Sub",
		},
		StorageSinks: []string{
			"db.Query", "db.QueryRow", "db.Exec", "db.Find", "db.First",
			"repository.findById", "cache.Get", "os.Open",
		},
	}
}

// queryIDORCandidates finds METHOD nodes where an external resource ID (P-API)
// flows to a storage sink without an intervening ownership check (C-API anchor).
// Uses graph.TaintPaths with P-API as sources and storage sinks as sinks; paths
// where any intermediate node label matches a C-API anchor are excluded.
func (t *Targeter) queryIDORCandidates(ctx context.Context, cfg IDORConfig) ([]Surface, error) {
	methods, err := t.graph.QueryNodes(cpg.NodeMethod)
	if err != nil {
		return nil, err
	}

	// Build source and sink slices from METHOD edge labels matching config patterns.
	var sources []cpg.TaintSource
	var sinks []cpg.TaintSink
	for _, m := range methods {
		edges, err := t.graph.QueryEdges(m.ID, "")
		if err != nil {
			return nil, err
		}
		for _, e := range edges {
			if matchesAny(e.Label, cfg.PAPISources) {
				sources = append(sources, cpg.TaintSource{
					NodeID: m.ID,
					Kind:   "http_param",
					File:   m.File,
					Line:   m.Line,
				})
			}
			if matchesAny(e.Label, cfg.StorageSinks) {
				sinks = append(sinks, cpg.TaintSink{
					NodeID: m.ID,
					Kind:   cpg.SinkSQL,
					File:   m.File,
					Line:   m.Line,
				})
			}
		}
	}

	if len(sources) == 0 || len(sinks) == 0 {
		return nil, nil
	}

	paths, err := t.graph.TaintPaths(sources, sinks)
	if err != nil {
		return nil, err
	}

	// nodeID → Node for quick lookup.
	byID := make(map[string]cpg.Node, len(methods))
	for _, m := range methods {
		byID[m.ID] = m
	}

	seen := make(map[string]bool)
	var out []Surface
	for _, p := range paths {
		if p.Sanitized {
			continue
		}
		// Exclude paths that pass through a C-API ownership-check node.
		if hasOwnershipCheck(p.IntermediateNodes, cfg.CAPIAnchors) {
			continue
		}
		if seen[p.Source.NodeID] {
			continue
		}
		seen[p.Source.NodeID] = true
		n := byID[p.Source.NodeID]
		out = append(out, Surface{
			ID:              n.ID,
			File:            n.File,
			FunctionName:    n.Name,
			NodeType:        cpg.NodeMethod,
			Kind:            SurfaceIDORCandidate,
			IsIDORCandidate: true,
		})
	}
	return out, nil
}

func matchesAny(label string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(label, p) {
			return true
		}
	}
	return false
}

func hasOwnershipCheck(nodes []cpg.Node, anchors []string) bool {
	for _, n := range nodes {
		if matchesAny(n.Name, anchors) || matchesAny(n.Code, anchors) { //nolint:gocritic
			return true
		}
	}
	return false
}
