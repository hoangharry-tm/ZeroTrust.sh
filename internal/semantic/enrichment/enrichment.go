// Copyright 2026 hoangharry-tm
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

// Package enrichment implements the Call Graph + CVE Enrichment + Resource ID
// Dataflow node (Path B Tier 1).
//
// The Enricher augments each Heuristic Targeting surface with three data sources:
//
//  1. CVE enrichment via Trivy (Apache 2.0): runs against the project's dependency
//     manifest (go.sum, requirements.txt, pom.xml, etc.) and matches known CVEs to
//     the function's package. Trivy runs locally — source code never leaves the machine.
//     Offline mode (--offline flag) disables network lookups; Trivy uses its local DB.
//
//  2. Call graph edges: caller and callee IDs are extracted from the Joern CPG and
//     attached to each surface so downstream stages can resolve the call chain without
//     re-querying the CPG.
//
//  3. Zero-trust resource ID tracking (BolaRay CCS 2024 / BOLAZ formal model):
//     all external IDs (URL path params, query params, JSON body fields) are treated
//     as untrusted until an ownership check is confirmed on the taint path. Surfaces
//     that read an external ID and route it to a storage call are flagged as IDOR
//     candidates and marked for mandatory LLM escalation.
//
// Auto-flagging: surfaces with an exact CVE match (CVSS ≥ 7.0) are promoted to
// HIGH severity without going through the UniXcoder classifier.
package enrichment

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// CVEMatch holds a single CVE finding from Trivy for a dependency used by a surface.
type CVEMatch struct {
	// CVE is the CVE identifier (e.g. "CVE-2021-44228").
	CVE string
	// CVSS is the CVSS v3 base score (0.0–10.0).
	CVSS float64
	// Package is the vulnerable package name (e.g. "log4j-core").
	Package string
	// Version is the installed version of the vulnerable package.
	Version string
	// FixedIn is the version that resolves the CVE (empty if no fix exists).
	FixedIn string
}

// ResourceIDFlow describes an untrusted external resource ID observed flowing
// through a surface toward a storage sink (the IDOR signal).
type ResourceIDFlow struct {
	// SourceParam is the function parameter name carrying the external ID.
	SourceParam string
	// StorageSink is the storage call the ID flows into (e.g. "db.QueryRow").
	StorageSink string
	// HasOwnershipCheck is true when an ownership or permission check was detected
	// between the source parameter and the storage sink on the taint path.
	HasOwnershipCheck bool
}

// EnrichedSurface adds CVE, call graph, source code, and IDOR metadata to a
// targeting.Surface.
type EnrichedSurface struct {
	// Surface is the base surface from Heuristic Targeting.
	targeting.Surface
	// Code is the full source text of the function at this surface, fetched from
	// the Joern CPG. The UniXcoder classifier uses this as its primary input.
	Code string
	// Language is the programming language of the surface's source file, derived
	// from the file extension (e.g. "go", "python", "java"). Used by the classifier
	// to route unsupported languages directly to the LLM tier.
	Language string
	// CVEMatches holds all CVEs affecting dependencies used by this surface.
	// Sorted by descending CVSS score.
	CVEMatches []CVEMatch
	// AutoFlagged is true when at least one CVEMatch has CVSS ≥ 7.0.
	// Auto-flagged surfaces bypass the UniXcoder classifier and go directly to dedup.
	AutoFlagged bool
	// CallerIDs are the CPG function IDs that directly call this surface's function.
	CallerIDs []string
	// CalleeIDs are the CPG function IDs directly called by this surface's function.
	CalleeIDs []string
	// ResourceIDFlows lists untrusted ID taint flows observed in this surface.
	// Non-empty means IsIDORCandidate is true in the embedded Surface.
	ResourceIDFlows []ResourceIDFlow
}

// Enricher adds CVE, call graph, and IDOR data to a surface list.
type Enricher struct {
	// graph is the shared Joern CPG used for call graph edge queries.
	graph cpg.Graph
	// trivyPath is the absolute or PATH-resolved path to the trivy binary.
	trivyPath string
	// offlineMode disables Trivy's network lookups; uses local DB only.
	offlineMode bool
}

// New returns an Enricher. Set offlineMode=true for air-gapped environments.
//
// Parameters:
//   - graph: the shared Joern CPG (must be built before Enrich is called).
//   - trivyPath: path to the trivy binary (e.g. "trivy" for PATH lookup).
//   - offlineMode: true disables all outbound network requests during CVE lookup.
func New(graph cpg.Graph, trivyPath string, offlineMode bool) *Enricher {
	return &Enricher{graph: graph, trivyPath: trivyPath, offlineMode: offlineMode}
}

// Enrich augments surfaces with CVE matches, call graph edges, and IDOR signals.
//
// For each surface:
//  1. Run Trivy against the project's dependency manifests in projectRoot.
//  2. Query the CPG for CallerIDs and CalleeIDs.
//  3. Apply the zero-trust resource ID heuristic to detect IDOR flows.
//  4. Set AutoFlagged=true for surfaces with any CVSS ≥ 7.0 CVE match.
//
// Auto-flagged surfaces are returned in the output slice with AutoFlagged=true;
// the caller (pipeline orchestrator) must route them directly to dedup.
//
// Parameters:
//   - ctx: cancellation context.
//   - surfaces: the surface list from Heuristic Targeting.
//   - projectRoot: absolute path to the project root (for Trivy manifest discovery).
//
// Returns:
//   - []EnrichedSurface: one enriched surface per input surface.
//   - error: non-nil if Trivy fails to start or CPG queries fail.
func (e *Enricher) Enrich(_ context.Context, _ []targeting.Surface, _ string) ([]EnrichedSurface, error) {
	// implemented in G3.M3.1
	return nil, nil
}

// DetectIDORFlows applies the zero-trust resource ID heuristic to a single surface.
// Returns the list of resource ID flows detected (empty slice means no IDOR signal).
//
// Parameters:
//   - ctx: cancellation context.
//   - surface: the surface to analyse.
func (e *Enricher) DetectIDORFlows(_ context.Context, _ targeting.Surface) ([]ResourceIDFlow, error) {
	// implemented in G3.M3.1
	return nil, nil
}
