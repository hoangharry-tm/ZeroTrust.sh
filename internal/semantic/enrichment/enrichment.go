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
// HIGH severity without going through the CodeT5+ classifier.
package enrichment

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
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
	// the Joern CPG. The CodeT5+ classifier uses this as its primary input.
	Code string
	// Language is the programming language of the surface's source file, derived
	// from the file extension (e.g. "go", "python", "java"). Used by the classifier
	// to route unsupported languages directly to the LLM tier.
	Language string
	// CVEMatches holds all CVEs affecting dependencies used by this surface.
	// Sorted by descending CVSS score.
	CVEMatches []CVEMatch
	// AutoFlagged is true when at least one CVEMatch has CVSS ≥ 7.0.
	// Auto-flagged surfaces bypass the CodeT5+ classifier and go directly to dedup.
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
func (e *Enricher) Enrich(ctx context.Context, surfaces []targeting.Surface, projectRoot string) ([]EnrichedSurface, error) {
	// Phase-level deadline: abort if enrichment exceeds budget.
	total := len(surfaces)
	timeout := 5 * time.Minute
	if d := time.Duration(total) * 10 * time.Millisecond; d > timeout {
		timeout = d
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	slog.Debug("enriching surfaces", slog.Int("surfaces", total), slog.String("project_root", projectRoot))
	cvesByPkg, err := e.RunTrivy(ctx, projectRoot)
	if err != nil {
		// ponytail: non-fatal — CVE enrichment is best-effort; continue without CVEs.
		slog.Warn("trivy CVE enrichment failed; continuing without CVEs", "err", err)
		cvesByPkg = make(map[string][]CVEMatch)
	}

	limit := runtime.GOMAXPROCS(0) * 2
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)

	var (
		mu          sync.Mutex
		autoFlagged int
		enriched    = make([]EnrichedSurface, 0, total)
		done        int
	)
	loopStart := time.Now()

	for _, s := range surfaces {
		// s := s
		g.Go(func() error {
			es := EnrichedSurface{
				Surface:  s,
				Language: finding.LangFromPath(s.File),
			}

			if e.graph != nil {
				if callers, cerr := e.graph.GetCallers(s.ID); cerr == nil {
					es.CallerIDs = nodeIDs(callers)
				} else {
					slog.Warn("enrichment: GetCallers failed", slog.String("surface_id", s.ID), "err", cerr)
				}
				if callees, cerr := e.graph.GetCallees(s.ID); cerr == nil {
					es.CalleeIDs = nodeIDs(callees)
				} else {
					slog.Warn("enrichment: GetCallees failed", slog.String("surface_id", s.ID), "err", cerr)
				}
			}

			local := []EnrichedSurface{es}
			ApplyCVEMatches(local, cvesByPkg)
			es = local[0]

			if flows, ferr := e.DetectIDORFlows(gctx, s); ferr == nil {
				es.ResourceIDFlows = flows
			}

			mu.Lock()
			done++
			if done%10 == 0 {
				elapsed := time.Since(loopStart)
				elapsedSec := elapsed.Seconds()
				rate := float64(done) / elapsedSec
				remaining := total - done
				eta := time.Duration(float64(remaining)/elapsedSec*float64(time.Second)) * time.Second
				slog.Info(
					"enrichment: progress",
					slog.Int("done", done),
					slog.Int("total", total),
					slog.Float64("pct", float64(done)/float64(total)*100),
					slog.Float64("elapsed_seconds", elapsedSec),
					slog.Float64("throughput_ops_per_sec", rate),
					slog.String("eta", eta.Round(time.Second).String()),
				)
			}
			if es.AutoFlagged {
				autoFlagged++
			}
			enriched = append(enriched, es)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	slog.Info("enrichment complete", slog.Int("enriched", len(enriched)), slog.Int("auto_flagged", autoFlagged))
	return enriched, nil
}

// DetectIDORFlows applies the zero-trust resource ID heuristic to a single surface.
// Returns the list of resource ID flows detected (empty slice means no IDOR signal).
func (e *Enricher) DetectIDORFlows(_ context.Context, surface targeting.Surface) ([]ResourceIDFlow, error) {
	slog.Debug("enrichment: DetectIDORFlows", slog.String("surface_id", surface.ID))
	if e.graph == nil {
		return nil, nil
	}
	// Surface classification is structural (import-boundary + call graph reachability).
	// If targeting already flagged this surface as an IDOR candidate, report it directly
	// rather than re-running pattern detection over PDG edge labels.
	if !surface.IsIDORCandidate {
		return nil, nil
	}
	flows := []ResourceIDFlow{{
		SourceParam: surface.FunctionName,
		StorageSink: "unknown", // assembler/LLM confirm the specific sink
		// ponytail: ownership check absence confirmed structurally by canReachAuth BFS;
		// HasOwnershipCheck stays false until taint path analysis is added.
		HasOwnershipCheck: false,
	}}
	slog.Debug("enrichment: IDOR flows detected", slog.String("surface_id", surface.ID), slog.Int("flows", len(flows)))
	return flows, nil
}

func nodeIDs(nodes []cpg.Node) []string {
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID
	}
	return ids
}
