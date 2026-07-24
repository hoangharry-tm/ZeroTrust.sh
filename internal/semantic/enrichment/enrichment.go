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
// Dataflow node (Reasoning Tier 1).
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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	cpg "github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
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
	// SinkNodes lists CPG node IDs or method signatures that match dangerous
	// sink patterns at this surface. Populated by the enrichment layer from
	// the CPG's sink pre-flagging pass.
	SinkNodes []string
	// CallPath lists the call/identifier names (cpg.Node.Name values) along
	// the taint propagation path from source to sink. Empty when the CPG
	// taint tracker produced no path.
	CallPath []string
	// Sanitized is true when every taint path found from source to this
	// surface's sink(s) had a sanitizer node on it, per the CPG's own
	// language-normalized taint taxonomy (cpg_engine.TaintPath.Sanitized) —
	// not a keyword match against source text. False when no taint path was
	// found at all (there's nothing to have sanitized).
	Sanitized bool
	// ContractCWE is the CWE matched by the DCC stage, if any. Empty when no contract matched.
	ContractCWE string
	// TaintConfidence indicates the strength of taint evidence:
	// "" = no taint evidence, "weak" = contract-flagged but no taint path,
	// "confirmed" = inter-procedural taint path confirmed by CPG.
	TaintConfidence string
	// SinkFile is the source file containing the taint sink (from Joern CPG).
	// Populated when a confirmed taint path exists to a sink in a different file.
	SinkFile string
	// SinkLine is the line number of the taint sink call in SinkFile.
	SinkLine int
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

	// ── Project-wide taint analysis ─────────────────────────────────────────
	// Run a single Joern query across all surface methods instead of one query
	// per method. This discovers inter-procedural flows that cross multiple
	// method frames (e.g. controller → service → DAO → executeQuery).
	surfaceIDs := make([]string, len(surfaces))
	for i, s := range surfaces {
		surfaceIDs[i] = s.ID
	}
	lang := detectLangFromFile(surfaces)
	pathsByMethodID := make(map[string][]cpg.TaintPath)
	surfaceCallerChain := make(map[string][]string)
	if e.graph != nil && len(surfaceIDs) > 0 {
		allPaths, err := e.graph.ProjectWideTaintPaths(surfaceIDs, lang)
		if err != nil {
			slog.Warn("enrichment: ProjectWideTaintPaths failed; surfaces will have empty sink nodes",
				"err", err, "surfaces", len(surfaceIDs))
		} else {
			for _, p := range allPaths {
				key := p.Source.NodeID
				pathsByMethodID[key] = append(pathsByMethodID[key], p)
			}
			slog.Info("enrichment: ProjectWideTaintPaths result", "total_paths", len(allPaths))
		}

		// Walk-up: attribute paths to their surface ancestor when the direct
		// source method is not itself a surface (inter-procedural case).
		if e.graph != nil && len(allPaths) > 0 {
			surfaceIDSet := make(map[string]struct{}, len(surfaces))
			for _, s := range surfaces {
				surfaceIDSet[s.ID] = struct{}{}
			}

			// walkupCandidate holds a single-match attribution pending the
			// fan-in check below — not committed to pathsByMethodID yet.
			type walkupCandidate struct {
				callerID   string
				callerName string
				path       cpg.TaintPath
			}
			var candidates []walkupCandidate
			// sinkFanIn counts, for each taint path's sink node, how many
			// DISTINCT surfaces a walk-up attribution wants to attach it to.
			sinkFanIn := make(map[string]map[string]struct{}) // sinkNodeID -> set of callerIDs

			for _, p := range allPaths {
				sourceID := p.Source.NodeID
				if sourceID == "" {
					continue
				}
				if _, direct := surfaceIDSet[sourceID]; direct {
					continue // already attributed directly
				}
				// BFS upward through callers to find the closest surface ancestor(s).
				// Uses surface-adjacency early-stop: if no caller at a given depth
				// is a surface candidate, further expansion is unlikely to find one.
				// depth=8 blanket cap caused over-attribution (SQL taint attributed to
				// crypto utilities); depth=3 was too tight for deep call chains.
				//
				// Caller-edge proximity alone is not reachability: Joern's Java call
				// graph over-approximates virtual dispatch (CHA-style resolution), so
				// two unrelated classes that both call a same-named interface method
				// can appear as "callers" of each other's call chains. When the BFS
				// finds more than one distinct surface at the same proximity for a
				// single taint path, that fan-out is itself evidence the heuristic
				// can't disambiguate for this path — attribute to none rather than
				// guess (a single unlucky guess previously attached an unrelated
				// DB-backup Runtime.exec() sink to an unrelated goods-CRUD surface).
				visited := map[string]bool{sourceID: true}
				queue := []string{sourceID}
				var matched []cpg.Node
				pathKey := sourceID + ":" + p.Sink.NodeID

				for depth := 0; depth < 6 && len(queue) > 0 && len(matched) == 0; depth++ {
					var next []string
					hasAnySurfaceNeighbour := false

					for _, id := range queue {
						callers, cerr := e.graph.GetCallers(id)
						if cerr != nil {
							continue
						}
						for _, caller := range callers {
							if visited[caller.ID] {
								continue
							}
							visited[caller.ID] = true
							if _, isSurface := surfaceIDSet[caller.ID]; isSurface {
								matched = append(matched, caller)
								hasAnySurfaceNeighbour = true
							}
							next = append(next, caller.ID)
						}
					}

					slog.Debug(
						"enrichment: bfs_depth",
						"depth", depth,
						"queue_size", len(queue),
						"matched", len(matched),
						"has_surface_neighbour", hasAnySurfaceNeighbour,
						"path_key", pathKey,
					)

					// Stop early: if this frontier has no surface-adjacent callers at all
					// and we are past depth 2, further expansion is unlikely to help and
					// risks over-attribution.
					if !hasAnySurfaceNeighbour && depth >= 2 {
						break
					}
					queue = next
				}

				switch len(matched) {
				case 0:
					// no ancestor found — leave unattributed, as before.
				case 1:
					caller := matched[0]
					candidates = append(candidates, walkupCandidate{callerID: caller.ID, callerName: caller.Name, path: p})
					if sinkFanIn[p.Sink.NodeID] == nil {
						sinkFanIn[p.Sink.NodeID] = make(map[string]struct{})
					}
					sinkFanIn[p.Sink.NodeID][caller.ID] = struct{}{}
				default:
					names := make([]string, len(matched))
					for i, m := range matched {
						names[i] = m.Name
					}
					slog.Warn(
						"enrichment: ambiguous taint attribution — multiple surfaces equidistant from taint source, dropping rather than guessing",
						"path_key", pathKey,
						"candidates", names,
					)
				}
			}

			// Fan-in guard: commit a walk-up candidate only if its sink isn't
			// also claimed by several OTHER structurally-unrelated surfaces.
			// Found live on a real Grafana scan: a single sink location
			// (login_oauth.go's OAuth error handler) got walk-up-attributed
			// to 5 completely unrelated surfaces spanning 3 different
			// top-level packages (avatar, pluginproxy, static) — including a
			// bare logger wrapper (logWrapper.Write) that has nothing to do
			// with OAuth. A real inter-procedural flow is roughly one
			// surface per sink; many structurally-unrelated surfaces
			// converging on the exact same sink node is the signature of
			// Joern's call-graph over-approximating interface/method-name
			// dispatch (Go's io.Writer, or any other common-signature
			// interface method), not real reachability — the BFS walk-up's
			// per-path "multiple surfaces at once" ambiguity check (above)
			// can't catch this because each individual path's own BFS finds
			// exactly ONE ancestor; the ambiguity only becomes visible when
			// looking across many DIFFERENT paths that all converge on the
			// same sink. This mirrors the existing "many surfaces match one
			// path — drop rather than guess" rule for the inverse direction.
			const maxSinkFanIn = 3
			droppedForFanIn := 0
			for _, c := range candidates {
				if len(sinkFanIn[c.path.Sink.NodeID]) > maxSinkFanIn {
					droppedForFanIn++
					continue
				}
				pathsByMethodID[c.callerID] = append(pathsByMethodID[c.callerID], c.path)
				surfaceCallerChain[c.callerID] = append(surfaceCallerChain[c.callerID], c.callerName)
			}
			if droppedForFanIn > 0 {
				slog.Warn(
					"enrichment: sink fan-in guard — dropped walk-up attributions whose sink was claimed by too many unrelated surfaces",
					"dropped", droppedForFanIn, "max_sink_fan_in", maxSinkFanIn,
				)
			}

			attributed := 0
			for _, s := range surfaces {
				if _, ok := pathsByMethodID[s.ID]; ok {
					attributed++
				}
			}
			slog.Info(
				"enrichment: attribution summary",
				"total_surfaces", len(surfaces),
				"attributed", attributed,
				"gap_pct", fmt.Sprintf("%.1f%%", 100*float64(len(surfaces)-attributed)/float64(len(surfaces))),
			)
			slog.Info("enrichment: walk-up complete", "mapped_surfaces", len(pathsByMethodID))
		}
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
			slog.Debug(
				"enrichment: input",
				"function", s.FunctionName,
				"file", s.File,
				"kind", s.Kind,
				"surface_id", s.ID,
			)

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

			// Fetch function source code for triage prompt context.
			if e.graph != nil && s.File != "" {
				relPath := s.File
				if filepath.IsAbs(s.File) {
					relPath, _ = filepath.Rel(projectRoot, s.File)
				}
				nodes, nerr := e.graph.QueryNodesByFile(relPath, cpg.NodeMethod)
				if nerr == nil {
					for _, n := range nodes {
						if n.Name == s.FunctionName && n.Code != "" {
							codePreview := n.Code
							if len(codePreview) > 100 {
								codePreview = codePreview[:100]
							}
							slog.Debug(
								"enrichment: cpg_node_match",
								"surface_id", s.ID,
								"node_name", n.Name,
								"node_code_preview", codePreview,
							)
							// n.Code is the Joern method signature only — try to read
							// the actual function body from the source file instead.
							absPath := s.File
							if !filepath.IsAbs(absPath) {
								absPath = filepath.Join(projectRoot, absPath)
							}
							if body := readFunctionBody(absPath, n.Line, n.Name); body != "" {
								slog.Debug(
									"enrichment: read_function_body",
									"surface_id", s.ID,
									"success", true,
									"chars", len(body),
								)
								es.Code = body
							} else {
								slog.Debug(
									"enrichment: read_function_body",
									"surface_id", s.ID,
									"success", false,
									"chars", 0,
								)
								es.Code = n.Code
							}
							break
						}
					}
				}
			}

			local := []EnrichedSurface{es}
			ApplyCVEMatches(local, cvesByPkg)
			es = local[0]

			if paths, ok := pathsByMethodID[s.ID]; ok {
				seenSinks := make(map[string]bool)
				allSanitized := true
				for _, p := range paths {
					sinkLabel := p.Sink.Name
					if sinkLabel == "" {
						sinkLabel = string(p.Sink.Kind)
					}
					if !seenSinks[sinkLabel] {
						seenSinks[sinkLabel] = true
						es.SinkNodes = append(es.SinkNodes, sinkLabel)
					}
					for _, n := range p.IntermediateNodes {
						es.CallPath = append(es.CallPath, n.Name)
					}
					// For directly-attributed paths (source == surface), the sink is confirmed.
					// Seed it into CallPath so filterSinksByCallPath always retains it.
					if p.Source.NodeID == s.ID {
						es.CallPath = append(es.CallPath, sinkLabel)
					}
					// Capture sink file/line from first path with a file pointer.
					if es.SinkFile == "" && p.Sink.File != "" {
						es.SinkFile = p.Sink.File
						es.SinkLine = p.Sink.Line
					}
					if !p.Sanitized {
						allSanitized = false
					}
				}
				// Sanitized only means something when a path was actually found —
				// a surface with zero taint paths hasn't been "sanitized", it's
				// just unconfirmed (Contracts treats that as inconclusive, not safe).
				es.Sanitized = len(paths) > 0 && allSanitized
			}

			// Augment CallPath with BFS caller-chain names for better sink confirmation.
			if chain, ok := surfaceCallerChain[s.ID]; ok {
				es.CallPath = append(es.CallPath, chain...)
			}

			// Augment CallPath with callee method names when CallPath is short.
			// This seeds the call path with real method names the surface directly
			// invokes — precisely what filterSinksByCallPath needs to confirm sink relevance.
			if e.graph != nil && len(es.CallPath) < 3 {
				if callees, cerr := e.graph.GetCallees(s.ID); cerr == nil {
					for _, c := range callees {
						if c.Name != "" && !strings.HasPrefix(c.Name, "<operator>") {
							es.CallPath = append(es.CallPath, c.Name)
						}
					}
				}
			}

			// Call-path sink filter: retain only sink labels that also appear
			// in the surface's call path. Falls back to original list if filtering
			// would leave SinkNodes empty.
			if len(es.SinkNodes) > 0 && len(es.CallPath) > 0 {
				beforeFilter := len(es.SinkNodes)
				callPathSet := make(map[string]bool, len(es.CallPath))
				for _, node := range es.CallPath {
					callPathSet[node] = true
				}
				filtered := es.SinkNodes[:0]
				for _, sink := range es.SinkNodes {
					if callPathSet[sink] {
						filtered = append(filtered, sink)
					}
				}
				if len(filtered) > 0 {
					es.SinkNodes = filtered
				}
				slog.Debug(
					"enrichment: sink_nodes_filtered",
					"surface_id", s.ID,
					"before", beforeFilter,
					"after", len(es.SinkNodes),
				)
			}

			if flows, ferr := e.DetectIDORFlows(gctx, s); ferr == nil {
				es.ResourceIDFlows = flows
			}

			slog.Debug(
				"enrichment: sink_nodes",
				"surface_id", s.ID,
				"sink_nodes", es.SinkNodes,
			)
			slog.Debug(
				"enrichment: output",
				"surface_id", s.ID,
				"function", s.FunctionName,
				"file", s.File,
				"code_len", len(es.Code),
				"sink_node_count", len(es.SinkNodes),
				"call_path_len", len(es.CallPath),
				"sink_file", es.SinkFile,
				"sink_line", es.SinkLine,
			)

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

	var withCode, withSinkNodes, withCallPath int
	for _, es := range enriched {
		if es.Code != "" {
			withCode++
		}
		if len(es.SinkNodes) > 0 {
			withSinkNodes++
		}
		if len(es.CallPath) > 0 {
			withCallPath++
		}
	}
	slog.Info(
		"enrichment: surface coverage",
		"total", len(enriched),
		"with_code", withCode,
		"with_sink_nodes", withSinkNodes,
		"with_call_path", withCallPath,
	)

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

// detectLangFromFile detects the source language by majority vote across all
// surface file extensions. Returns "java", "python", "go", "javascript", or empty string.
func detectLangFromFile(surfaces []targeting.Surface) string {
	if len(surfaces) == 0 {
		return ""
	}
	counts := make(map[string]int)
	for _, s := range surfaces {
		ext := filepath.Ext(s.File)
		var lang string
		switch ext {
		case ".java":
			lang = "java"
		case ".py":
			lang = "python"
		case ".go":
			lang = "go"
		case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
			lang = "javascript"
		}
		if lang != "" {
			counts[lang]++
		}
	}
	if len(counts) == 0 {
		return ""
	}
	best := ""
	maxN := 0
	for lang, n := range counts {
		if n > maxN {
			best = lang
			maxN = n
		}
	}
	return best
}

func nodeIDs(nodes []cpg.Node) []string {
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID
	}
	return ids
}

// dedupSinks extracts unique sink labels from a slice of taint paths.
// The first occurrence of each sink label is kept; subsequent duplicates are dropped.
func dedupSinks(paths []cpg.TaintPath) []string {
	seen := make(map[string]bool)
	var sinks []string
	for _, p := range paths {
		label := p.Sink.Name
		if label == "" {
			label = string(p.Sink.Kind)
		}
		if !seen[label] {
			seen[label] = true
			sinks = append(sinks, label)
		}
	}
	return sinks
}

// filterSinksByCallPath retains only sink labels that also appear in the
// surface's call path. If filtering would produce an empty result, the
// original sinks are returned unchanged (safety fallback).
func filterSinksByCallPath(sinks, callPath []string) []string {
	if len(sinks) == 0 || len(callPath) == 0 {
		return sinks
	}
	callPathSet := make(map[string]bool, len(callPath))
	for _, node := range callPath {
		callPathSet[node] = true
	}
	filtered := sinks[:0]
	for _, sink := range sinks {
		if callPathSet[sink] {
			filtered = append(filtered, sink)
		}
	}
	if len(filtered) > 0 {
		return filtered
	}
	return sinks
}

// stripStringsAndComments removes line comments and double-quoted string contents
// from a line so that brace counting is not fooled by braces inside literals.
func stripStringsAndComments(line string) string {
	// Remove // line comments
	if idx := strings.Index(line, "//"); idx >= 0 {
		line = line[:idx]
	}
	// Remove contents of double-quoted strings (simple, non-nested)
	result := strings.Builder{}
	inStr := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '\\' && inStr {
			i++
			continue
		}
		if ch == '"' {
			inStr = !inStr
			result.WriteByte(ch)
			continue
		}
		if !inStr {
			result.WriteByte(ch)
		}
	}
	return result.String()
}

// readFunctionBody reads the source file at absPath and extracts the function
// body starting at startLine (1-indexed). It tracks brace depth to find the
// closing brace and returns up to 6000 chars. When brace-counting returns empty
// (e.g. method signature spans a single line with no body), falls back to
// returning the first 300 chars of the line at startLine so the caller at least
// sees the function signature rather than dropping it as a stub.
//
// When methodName is non-empty and startLine exceeds the file length, a
// name-based fallback search is attempted for bytecode-inflated lines
// (Lombok-generated methods, etc.).
func readFunctionBody(absPath string, startLine int, methodName string) string {
	data, err := os.ReadFile(absPath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if startLine <= 0 || startLine > len(lines) {
		// Bytecode-inflated line number (Lombok-generated method).
		// Search source by method name to find the real body.
		if startLine > len(lines) && methodName != "" {
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.Contains(trimmed, methodName+"(") && isMethodLikeDeclaration(trimmed) {
					startLine = i + 1
					break
				}
			}
		}
		if startLine <= 0 || startLine > len(lines) {
			return ""
		}
	}
	// Joern's lineNumber sometimes points to the closing brace of the previous
	// method. Scan forward (up to 10 lines) to find the line that opens this one.
	actualStart := startLine - 1 // 0-indexed
	foundBrace := false
	for i := actualStart; i < len(lines) && i < actualStart+10; i++ {
		stripped := strings.TrimRight(stripStringsAndComments(lines[i]), " \t")
		trimmedRaw := strings.TrimSpace(lines[i])
		if strings.HasSuffix(stripped, "{") &&
			(strings.Contains(stripped, ")") || trimmedRaw == "{" || isClassLikeDeclaration(trimmedRaw)) {
			actualStart = i
			foundBrace = true
			break
		}
	}

	// Where to start output in the brace-counting path. May be before
	// actualStart when the method signature spans multiple lines (Class C).
	signatureStart := actualStart
	// If the forward scan moved to a line that looks like a new method/class
	// declaration (e.g. private void nextMethod() {), it latched onto the wrong
	// method's opening brace — treat as braceless UNLESS the original line was a
	// closing } (that's the legitimate N2 off-by-one case — the target method is
	// the next one and we should keep its brace).
	if foundBrace && actualStart != startLine-1 &&
		isMethodLikeDeclaration(strings.TrimSpace(lines[actualStart])) {
		orig := strings.TrimSpace(lines[startLine-1])
		if !strings.HasSuffix(orig, "}") {
			foundBrace = false
		}
	}

	// Class B: class-level { capture — the forward scan latched onto the class
	// declaration's opening brace (e.g. "public class Salaries {"). Skip past
	// it to find the first method-level { within 30 lines.
	if foundBrace && isClassLikeDeclaration(strings.TrimSpace(lines[actualStart])) {
		foundMethodBrace := false
		for i := actualStart + 1; i < len(lines) && i < actualStart+30; i++ {
			trimmed := strings.TrimSpace(lines[i])
			if isMethodLikeDeclaration(trimmed) &&
				strings.Contains(stripStringsAndComments(lines[i]), "{") {
				actualStart = i
				signatureStart = i
				foundMethodBrace = true
				break
			}
		}
		if !foundMethodBrace {
			foundBrace = false
		}
	}

	// Class C: multi-line method signature — scan backward from actualStart
	// to find the true start of the method signature (access modifier or @).
	// Guards prevent walking past class/interface/enum boundaries or latching
	// onto class-level { that are not method bodies.
	if foundBrace {
		for i := actualStart - 1; i >= 0 && i >= actualStart-8; i-- {
			trimmed := strings.TrimSpace(lines[i])
			if (isMethodLikeDeclaration(trimmed) && !isClassLikeDeclaration(trimmed)) ||
				(strings.HasPrefix(trimmed, "@") && !isClassLikeDeclaration(trimmed)) {
				signatureStart = i
				break
			}
			strippedLine := strings.TrimRight(stripStringsAndComments(lines[i]), " \t")
			trimmedStripped := strings.TrimSpace(strippedLine)
			if trimmedStripped == "}" || trimmedStripped == "};" ||
				strings.HasSuffix(strippedLine, "{") {
				break
			}
		}
	}

	if !foundBrace {
		// Name-based fallback: when methodName is known and the forward scan
		// failed (e.g. Joern's line is in the import block), scan the entire
		// file for the method declaration and re-run the forward scan.
		if methodName != "" {
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.Contains(trimmed, methodName+"(") && isMethodLikeDeclaration(trimmed) {
					actualStart = i
					for j := actualStart; j < len(lines) && j < actualStart+10; j++ {
						stripped := strings.TrimRight(stripStringsAndComments(lines[j]), " \t")
						trimmedRaw := strings.TrimSpace(lines[j])
						if strings.HasSuffix(stripped, "{") &&
							(strings.Contains(stripped, ")") || trimmedRaw == "{") {
							actualStart = j
							foundBrace = true
							break
						}
					}
					if foundBrace {
						signatureStart = actualStart
						// Backward scan for multi-line sig.
						for k := actualStart - 1; k >= 0 && k >= actualStart-8; k-- {
							t := strings.TrimSpace(lines[k])
							if (isMethodLikeDeclaration(t) && !isClassLikeDeclaration(t)) ||
								(strings.HasPrefix(t, "@") && !isClassLikeDeclaration(t)) {
								signatureStart = k
								break
							}
							sl := strings.TrimRight(stripStringsAndComments(lines[k]), " \t")
							ts := strings.TrimSpace(sl)
							if ts == "}" || ts == "};" || strings.HasSuffix(sl, "{") {
								break
							}
						}
						break
					}
				}
			}
		}
	}

	if !foundBrace {
		// Braceless body (e.g. expression-form lambda). Capture from the
		// reported line with a fixed window, stopping early at the next
		// method declaration to avoid bleeding into an unrelated method.
		var out strings.Builder
		limit := min(startLine-1+20, len(lines))
		for i := startLine - 1; i < limit && out.Len() < 6000; i++ {
			line := lines[i]
			trimmed := strings.TrimSpace(line)
			if i > startLine-1 && isMethodLikeDeclaration(trimmed) {
				break
			}
			out.WriteString(line)
			out.WriteByte('\n')
		}
		if body := strings.TrimSpace(out.String()); body != "" {
			return body
		}
		// Final fallback: return the line we started from.
		line := lines[startLine-1]
		if len(line) > 300 {
			line = line[:300]
		}
		return line
	}

	depth := 0
	started := false
	var out strings.Builder
	for i := signatureStart; i < len(lines) && out.Len() < 6000; i++ {
		line := lines[i]
		out.WriteString(line)
		out.WriteByte('\n')
		if i >= actualStart {
			stripped := stripStringsAndComments(line)
			for _, ch := range stripped {
				switch ch {
				case '{':
					depth++
					started = true
				case '}':
					depth--
				}
			}
			if started && depth <= 0 {
				break
			}
		}
	}
	if body := strings.TrimSpace(out.String()); body != "" {
		return body
	}
	// Fallback: return the line we actually started from.
	line := lines[signatureStart]
	if len(line) > 300 {
		line = line[:300]
	}
	return line
}

// isMethodLikeDeclaration reports whether a trimmed source line looks like
// the start of a new method/class/interface declaration, used to prevent the
// braceless-lambda fallback in readFunctionBody from bleeding into an
// unrelated method body.
func isMethodLikeDeclaration(line string) bool {
	switch {
	case strings.HasPrefix(line, "private "),
		strings.HasPrefix(line, "public "),
		strings.HasPrefix(line, "protected "),
		strings.HasPrefix(line, "static "),
		strings.HasPrefix(line, "@"):
		return true
	}
	return false
}

// isClassLikeDeclaration reports whether a trimmed source line is a class,
// interface, enum, or annotation declaration (rather than a method body).
// Used in readFunctionBody to skip past class-level { and find the real
// method body inside.
func isClassLikeDeclaration(line string) bool {
	return strings.Contains(line, " class ") ||
		strings.Contains(line, " interface ") ||
		strings.Contains(line, " enum ") ||
		strings.Contains(line, " @interface ")
}
