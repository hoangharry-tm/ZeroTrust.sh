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
	"context"
	"log/slog"
	"runtime"
	"strconv"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"golang.org/x/sync/errgroup"
)

// Verdict is the DCC's conclusion for one surface.
type Verdict int

const (
	VerdictSafe         Verdict = iota // provably not vulnerable — drop
	VerdictViolation                   // certain invariant breach — escalate to PoE queue
	VerdictInconclusive                // ambiguous — forward to LLM triage
)

func (v Verdict) String() string {
	switch v {
	case VerdictSafe:
		return "SAFE"
	case VerdictViolation:
		return "VIOLATION"
	case VerdictInconclusive:
		return "INCONCLUSIVE"
	default:
		return "UNKNOWN"
	}
}

// Result is the DCC's conclusion for one surface.
type Result struct {
	Surface  enrichment.EnrichedSurface
	Verdict  Verdict
	CWE      string // which CWE triggered (empty for VerdictSafe)
	Evidence string // human-readable reason for the verdict
}

// Checker runs deterministic contract checks against enriched surfaces.
type Checker struct{}

// New returns a new Checker.
func New() *Checker { return &Checker{} }

// applicableCWEs returns the CWE IDs to check for the given surface kind,
// ordered by CWE number ascending for deterministic tie-breaking.
func applicableCWEs(kind targeting.SurfaceKind) []string {
	switch kind {
	case targeting.SurfaceExternalInput:
		return []string{"CWE-22", "CWE-89", "CWE-78", "CWE-79", "CWE-94", "CWE-502", "CWE-918"}
	case targeting.SurfaceAuthBoundary:
		return []string{"CWE-862", "CWE-89", "CWE-78"}
	case targeting.SurfaceIDORCandidate:
		// IDOR surfaces may also reach SQL/OS sinks — check both auth and injection CWEs.
		return []string{"CWE-862", "CWE-89", "CWE-78"}
	case targeting.SurfaceDangerousSink:
		return []string{"CWE-327"}
	default:
		return nil
	}
}

// cweNumber extracts the numeric portion of a CWE ID for comparison.
func cweNumber(cwe string) int {
	n := strings.TrimPrefix(cwe, "CWE-")
	v, err := strconv.Atoi(n)
	if err != nil {
		return 0
	}
	return v
}

// cweSortKey returns a sort key for deterministic ordering by CWE number.
type cweResult struct {
	cwe    string
	result Verdict
}

// Check runs all applicable rulebook invariants against surface and returns a Result.
// It never calls any external service — purely structural CPG analysis.
func (c *Checker) Check(ctx context.Context, surface enrichment.EnrichedSurface) Result {
	slog.Debug("contracts: input",
		"function", surface.FunctionName,
		"file", surface.File,
		"kind", surface.Kind,
		"sink_nodes", surface.SinkNodes,
		"call_path_len", len(surface.CallPath),
	)
	cweList := applicableCWEs(surface.Kind)
	if len(cweList) == 0 {
		return Result{
			Surface:  surface,
			Verdict:  VerdictInconclusive,
			CWE:      "",
			Evidence: "no applicable CWE for surface kind " + string(surface.Kind),
		}
	}

	type candidate struct {
		cwe         string
		verdict     Verdict
		evidence    string
		sinkMatched bool // true if anchor matched via SinkNodes, false if via code text
	}

	var best *candidate

	for _, cwe := range cweList {
		inv, ok := Rulebook[cwe]
		if !ok {
			continue
		}

		anchorMatched := false
		sinkMatched := false
		for _, anchor := range inv.SinkAnchors {
			for _, sinkNode := range surface.SinkNodes {
				matched := strings.Contains(sinkNode, anchor) || anchor == sinkNode
				slog.Debug("contracts: anchor_check",
					"cwe", cwe,
					"anchor", anchor,
					"sink_node", sinkNode,
					"matched", matched,
				)
				if matched {
					anchorMatched = true
					sinkMatched = true
					break
				}
			}
			if anchorMatched {
				break
			}
		}

		if !anchorMatched && surface.Code != "" && cwe != "CWE-89" {
			stripped := stripCode(surface.Code)
			for _, anchor := range inv.SinkAnchors {
				if strings.Contains(stripped, anchor) {
					slog.Debug("contracts: anchor_check_code",
						"cwe", cwe,
						"anchor", anchor,
						"matched", true,
					)
					anchorMatched = true
					break
				}
			}
		}

		if !anchorMatched {
			continue
		}

		var v Verdict
		var evidence string

		if len(surface.CallPath) == 0 {
			v = VerdictInconclusive
			evidence = "sink anchor " + inv.Name + " matched but call path is empty"
		} else {
			safeMatched := hasSafeNode(surface.CallPath, inv.SafeNodes, surface.Code)
			callPathSample := surface.CallPath
			if len(callPathSample) > 5 {
				callPathSample = callPathSample[:5]
			}
			slog.Debug("contracts: safe_node_check",
                                "cwe", cwe,
				"safe_nodes", inv.SafeNodes,
				"call_path_sample", callPathSample,
				"matched", safeMatched,
			)
			if safeMatched {
				v = VerdictSafe
				evidence = "safe node on call path neutralizes " + cwe
			} else {
				v = VerdictViolation
				evidence = invariant{
					name:   inv.Name,
					cwe:    cwe,
					anchor: firstMatch(inv.SinkAnchors, surface.SinkNodes),
				}.violationEvidence()
			}
		}

		if best == nil || v.greaterThan(best.verdict) ||
			(v == best.verdict && v == VerdictViolation &&
				(sinkMatched && !best.sinkMatched ||
					(sinkMatched == best.sinkMatched && cweNumber(cwe) < cweNumber(best.cwe)))) {
			best = &candidate{cwe: cwe, verdict: v, evidence: evidence, sinkMatched: sinkMatched}
		}
	}

	if best == nil {
		primaryCWE := ""
		if list := applicableCWEs(surface.Kind); len(list) > 0 {
			primaryCWE = list[0]
		}
		return Result{
			Surface:  surface,
			Verdict:  VerdictInconclusive,
			CWE:      primaryCWE,
			Evidence: "no sink anchor matched for any applicable CWE",
		}
	}

	cweOut := best.cwe
	if best.verdict == VerdictSafe {
		cweOut = ""
	}

	result := Result{
		Surface:  surface,
		Verdict:  best.verdict,
		CWE:      cweOut,
		Evidence: best.evidence,
	}

	slog.Debug(
		"contracts: surface verdict",
		"file", surface.File,
		"function", surface.FunctionName,
		"verdict", result.Verdict.String(),
		"cwe", result.CWE,
		"sink_nodes", len(surface.SinkNodes),
		"call_path_len", len(surface.CallPath),
	)

	return result
}

func (v Verdict) greaterThan(other Verdict) bool {
	return v > other
}

func hasSafeNode(callPath []string, safeNodes []string, code string) bool {
	if len(safeNodes) == 0 {
		return false
	}
	for _, node := range callPath {
		for _, safe := range safeNodes {
			if strings.Contains(node, safe) || node == safe {
				return true
			}
		}
	}
	// Fallback: check function body source for safe sanitizer calls
	for _, safe := range safeNodes {
		if strings.Contains(code, safe) {
			return true
		}
	}
	return false
}

func firstMatch(needles []string, haystack []string) string {
	for _, n := range needles {
		for _, h := range haystack {
			if strings.Contains(h, n) || n == h {
				return n
			}
		}
	}
	return ""
}

type invariant struct {
	name   string
	cwe    string
	anchor string
}

func (i invariant) violationEvidence() string {
	return "user-controlled value reaches " + i.name + " sink (" + i.anchor + ") with no safe node on path"
}

// stripCode removes single-line // comments and double-quoted string contents
// from source code so that anchor matching does not fire on words inside
// comments or string literals.
func stripCode(code string) string {
	var out strings.Builder
	for i := 0; i < len(code); i++ {
		if code[i] == '/' && i+1 < len(code) && code[i+1] == '/' {
			for i < len(code) && code[i] != '\n' {
				i++
			}
			if i < len(code) {
				out.WriteByte('\n')
			}
			continue
		}
		if code[i] == '"' {
			i++
			for i < len(code) && !(code[i] == '"' && (i == 0 || code[i-1] != '\\')) {
				i++
			}
			continue
		}
		out.WriteByte(code[i])
	}
	return out.String()
}

// CheckAll runs Check on every surface concurrently (bounded by runtime.NumCPU()).
// Results preserve input order.
func (c *Checker) CheckAll(ctx context.Context, surfaces []enrichment.EnrichedSurface) []Result {
	if len(surfaces) == 0 {
		return nil
	}

	results := make([]Result, len(surfaces))
	g, ctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, runtime.NumCPU())

	for i, surface := range surfaces {
		sem <- struct{}{}
		g.Go(func() error {
			defer func() { <-sem }()
			results[i] = c.Check(ctx, surface)
			return nil
		})
	}

	_ = g.Wait() // Check never errors, but we wait for all goroutines

	var violations, safe, inconclusive, noSinkNodes, noCallPath int
	for _, r := range results {
		switch r.Verdict {
		case VerdictViolation:
			violations++
		case VerdictSafe:
			safe++
		case VerdictInconclusive:
			inconclusive++
		}
	}
	for _, es := range surfaces {
		if len(es.SinkNodes) == 0 {
			noSinkNodes++
		}
		if len(es.CallPath) == 0 {
			noCallPath++
		}
	}
	slog.Info(
		"contracts: summary",
		"total", len(results),
		"violations", violations,
		"safe", safe,
		"inconclusive", inconclusive,
		"surfaces_no_sink_nodes", noSinkNodes,
		"surfaces_no_call_path", noCallPath,
	)

	return results
}
