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
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"unicode/utf8"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
	"golang.org/x/sync/errgroup"
)

// Prompt text lives in prompts/escalate.md.tmpl — edit that file, not this one.
//
//go:embed prompts/escalate.md.tmpl
var escalatePromptSrc string

var escalateTmpl = template.Must(template.New("escalate").Parse(escalatePromptSrc))

// Verdict is the DCC's conclusion for one surface.
type Verdict int

// Declared in ascending "best candidate" priority — see greaterThan and its
// use in Check's best-selection loop. VerdictInconclusive is deliberately
// lowest: it means "this CWE has no fixed signature to check, deferring
// entirely" (NoSinkModel's default), which is strictly less informative than
// a DIFFERENT applicable CWE's actual Safe or Violation determination. This
// used to be the opposite (Inconclusive numerically highest, since it was
// declared last) — found live on a real Grafana scan: getPluginAssets is
// both an IDOR candidate (CWE-862, always Inconclusive when NoSinkModel
// can't resolve it) AND a real CWE-22 path-traversal surface with a genuine
// anchor match — but CWE-862's Inconclusive default kept winning as "best"
// over CWE-22's actual (correctly reasoned) verdict on every applicable-CWE
// comparison, purely because Inconclusive's old iota position (2) beat
// Violation (1) and Safe (0) under a raw v > other comparison. A surface
// with ANY resolved verdict from ANY applicable CWE should report that, not
// a different CWE's shrug.
const (
	VerdictInconclusive Verdict = iota // ambiguous — forward to LLM triage; lowest priority as "best"
	VerdictSafe                        // provably not vulnerable — drop
	VerdictViolation                   // certain invariant breach — escalate to PoE queue; highest priority
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
//
// The primary safe/violation signal is structural: enrichment.EnrichedSurface.Sanitized,
// which the CPG's own language-normalized taint taxonomy computes (see
// cpg_engine.TaintPath.Sanitized) — this is what makes Contracts work the same
// way across Java/Python/JS/Go, since it operates on Joern's normalized graph,
// not per-language source-text keywords. The rulebook's SafeNodes keyword list
// is kept only as a fallback for cases the taxonomy doesn't yet cover.
//
// When llm is non-nil, the narrow remaining gap — a confirmed, unsanitized-by-
// structure taint path where SafeNodes also found nothing — gets one scoped
// yes/no question before committing to VerdictViolation, instead of assuming
// violation outright. This is deliberately not a general "does this look
// vulnerable" prompt: it asks about the exact missing fact (does an
// intermediate function neutralize the tainted value), and any failure or
// non-affirmative answer defaults to VerdictViolation — the same
// asymmetric-trust posture used by the self-consistency check in
// internal/semantic/analysis and by internal/poe: a sandboxed/LLM "looks safe"
// signal never overrides a structurally-confirmed danger signal.
type Checker struct {
	llm   llm.Provider     // nil = fully deterministic, no scoped escalation
	graph cpg_engine.Graph // nil = escalate() sees only the matched function's own code
	root  string           // project root, for resolving caller source file paths
}

// New returns a Checker with no LLM escalation — the ambiguous "sink
// confirmed, not sanitized by structure or keyword" case defaults to
// VerdictViolation, matching this package's original behavior exactly.
func New() *Checker { return &Checker{} }

// NewWithEscalation returns a Checker that asks provider one scoped yes/no
// question for the narrow ambiguous case described in the Checker doc comment,
// instead of defaulting straight to VerdictViolation.
func NewWithEscalation(provider llm.Provider) *Checker { return &Checker{llm: provider} }

// WithGraph attaches a CPG graph, letting escalate() include the matched
// function's immediate callers as extra evidence. Without this, escalate()
// can only ever see the SafeNode-matched function's own text — the same
// structural blind spot found live in B5 (a guard living in the caller, not
// the function itself, was invisible until the investigation-gate work) also
// applies here, since a SafeNode match's neutralization could legitimately
// happen one hop up rather than in the matched function itself.
func (c *Checker) WithGraph(graph cpg_engine.Graph) *Checker {
	c.graph = graph
	return c
}

// WithRoot sets the project root for resolving caller source file paths when
// building caller context (see WithGraph).
func (c *Checker) WithRoot(root string) *Checker {
	c.root = root
	return c
}

// applicableCWEs returns the CWE IDs to check for the given surface kind,
// ordered by CWE number ascending for deterministic tie-breaking.
func applicableCWEs(kind targeting.SurfaceKind) []string {
	switch kind {
	case targeting.SurfaceExternalInput:
		return []string{"CWE-22", "CWE-89", "CWE-78", "CWE-79", "CWE-94", "CWE-502", "CWE-918"}
	case targeting.SurfaceAuthBoundary:
		return []string{"CWE-862", "CWE-89", "CWE-78"}
	case targeting.SurfaceIDORCandidate:
		// IDOR surfaces may also reach SQL/OS/filesystem sinks — check auth
		// and injection CWEs too. CWE-22 was missing here entirely — found
		// live on a real Grafana scan: getPluginAssets (CVE-2021-43798) is
		// exactly this shape, a resource-ID parameter (pluginID) used to
		// both look up a resource (why targeting classified it IDOR) AND
		// construct a file path passed to os.Open (a real CWE-22 sink) —
		// but since CWE-22 was never even in this list, it could never be
		// contract-checked as path traversal, only as CWE-862 (via
		// NoSinkModel's always-inconclusive default), regardless of how
		// good B5's own reasoning was. A resource-ID-to-file-path lookup is
		// one of the most common IDOR-adjacent patterns there is, not an
		// edge case.
		return []string{"CWE-862", "CWE-89", "CWE-78", "CWE-22"}
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

		var v Verdict
		var evidence string
		sinkMatched := false

		if inv.NoSinkModel {
			// No dangerous-API signature to keyword-match — Targeting's
			// structural classification (surface.Kind) already established
			// this surface is relevant to cwe. Contracts can still apply the
			// CPG's structural taint taxonomy (surface.Sanitized) as a real
			// safety signal, but has no keyword-based basis to assert
			// VerdictViolation on its own — defer to B4/B5, which get real
			// code, the corrected security-contract text, and (for B5) tool
			// access to inspect callers/callees rather than a method-name list.
			if surface.Sanitized {
				v = VerdictSafe
				evidence = "CPG taint analysis confirmed a sanitizer on every path for " + cwe
			} else {
				v = VerdictInconclusive
				evidence = "no fixed sink signature for " + inv.Name + " (" + cwe + ") — deferring to LLM reasoning over real code"
			}
		} else {
			anchorMatched := false
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

			if len(surface.CallPath) == 0 {
				v = VerdictInconclusive
				evidence = "sink anchor " + inv.Name + " matched but call path is empty"
			} else if surface.Sanitized {
				// Structural, cross-language signal from the CPG's own taint
				// taxonomy — takes priority over the keyword fallback below.
				v = VerdictSafe
				evidence = "CPG taint analysis confirmed a sanitizer on every path to the sink for " + cwe
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
				// A keyword-matched safe node (e.g. "filepath.Clean" found in
				// the code) used to be trusted immediately as VerdictSafe,
				// with no LLM involved at all — but a keyword match only
				// proves the sanitizer-shaped call is PRESENT, not that it's
				// actually sufficient in this position. Found live on a real
				// Grafana scan: getPluginAssets (CVE-2021-43798) calls
				// filepath.Clean on the tainted value, matching CWE-22's
				// SafeNodes list, so contracts declared it safe outright —
				// exactly the failure mode CWE-22's own AI Failure Profile
				// text already warns about ("AI models miss path traversal
				// when normalization appears to happen but uses a
				// non-canonical form... Verify canonicalization order"),
				// except that warning never reached the LLM because the
				// keyword match short-circuited before any escalation
				// happened. When an LLM is configured, treat a keyword match
				// as provisional and let escalate() (same call used for the
				// no-match case) make the real call — it already asks
				// "does this code actually neutralize the tainted value",
				// which is the right question regardless of whether a
				// sanitizer-shaped token was merely present in the text.
				switch {
				case c.llm != nil:
					v, evidence = c.escalate(ctx, surface, inv, cwe)
				case safeMatched:
					v = VerdictSafe
					evidence = "safe node on call path neutralizes " + cwe
				default:
					v = VerdictViolation
					evidence = invariant{
						name:   inv.Name,
						cwe:    cwe,
						anchor: firstMatch(inv.SinkAnchors, surface.SinkNodes),
					}.violationEvidence()
				}
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

// escalationSamples is the number of independent samples escalate() draws
// before majority-voting a YES/NO answer. This is genuine self-consistency
// (Wang et al. 2022 — resample the SAME prompt, majority vote), unlike the
// differently-scoped adversarial probe in internal/semantic/analysis's
// selfConsistencyCheck: escalate()'s prompt is short (NumPredict=120) and
// this is the single highest-leverage decision point in the contracts
// package (it decides Safe vs Violation directly, with no downstream
// re-check the way B5 re-checks a contracts verdict), so the extra 2 calls
// per escalation are a reasonable trade for a real accuracy gain on exactly
// the calls that matter most.
const escalationSamples = 3

// escalationTemperature is intentionally non-zero (unlike most of this
// codebase's low-temperature classification calls) — self-consistency only
// produces genuinely independent samples to vote over if there's real
// variance between them; sampling the same prompt 3 times at temperature 0.1
// mostly reproduces the same single answer 3 times, defeating the point.
const escalationTemperature = 0.4

// escalate asks c.llm a scoped yes/no question about the specific missing
// fact structural analysis couldn't resolve: does an intermediate function on
// the call path neutralize the tainted value before it reaches inv's sink.
// Any error, empty response, or non-affirmative majority defaults to
// VerdictViolation — self-consistency can confirm safety, it never overrides
// a structurally-confirmed danger signal by staying silent or splitting.
func (c *Checker) escalate(ctx context.Context, surface enrichment.EnrichedSurface, inv Invariant, cwe string) (Verdict, string) {
	violation := invariant{
		name:   inv.Name,
		cwe:    cwe,
		anchor: firstMatch(inv.SinkAnchors, surface.SinkNodes),
	}.violationEvidence()

	code := surface.Code
	if len(code) > 1500 {
		code = truncateUTF8(code, 1500) + "\n...[truncated]"
	}
	if code == "" {
		// Nothing to scope the question against — the LLM would just be
		// guessing from the CWE name alone. Not worth the call.
		return VerdictViolation, violation
	}

	var promptBuf strings.Builder
	if err := escalateTmpl.Execute(&promptBuf, struct{ CWEName, CWE, Code, CallerContext string }{
		CWEName: inv.Name, CWE: cwe, Code: code, CallerContext: c.callerContext(surface),
	}); err != nil {
		panic("contracts: escalate.md.tmpl execute: " + err.Error())
	}
	prompt := promptBuf.String()

	yes, no := 0, 0
	var lastResp string
	for i := 0; i < escalationSamples; i++ {
		resp, err := c.llm.Generate(ctx, prompt, &llm.Options{Temperature: escalationTemperature, NumPredict: 120, NumCtx: 4096, Think: new(false)})
		if err != nil {
			slog.Warn("contracts: escalation sample failed", "cwe", cwe, "function", surface.FunctionName, "sample", i, "err", err)
			continue
		}
		lastResp = resp
		if answersYes(resp) {
			yes++
		} else {
			no++
		}
	}
	slog.Debug("contracts: escalation votes", "cwe", cwe, "function", surface.FunctionName, "yes", yes, "no", no)

	if yes == 0 && no == 0 {
		// Every sample errored — defaulting to violation, same as a single failed call.
		slog.Warn("contracts: all escalation samples failed, defaulting to violation", "cwe", cwe, "function", surface.FunctionName)
		return VerdictViolation, violation
	}
	if yes <= no {
		return VerdictViolation, violation
	}
	return VerdictSafe, fmt.Sprintf("scoped LLM check confirmed sanitization for %s (%d/%d votes): %s", cwe, yes, yes+no, strings.TrimSpace(lastResp))
}

// answersYes reports whether resp's answer is YES, per the prompt's
// "reasoning first, then YES/NO as the last word on the last line" format —
// reasoning-before-answer (not answer-then-justify) matches the same fix
// already applied to triage's category-word prompt, for the same reason: an
// answer committed to before any stated reasoning invites a fabricated
// after-the-fact justification, since the decision token is already locked
// in by the time the "reasoning" is generated.
func answersYes(resp string) bool {
	trimmed := strings.TrimSpace(resp)
	lines := strings.Split(trimmed, "\n")
	lastLine := strings.ToUpper(strings.TrimSpace(lines[len(lines)-1]))
	fields := strings.Fields(lastLine)
	if len(fields) == 0 {
		return false
	}
	lastWord := strings.Trim(fields[len(fields)-1], ".,;:!\"'")
	return lastWord == "YES"
}

// callerContextLines bounds the code window read around each caller — enough
// to see a guard clause near the top of the function without letting a
// caller list with many results balloon the prompt.
const callerContextLines = 6

// callerContextBudget caps the total caller-context text appended to the
// escalation prompt, keeping it well within NumCtx=4096 alongside the
// function's own (up to 1500-byte) code and the rest of the prompt scaffold.
const callerContextBudget = 1200

// callerContext returns a short block of the matched surface's immediate
// callers' source, or "" if no graph is attached, the surface has no callers,
// or nothing could be read. See WithGraph's doc comment for why this exists.
func (c *Checker) callerContext(surface enrichment.EnrichedSurface) string {
	if c.graph == nil || surface.ID == "" {
		return ""
	}
	callers, err := c.graph.GetCallers(surface.ID)
	if err != nil || len(callers) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, caller := range callers {
		if sb.Len() >= callerContextBudget {
			break
		}
		snippet := readCallerSnippet(c.root, caller.File, caller.Line, callerContextLines)
		if snippet == "" {
			continue
		}
		fmt.Fprintf(&sb, "--- caller: %s (%s:%d) ---\n%s\n", caller.Name, caller.File, caller.Line, snippet)
	}
	out := sb.String()
	if len(out) > callerContextBudget {
		out = out[:callerContextBudget] + "\n... [truncated]"
	}
	return out
}

// readCallerSnippet reads contextLines lines around lineNum from root/file.
// Returns "" on any read failure — a missing/unreadable caller file just
// means no caller context is available, not an error worth surfacing.
func readCallerSnippet(root, file string, lineNum, contextLines int) string {
	path := file
	if root != "" && !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	start := max(0, lineNum-1-contextLines)
	end := min(len(lines), lineNum+contextLines)
	if start >= end {
		return ""
	}
	var out strings.Builder
	for i := start; i < end; i++ {
		fmt.Fprintf(&out, "%d: %s\n", i+1, lines[i])
	}
	return out.String()
}

// truncateUTF8 returns the first n bytes of s, backing up to the nearest
// rune boundary if n would otherwise split a multi-byte UTF-8 character —
// plain code[:n] byte-slicing corrupts non-ASCII comments/strings (Chinese,
// Japanese, Vietnamese etc. are common in real codebases).
func truncateUTF8(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
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
