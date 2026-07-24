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

// Package analysis implements Reasoning Tier 3 — LLM Semantic Reasoning.
// The Scanner receives enriched surfaces that passed the contract check and
// lightweight triage stages (Tier 2). For each surface it makes one bounded
// LLM call with three evidence layers injected into the prompt: Security
// Contract Layer (SCL), Control Flow Predicate (CFP), and AI Failure Profile
// (AIP). It returns a structured JSON verdict parsed into a finding.Finding.
//
// When a CPG graph is attached (WithGraph), the LLM call becomes a bounded
// tool-calling loop instead of a single shot: the model may call a handful of
// read-only graph queries (get_callers, get_callees, get_neighbours_at_depth,
// query_nodes_by_file — see tools.go) to investigate one more hop before
// committing to a verdict, capped at maxToolCalls round-trips. This is
// deliberately not an open-ended agent loop — the cap makes per-surface cost
// computable in advance, and every tool call/result is logged, so the
// investigation is auditable the same way a graph query is independently
// re-runnable. Without a graph attached, Scanner falls back to the original
// single-shot Generate call unchanged.
package analysis

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/contracts"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
)

// maxToolCalls bounds the tool-calling loop per surface — a hard cap, not a
// budget the model can negotiate. Chosen to allow a couple of genuine
// follow-up hops ("who calls this", "is there an auth check nearby") without
// letting per-surface cost become unpredictable the way an open-ended agent
// loop's would.
//
// Raised from 4 to 8: headroom, not a response to hitting the old cap — at
// the time of this change, 0 real surfaces had ever exhausted 4 rounds. But
// two mechanisms now legitimately compose more rounds than before: the
// dual-tool confirmation gate can add a round on top of the single-hop
// chase-nudge, and the repeated (not single) zero-tool-call nudge means a
// slow-to-comply model consumes more of the budget just reaching real
// investigation. The tool-result cache (dispatchToolCached) keeps the actual
// cost of a longer chain low when nodes repeat across surfaces, so the
// latency/cost trade of a higher cap is smaller than it would have been
// before that existed.
const maxToolCalls = 8

// Scanner runs the LLM semantic reasoning pass over enriched surfaces.
type Scanner struct {
	provider llm.Provider
	root     string
	graph    cpg_engine.Graph // nil = no tool-calling loop, single-shot Generate only
	cache    *toolCache       // memoizes tool results across surfaces within one scan run
}

// WithRoot sets the project root directory for resolving relative sink file paths.
func (s *Scanner) WithRoot(root string) *Scanner {
	s.root = root
	return s
}

// WithGraph attaches a CPG graph, enabling the bounded tool-calling
// investigation loop (see package doc). Pass nil (or don't call WithGraph) to
// keep Scanner on the original single-shot Generate path.
func (s *Scanner) WithGraph(graph cpg_engine.Graph) *Scanner {
	s.graph = graph
	return s
}

// New returns a Scanner backed by the provided LLM provider.
func New(provider llm.Provider) *Scanner {
	return &Scanner{provider: provider, cache: newToolCache()}
}

// analysisOpts returns the LLM options for B5 analysis calls.
//
// NumCtx=16384: both locally-supported models exceed this comfortably
// (qwen2.5-coder:7b natively supports 32768; qwen3.5:9b up to 262144), so
// this isn't a model-capability ceiling — it's a deliberate local-inference
// latency/memory budget. B5 gets the largest window of any call site since
// it carries the full SCL+CFP+code+sink-context+AIP evidence bundle.
//
// Think: new(false) — thinking models (qwen3.5 and similar) default to
// emitting a chain-of-thought block before any content/tool-call when this
// isn't set. Observed in practice: qwen3.5:9b spent its entire NumPredict
// budget on invisible thinking and returned empty content (resp_len=0,
// done_reason=length) on the primary tool-enabled call for the large
// majority of surfaces in one run, only producing a real answer via the
// empty-response retry fallback below — which forces Think off but also
// drops tool access, meaning the bounded tool-calling loop (runToolLoop)
// never got a real chance to run; every surface silently degraded to a
// single-shot, tool-less call. Our prompt already supplies an explicit
// 5-step reasoning scaffold (see prompts/b5_analysis.md.tmpl) as the
// intended substitute for free-form chain-of-thought — a second, invisible
// round of the model's own thinking on top is redundant even when it
// doesn't blow the budget entirely, and catastrophic when it does.
func analysisOpts() *llm.Options {
	return &llm.Options{
		Temperature: 0.1,
		NumPredict:  1024,
		NumCtx:      16384,
		Think:       new(false),
		// JSON: the prompt's entire output contract is one JSON verdict
		// object; constrained decoding removes the "wrapped it in prose or a
		// markdown fence" failure class that parseVerdict's brace-slicing has
		// to work around today, rather than just mitigating it after the
		// fact. Left on in runToolLoop's toolOpts too — the JSON-format
		// constraint governs only the text "content" field, a separate
		// channel from tool_calls, so it doesn't stop the model from calling
		// a tool instead of answering.
		JSON: true,
	}
}

// surfaceDeadline is the per-surface LLM timeout.
const surfaceDeadline = 300 * time.Second

// Scan runs Tier 3 analysis on escalated surfaces concurrently.
// Returns one finding per surface. The caller (pathb) filters for
// exploitable vs. non-exploitable based on surface context (violation
// confirmation loop, taint mismatch handling).
func (s *Scanner) Scan(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]finding.Finding, error) {
	if len(surfaces) == 0 {
		return nil, nil
	}

	type indexedFinding struct {
		index    int
		finding  finding.Finding
		hasFound bool
	}

	results := make([]indexedFinding, len(surfaces))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(1) // serialize: safe for both local Ollama and rate-limited API providers

	for i, surface := range surfaces {
		g.Go(func() error {
			f, err := s.scanOne(gctx, surface)
			if err != nil {
				slog.Warn("analysis: scanOne error", slog.String("surface_id", surface.ID), "err", err)
				return nil
			}
			if f != nil {
				results[i] = indexedFinding{index: i, finding: *f, hasFound: true}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	findings := make([]finding.Finding, 0, len(surfaces))
	for _, rf := range results {
		if rf.hasFound {
			findings = append(findings, rf.finding)
		}
	}

	return findings, nil
}

func (s *Scanner) scanOne(ctx context.Context, surface enrichment.EnrichedSurface) (*finding.Finding, error) {
	slog.Debug(
		"analysis: input",
		"function", surface.FunctionName,
		"file", surface.File,
		"kind", surface.Kind,
		"contract_cwe", surface.ContractCWE,
		"has_sink_nodes", len(surface.SinkNodes) > 0,
		"code_len", len(surface.Code),
	)

	// Per-surface deadline prevents a single hung LLM call from blocking the entire batch.
	sctx, cancel := context.WithTimeout(ctx, surfaceDeadline)
	defer cancel()

	opts := analysisOpts()
	prompt := buildPrompt(surface, s.root)

	slog.Debug(
		"analysis: prompt",
		"prompt", prompt,
		"timeout", surfaceDeadline,
	)

	genStart := time.Now()
	var raw string
	var investigated bool
	var distinctToolsUsed int
	var err error
	if s.graph != nil {
		raw, investigated, distinctToolsUsed, err = s.runToolLoop(sctx, surface, prompt, opts)
	} else {
		raw, err = s.provider.Generate(sctx, prompt, opts)
	}
	genElapsed := time.Since(genStart)
	if err != nil {
		if sctx.Err() != nil {
			slog.Warn(
				"analysis: surface timeout",
				"surface_id", surface.ID,
				"function", surface.FunctionName,
				"timeout", surfaceDeadline,
			)
		} else {
			slog.Debug(
				"analysis: response",
				"err", err.Error(),
				"elapsed_ms", genElapsed.Milliseconds(),
			)
		}
		return nil, err
	}

	// Empty response retry: context overflow or output truncation.
	// Retry once with halved NumPredict and CoT forced off.
	if raw == "" {
		slog.Warn(
			"analysis: empty response, retrying with reduced num_predict",
			"surface_id", surface.ID,
		)
		retryOpts := *opts
		retryOpts.NumPredict = max(opts.NumPredict/2, 64)
		retryOpts.Think = new(false)
		raw, err = s.provider.Generate(sctx, prompt, &retryOpts)
		if err != nil || raw == "" {
			slog.Warn(
				"analysis: retry also returned empty, dropping surface",
				"surface_id", surface.ID,
			)
			return nil, nil
		}
	}

	slog.Debug(
		"analysis: response",
		"raw_resp", raw,
		"elapsed_ms", genElapsed.Milliseconds(),
	)

	verdict := parseVerdict(raw)
	slog.Debug(
		"analysis: parse_result",
		"exploitable", verdict.Exploitable,
		"cwe", verdict.CWE,
		"severity", verdict.Severity,
		"confidence", verdict.Confidence,
		"explanation", verdict.Explanation,
		"taint_mismatch", verdict.TaintMismatch,
	)

	// Mandatory-investigation gate: any CWE with contract coverage depends
	// on the call chain, not this function's text alone, to judge
	// correctly — originally NoSinkModel-only (e.g. CWE-862, no fixed sink
	// signature at all), broadened to every contract CWE after a live
	// SSRF false positive (see requiresInvestigation's doc comment): a
	// sink-anchor CWE can have a real taint path AND a real sink match and
	// STILL be wrong, if the caller validates the value before it ever
	// reaches this function — evidence that "looks complete" locally but
	// is missing the one fact that actually decides exploitability. A
	// model that answers without ever calling get_callers is guessing from
	// absence of evidence, not investigating — observed live in testing:
	// qwen3.5:9b confidently claimed "no authorization check" without
	// checking a single caller in 3 of 4 identical trial runs.
	//
	// Applies to BOTH verdict directions, not just exploitable=true. A
	// fabricated exploitable=false is at least as dangerous as a fabricated
	// exploitable=true: observed live — nudged for not investigating, the
	// model still made zero real tool calls, then wrote "Caller
	// AdminGoodsController.create is gated by @PreAuthorize" as its
	// justification for exploitable=false. That caller/annotation appears
	// nowhere in the actual evidence — it was invented, not read. Had this
	// only guarded the exploitable=true direction (as an earlier version of
	// this gate did), the fabricated confidence=0.95 "safe" verdict would
	// have gone on to make processB5Findings SUPPRESS the original DCC
	// violation outright (b5SuppressionThreshold=0.75) — a real structural
	// finding erased by invented evidence, permanently. Capping confidence
	// below that threshold here means an uninvestigated claim, in either
	// direction, can only leave the original violation's MEDIUM severity
	// unchanged for a human to review — never silently confirm OR dismiss it.
	if s.graph != nil && requiresInvestigation(surface.ContractCWE) && !investigated {
		slog.Warn("analysis: uninvestigated verdict for a call-chain-dependent CWE — downgrading",
			"surface_id", surface.ID, "cwe", surface.ContractCWE,
			"exploitable", verdict.Exploitable, "original_confidence", verdict.Confidence)
		verdict.Confidence = min(verdict.Confidence, uninvestigatedConfidenceCap)
		verdict.Explanation = "[uninvestigated: no caller chain checked] " + verdict.Explanation
		verdict.Summary = "[uninvestigated] " + verdict.Summary
	}

	// Single-tool-type guard: a defense-in-depth downstream cap matching the
	// in-loop dual-tool nudge in runToolLoop — fires if the model ignored
	// that nudge (or the round budget ran out before it could comply) and
	// still landed on a high-confidence exploitable verdict backed by only
	// one kind of investigation. Investigated=true already means the
	// uninvestigated gate above didn't fire, so this catches the narrower
	// "investigated, but only from one angle" gap it can't see.
	if s.graph != nil && investigated && requiresInvestigation(surface.ContractCWE) &&
		distinctToolsUsed < 2 && verdict.Exploitable && verdict.Confidence >= dualToolConfidenceThreshold {
		slog.Warn("analysis: high-confidence verdict from a single tool type — downgrading",
			"surface_id", surface.ID, "cwe", surface.ContractCWE,
			"distinct_tools_used", distinctToolsUsed, "original_confidence", verdict.Confidence)
		verdict.Confidence = min(verdict.Confidence, uninvestigatedConfidenceCap)
		verdict.Explanation = "[single investigative angle: only one tool type used] " + verdict.Explanation
		verdict.Summary = "[single angle] " + verdict.Summary
	}

	// Hedge-language guard: catches a DIFFERENT failure mode than the gate
	// above — this fires even when investigation DID happen. Observed live on
	// a real litemall scan: QiniuStorage.java:71 got exploitable=true,
	// confidence=0.9, severity=HIGH with explanation "Caller chain includes
	// controllers... where authorization checks like @PreAuthorize are
	// typically enforced upstream." The model investigated, found nothing
	// concrete, said so in its own words ("typically", "likely", "may be" —
	// i.e. "I didn't actually verify this"), and then reported high
	// confidence anyway — self-contradictory. cited @PreAuthorize itself was
	// also fabricated (zero occurrences anywhere in litemall; it uses Apache
	// Shiro). A model's own hedge word is a stronger, cheaper signal than any
	// prompt instruction: if it says "typically"/"likely"/"probably"/"may be"
	// about an upstream check, it is explicitly telling us it guessed.
	//
	// Originally gated on the explanation also containing "auth" — broadened
	// after a live Grafana scan finding (ds_proxy.go logRequest, CWE-22) whose
	// explanation literally said "...this remains uncertain but leans toward
	// exploitable" and was NOT downgraded, because the CWE was path traversal,
	// not auth, and the "auth" substring check silently exempted it. Hedge
	// language is exactly as much a "the model is guessing" signal for
	// injection/SSRF/path-traversal CWEs as it is for CWE-862 — the topic
	// gate never should have been auth-specific, matching every other
	// CWE-agnostic broadening made this session.
	if verdict.Exploitable && hedgesOnUnverifiedClaim(verdict.Explanation) {
		slog.Warn("analysis: verdict explanation hedges on an unverified claim — downgrading",
			"surface_id", surface.ID, "cwe", surface.ContractCWE,
			"original_confidence", verdict.Confidence, "explanation", verdict.Explanation)
		verdict.Confidence = min(verdict.Confidence, uninvestigatedConfidenceCap)
		verdict.Explanation = "[hedged claim of an unverified guard] " + verdict.Explanation
		verdict.Summary = "[hedged/unverified] " + verdict.Summary
	}

	// Self-consistency check: second evidence-only call for high-confidence
	// exploitable findings, to catch single-pass overconfidence.
	if verdict.Exploitable && verdict.Confidence >= 0.85 {
		verdict = s.selfConsistencyCheck(sctx, surface, verdict)
	}

	f := verdictToFinding(surface, verdict)
	return &f, nil
}

// requiresInvestigation reports whether cwe should require the model to
// check the call chain (get_callers) before an "exploitable" verdict can be
// trusted at face value.
//
// Originally NoSinkModel-only (e.g. CWE-862, which literally has no fixed
// sink signature to match). Broadened to every CWE with contract coverage —
// found live on a real Grafana scan: a CWE-918 (SSRF) surface, `fetch()`,
// got exploitable=true/HIGH/0.95 for passing a URL straight to client.Do()
// with "no validation" — except the validation existed, in the CALLER
// (`Handler`, which regex-validates the value as a 32-char MD5 hash before
// ever invoking fetch()). B5 never checked, because only NoSinkModel CWEs
// had a mandatory investigation gate — sink-anchor CWEs (SSRF, path
// traversal, injection, ...) had a taint path AND a real sink match, so the
// evidence "looked complete" even though it was missing exactly the same
// kind of fact CWE-862 already knew to ask about: what does the caller do
// before this value gets here. Upstream input validation is exactly as easy
// to miss as an upstream auth check, and for the identical reason — it's
// idiomatic to validate at the boundary and call the "unsafe-looking"
// function only after, which is invisible from a single function's own text.
func requiresInvestigation(cwe string) bool {
	_, ok := contracts.Rulebook[cwe]
	return ok
}

// uninvestigatedConfidenceCap bounds confidence for either verdict direction
// on a call-chain-dependent CWE when the model never actually investigated
// the call chain. Deliberately below both thresholds that would let an
// unverified claim take an irreversible action on the original DCC
// violation: b5ElevationThreshold (reasoning.go) so it can't elevate to
// HIGH, and b5SuppressionThreshold (reasoning.go, 0.75) so a fabricated
// "safe" claim can't suppress the violation outright either. Either way the
// original MEDIUM finding surfaces unchanged for a human to check, which is
// the honest thing to do with an unverified claim in either direction.
const uninvestigatedConfidenceCap = 0.5

// dualToolConfidenceThreshold is the confidence bar above which a gated
// exploitable=true verdict must be backed by at least 2 distinct tool types,
// not just 2+ calls to the same one. Matches selfConsistencyCheck's existing
// 0.85 threshold below — both are "this claim is expensive enough to double
// check" gates.
const dualToolConfidenceThreshold = 0.85

// hedgeWords are terms that signal the model is speculating rather than
// reporting something it actually verified in evidence. Expanded after a
// live Grafana scan finding whose explanation said "...remains uncertain but
// leans toward exploitable" — a self-admission of guessing that the
// original, narrower list (borrowed from a single litemall incident) didn't
// contain at all.
var hedgeWords = []string{
	"typically", "likely", "probably", "presumably", "may be", "usually",
	"uncertain", "leans toward", "leaning toward", "not entirely sure",
	"can't be certain", "cannot be certain", "might be", "could be",
}

// hedgesOnUnverifiedClaim reports whether explanation contains one of
// hedgeWords, signaling the model is speculating rather than reporting
// something it actually verified in evidence. Deliberately text-based rather
// than tool-call-based: this guard exists specifically for the case where a
// tool WAS called (so requiresInvestigation's gate doesn't fire) but the
// evidence it returned didn't actually confirm anything, and the model's own
// wording says so.
//
// Originally required the explanation to also contain "auth" — dropped that
// gate after finding it silently exempted non-auth CWEs (a CWE-22 path
// traversal explanation hedging with "uncertain but leans toward
// exploitable" was never auth-related and evaded the guard entirely). Hedge
// language is topic-agnostic: a model telling you it's guessing is the same
// signal whether the guess is about an auth check, a sanitizer, or a filter.
func hedgesOnUnverifiedClaim(explanation string) bool {
	lower := strings.ToLower(explanation)
	for _, w := range hedgeWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// runToolLoop drives the bounded tool-calling investigation loop: the model
// gets up to maxToolCalls round-trips to call CPG tools before it must answer.
// Returns the model's final text content (the same shape scanOne's
// single-shot Generate path returns), whether at least one tool call was
// actually made, and any error.
//
// Mandatory-investigation gate: for any CWE with contract coverage
// (requiresInvestigation — originally NoSinkModel-only, broadened to all
// contract CWEs after a live SSRF false positive that only a caller check
// would have caught, see requiresInvestigation's doc comment), a model that
// tries to answer before ever calling a tool is refused — a corrective
// nudge, not silently accepted — since a live test showed this is a real
// failure mode, not a hypothetical one: qwen3.5:9b answered "exploitable, no
// auth check found" without calling get_callers a single time in 3 of 4
// identical trials, despite the prompt already naming the tool and
// explaining when to use it. Telling the model what to do isn't the same as
// it reliably doing it; this makes the loop itself refuse to accept an
// uninvestigated verdict rather than relying on the model to comply
// voluntarily.
//
// Re-nudged on EVERY no-tool-call round, not just once — an earlier version
// nudged a single time, then accepted whatever came back. Found live: this
// let a model treat the nudge as something to react to rather than comply
// with — getTokenProvider answered exploitable=true on round 1, got nudged,
// then answered again on round 2 (still zero tool calls) and flipped to
// exploitable=false, with no new evidence gathered between the two answers
// and an explanation that fabricated tool results it never fetched. A tool
// call must inform the verdict, not follow one that's already formed;
// accepting any post-nudge answer at all — genuine, refused, or fabricated —
// treated tool use as optional. Bounded the same way as before (maxToolCalls
// rounds total, then the forced tools-disabled final answer + the
// uninvestigated-confidence-cap safety net below), so a surface still can
// never loop unboundedly — it just can't buy its way past the gate by
// answering again without ever actually calling anything.
//
// Single-hop-then-stop gate: found live on a real Grafana scan — fetch()
// (CWE-918 SSRF) was correctly nudged into calling get_callers, found its
// immediate caller (Fetch, a thin wrapper with no validation), and answered
// exploitable=true from that one hop alone. The actual validating caller
// (Handler, which regex-checks the value as a 32-char MD5 hash) was two hops
// up — Handler calls Fetch calls fetch(). The zero-tool-calls gate above
// stops outright fabrication; it does nothing to stop a model that
// genuinely investigates once, finds an unguarded intermediate wrapper, and
// concludes from that alone without checking whether ITS caller validates.
// Applied asymmetrically (exploitable=true only, not exploitable=false) to
// match this codebase's existing "prefer false negative over false
// positive" bias (see the prompt's ground rules) — an unresolved SAFE
// verdict after 1 hop just means the original DCC violation surfaces
// unchanged for a human, which is the same honest outcome as Example 7 in
// the prompt; an unresolved EXPLOITABLE verdict after 1 hop is exactly the
// fabricated-looking-plausible failure mode this whole gate exists to catch.
func (s *Scanner) runToolLoop(ctx context.Context, surface enrichment.EnrichedSurface, prompt string, opts *llm.Options) (string, bool, int, error) {
	toolOpts := *opts
	toolOpts.Tools = analysisToolDefs()
	// JSON:true stays on even with Tools set — Ollama's/OpenAI's JSON-format
	// constraint governs the text "content" field only, a separate channel
	// from tool_calls, so it doesn't block or interfere with the model
	// choosing to call a tool instead of answering. This matters because most
	// surfaces answer on the SAME round they stop calling tools (toolOpts,
	// not a separate no-Tools opts) — only the rare cap-exhaustion path below
	// uses plain opts — so clearing JSON here would leave the common case
	// unconstrained and defeat the point of setting it in analysisOpts.
	gated := requiresInvestigation(surface.ContractCWE)

	messages := []llm.Message{{Role: llm.RoleUser, Content: prompt}}
	investigated := false
	nudgeCount := 0
	chased := false
	diversityNudged := false
	toolCallCount := 0
	lastResultEmpty := false
	distinctTools := make(map[string]bool)

	for round := range maxToolCalls {
		msg, err := s.provider.Chat(ctx, messages, &toolOpts)
		if err != nil {
			return "", investigated, len(distinctTools), err
		}
		if len(msg.ToolCalls) == 0 {
			if gated && !investigated {
				// Re-nudge on EVERY no-tool-call round, not just once. Found
				// live on a real Grafana scan: getTokenProvider answered
				// exploitable=true on round 1, got the (old) single nudge,
				// then answered again on round 2 — still without calling any
				// tool — and flipped to exploitable=false. No new evidence
				// was gathered between the two answers; the model was
				// reacting to being told it should have investigated, not
				// investigating. Worse, its own explanation text on round 2
				// FABRICATED tool results it never actually fetched ("get_callers
				// returned no callers..."), mimicking the narrative shape of
				// the worked examples without doing the underlying work. A
				// single corrective nudge that then accepts ANY answer —
				// genuine, refused, or fabricated — treats tool use as an
				// optional retrofit on top of an already-formed verdict,
				// which is backwards: the tool call must inform the verdict,
				// not follow it. Nudging on every round (bounded naturally by
				// maxToolCalls, same as before) means no answer is ever
				// accepted while gated and uninvestigated with budget
				// remaining — only real investigation or genuine budget
				// exhaustion (which still falls through to the
				// uninvestigated-confidence-cap safety net below) ends this.
				nudgeCount++
				slog.Warn("analysis: investigation gate — model answered before calling any tool, re-nudging",
					"surface_id", surface.ID, "cwe", surface.ContractCWE, "nudge_count", nudgeCount)
				messages = append(messages, msg, llm.Message{
					Role: llm.RoleUser,
					Content: "You answered without calling a tool. An answer is not accepted for this CWE until " +
						"you have actually called get_callers or get_neighbours_at_depth — restating or revising " +
						"your answer without calling one does not count, and citing a tool result you did not " +
						"actually fetch is fabrication, not investigation. Before trusting this function's own " +
						"text, you must check whether the caller already validates, sanitizes, or gates this " +
						"value — an authorization check for CWE-862, or input validation/sanitization for " +
						"injection, SSRF, or path-traversal CWEs. Pick whichever tool answers the question you " +
						"actually have: get_callers if you want to see a specific caller's code, or " +
						"get_neighbours_at_depth if you want to search more widely in one call. Call one now, " +
						"using \"This surface's CPG node ID\" from the evidence above as function_id.",
				})
				continue
			}
			candidateVerdict := parseVerdict(msg.Content)
			if gated && investigated && toolCallCount < 2 && !chased && candidateVerdict.Exploitable {
				slog.Warn("analysis: investigation gate — exploitable verdict after only 1 hop, chasing one more",
					"surface_id", surface.ID, "cwe", surface.ContractCWE, "last_result_empty", lastResultEmpty)
				chased = true
				// Branches on what the one hop actually returned — found live
				// (scan log, real Grafana run): when get_callers came back
				// EMPTY (no callers at all — common, since a Go router's
				// apiRoute.Any(path, handler) idiom isn't modeled as a caller
				// edge by Joern's static call graph), the OLD version of this
				// nudge said "call get_callers again on the caller you just
				// found" — nonsensical when there IS no caller, and "that
				// same node ID" referred to nothing. Faced with an
				// inapplicable instruction, the model answered directly
				// instead of calling anything, which defeated the entire
				// point of this nudge for roughly half of all real cases.
				var nudgeText string
				if lastResultEmpty {
					nudgeText = "You concluded exploitable after get_callers returned NO callers at all. " +
						"An empty result means the graph has no caller EDGE here — it does NOT mean the " +
						"function is unreachable or unguarded; it commonly means a router registers this " +
						"handler in a way the static call graph doesn't model (e.g. passing it as a value " +
						"rather than calling it directly), which hides real production callers from you. " +
						"There is no caller node ID to re-query. Call get_neighbours_at_depth using " +
						"\"This surface's CPG node ID\" from the evidence above (not a caller's ID — there " +
						"isn't one) at depth 2 or more, to search more widely than a direct caller edge before " +
						"concluding no guard exists. Then answer."
				} else {
					nudgeText = "You concluded exploitable after checking only one caller, which showed no guard. " +
						"\"No guard in this one caller\" is not the same as \"no guard exists\" — a guard can live " +
						"one more hop up the chain (if that caller is itself a thin wrapper), or off to the side " +
						"in a filter/middleware/shared validator that a single caller hop wouldn't show at all. " +
						"Pick whichever fits what you've already seen: call get_callers again on the node ID of " +
						"the caller you just found, to check one hop further up the chain — OR call " +
						"get_neighbours_at_depth (depth 2+) on that same node ID to search more widely for a " +
						"guard that isn't a direct caller. Then answer."
				}
				messages = append(messages, msg, llm.Message{Role: llm.RoleUser, Content: nudgeText})
				continue
			}
			// Dual-tool confirmation gate: a high-confidence exploitable
			// verdict built entirely from ONE tool type (however many times
			// it was called) is still a single kind of evidence — e.g. three
			// get_callers calls walking up a chain never actually asks the
			// "is the guard somewhere other than a direct caller" question
			// get_neighbours_at_depth answers. Found live: the fetch()/
			// Handler SSRF false positive was exactly this shape, a single
			// caller hop that missed a guard two levels up a DIFFERENT
			// investigation direction would have caught faster. Fires once
			// per surface, only for exploitable=true at high confidence —
			// matches the same "prefer false negative" asymmetry as the
			// rest of this gate; an unresolved safe verdict just leaves the
			// original finding for a human, an unresolved high-confidence
			// exploitable claim built on one investigative angle is the
			// expensive direction to get wrong.
			if gated && investigated && !diversityNudged && len(distinctTools) < 2 &&
				candidateVerdict.Exploitable && candidateVerdict.Confidence >= dualToolConfidenceThreshold {
				diversityNudged = true
				usedTool := "get_callers"
				suggestTool := "get_neighbours_at_depth"
				if distinctTools["get_neighbours_at_depth"] {
					usedTool, suggestTool = "get_neighbours_at_depth", "get_callers"
				}
				slog.Warn("analysis: investigation gate — high-confidence verdict from a single tool type, requesting a second angle",
					"surface_id", surface.ID, "cwe", surface.ContractCWE, "confidence", candidateVerdict.Confidence, "tool_used", usedTool)
				messages = append(messages, msg, llm.Message{
					Role: llm.RoleUser,
					Content: fmt.Sprintf(
						"You reached %.2f confidence using only %s, however many times you called it — that's "+
							"one kind of evidence, not two independent checks. Before finalizing at this "+
							"confidence, call %s as well: it answers a different question than %s does, and a "+
							"guard living outside the direct caller chain (a filter, middleware, or shared "+
							"validator) would never show up no matter how many times you call %s. Call %s now.",
						candidateVerdict.Confidence, usedTool, suggestTool, usedTool, usedTool, suggestTool,
					),
				})
				continue
			}
			return msg.Content, investigated, len(distinctTools), nil
		}

		messages = append(messages, msg)
		investigated = true
		toolCallCount += len(msg.ToolCalls)
		for _, tc := range msg.ToolCalls {
			distinctTools[tc.Name] = true
			result := dispatchToolCached(s.graph, s.root, tc.Name, tc.Arguments, s.cache)
			lastResultEmpty = toolResultIsEmpty(result)
			slog.Debug(
				"analysis: tool call",
				"surface_id", surface.ID,
				"round", round,
				"tool", tc.Name,
				"arguments", tc.Arguments,
				"result", result,
			)
			messages = append(messages, llm.Message{
				Role:       llm.RoleTool,
				Content:    result,
				ToolCallID: tc.ID,
			})
		}
	}

	// Cap hit and the model still hasn't answered — force a final, tools-disabled
	// call so a surface can never silently exceed its tool-call budget.
	slog.Debug("analysis: tool call budget exhausted, forcing final answer",
		"surface_id", surface.ID, "max_tool_calls", maxToolCalls)
	messages = append(messages, llm.Message{
		Role:    llm.RoleUser,
		Content: "You've used your available tool calls. Answer now with the JSON verdict — no more tool calls.",
	})
	final, err := s.provider.Chat(ctx, messages, opts) // opts, not toolOpts: no Tools this time
	if err != nil {
		return "", investigated, len(distinctTools), err
	}
	return final.Content, investigated, len(distinctTools), nil
}

// selfConsistencyCheck runs a second, independent, deliberately lower-context
// LLM call to sanity-check a high-confidence exploitable verdict. This is NOT
// self-consistency in the literature sense (Wang et al. 2022 — resampling the
// SAME prompt and majority-voting); it is a cheap adversarial second opinion
// from a differently-scoped question. Anchor the code window on the sink line
// (same as buildPrompt does for B5 itself) rather than a blind head-cut, and
// name the CWE being checked — a prior version passed a generic "does this
// look vulnerable" question with an arbitrary 800-byte head-truncated
// snippet that often didn't even include the sink call, which invited
// disagreement for the wrong reason (surface pattern-matching on irrelevant
// code) rather than a genuine second read of the same evidence. If the
// second call disagrees, confidence is downgraded.
func (s *Scanner) selfConsistencyCheck(ctx context.Context, surface enrichment.EnrichedSurface, v Verdict) Verdict {
	const budget = 800
	code := stripIndent(surface.Code)
	if len(code) > budget {
		if surface.SinkFile == surface.File && surface.SinkLine > 0 && surface.SinkLine >= surface.Line {
			code = truncateAroundLine(code, surface.SinkLine-surface.Line, budget)
		} else {
			code = truncateUTF8(code, budget) + "\n...[truncated]"
		}
	}
	probe := fmt.Sprintf(
		"Independent second opinion — you have not seen any prior analysis of this code.\n"+
			"Does this code contain a real, exploitable %s vulnerability? Answer only: YES or NO\n\n```\n%s\n```",
		v.CWE, code)
	raw, err := s.provider.Generate(ctx, probe, &llm.Options{Temperature: 0.0, NumPredict: 8, NumCtx: 4096, Think: new(false)})
	if err != nil {
		return v
	}
	upper := strings.ToUpper(raw)
	if strings.Contains(upper, "NO") && !strings.Contains(upper, "YES") {
		slog.Info("analysis: self_consistency downgrade",
			"surface_id", surface.ID, "original_confidence", v.Confidence)
		v.Confidence -= 0.3
		if v.Confidence < 0 {
			v.Confidence = 0
		}
		if v.Confidence < 0.6 {
			v.Exploitable = false
		}
	}
	return v
}
