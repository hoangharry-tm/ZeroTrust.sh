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

// Package poe runs opt-in, sandboxed proof-of-exploitability verification
// (--verify-poc) against BLOCK/HIGH findings: package a caller-supplied,
// already-built artifact (--poe-artifact) into a minimal runtime image, boot
// it in a network-isolated Docker container, fire an LLM-crafted HTTP
// request at the route that reaches the finding's sink, and grade the
// response.
//
// This is grey-box, not build-from-source: the caller provides the exact jar
// / bundled JS file / Python script / native binary they want tested, and PoE
// never compiles anything. That has two consequences worth being explicit
// about. First, it makes multi-language support tractable — supporting
// Java, Python, JavaScript/TypeScript, and Go is four small runtime-only
// Dockerfiles (internal/poe/dockerfiles/) instead of one build pipeline per
// language/build-tool combination. Second, it introduces a trust assumption:
// PoE does not verify the supplied artifact was actually built from the
// source tree being scanned — a stale or mismatched artifact will produce
// misleading results. Detecting that drift is a deliberate follow-up, not
// solved here; for now, a correct artifact is assumed.
//
// Scope, deliberate and not to be silently expanded:
//   - No external service provisioning (no DB/Redis/etc). Artifacts that need
//     a live dependency to boot cleanly fall back to finding.PoEInconclusive.
//   - One container per scan, not per finding — built and booted once, torn
//     down once, N exploit requests fired against the same instance.
//   - A failed or inconclusive attempt never lowers a finding's confidence.
//     Only finding.PoESuccess moves the needle (config.BoostPoEConfirmed).
//     A sandboxed miss doesn't prove the real deployment is safe — different
//     env vars, different DB state, etc. — so asymmetric trust applies here
//     the same way it does for the self-consistency check in
//     internal/semantic/analysis.
//
// See docs/architecture.md for the full design rationale.
package poe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
)

// ErrDockerUnavailable is returned by Run when the docker CLI is not on PATH.
// Callers must fail fast rather than silently skip verification.
var ErrDockerUnavailable = errors.New("poe: docker CLI not found on PATH")

// Verifier runs sandboxed PoC verification for a single scan.
type Verifier struct {
	llm   llm.Provider
	graph cpg_engine.Graph
}

// New returns a Verifier. graph is the CPG shared with the rest of the scan
// (used for call-graph route resolution); provider is the LLM used for
// exploit-request generation and response grading.
func New(provider llm.Provider, graph cpg_engine.Graph) *Verifier {
	return &Verifier{llm: provider, graph: graph}
}

// Run verifies eligible findings against a sandboxed instance of artifactPath
// (an already-built jar/script/bundle/binary supplied by the caller). root is
// the source tree — still needed for CPG-based route resolution, even though
// nothing is compiled from it. Returns findings with PoEResult populated (nil
// for ineligible ones) and confidence/severity updated for confirmed
// exploits. Never returns findings in a different order or count than the input.
func (v *Verifier) Run(ctx context.Context, root, artifactPath string, findings []finding.Finding) ([]finding.Finding, error) {
	if !dockerAvailable() {
		return nil, ErrDockerUnavailable
	}

	eligible, ineligible := partitionEligible(findings)
	out := make([]finding.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if _, isEligible := ineligible[i]; isEligible {
			out[i].PoEResult = &finding.PoEResult{Status: ineligible[i]}
		}
	}
	if len(eligible) == 0 {
		return out, nil
	}

	rt, err := detectArtifactRuntime(artifactPath)
	if err != nil {
		for i := range out {
			if out[i].PoEResult == nil {
				out[i].PoEResult = &finding.PoEResult{Status: finding.PoELanguageUnsupported}
			}
		}
		return out, nil
	}

	imageTag := fmt.Sprintf("zt-poe-%d", time.Now().UnixNano())
	slog.Info("poe: building sandbox image", "runtime", rt, "image", imageTag)
	if err := buildSandboxImage(ctx, artifactPath, imageTag, config.PoEBuildTimeout); err != nil {
		slog.Warn("poe: build failed — all eligible findings marked failed_sandbox", "err", err)
		for idx := range eligible {
			out[idx].PoEResult = &finding.PoEResult{
				Status:   finding.PoEFailedSandbox,
				DevTrace: truncate(err.Error(), 500),
			}
		}
		return out, nil
	}
	defer removeSandboxImage(context.Background(), imageTag)

	sb := &sandbox{imageTag: imageTag}
	if err := sb.boot(ctx); err != nil {
		slog.Warn("poe: sandbox boot failed — all eligible findings marked failed_sandbox", "err", err)
		for idx := range eligible {
			out[idx].PoEResult = &finding.PoEResult{
				Status:   finding.PoEFailedSandbox,
				DevTrace: truncate(err.Error(), 500),
			}
		}
		return out, nil
	}
	defer sb.teardown(context.Background())

	client := &http.Client{Timeout: config.PoEExploitTimeout}
	for idx := range eligible {
		out[idx].PoEResult = v.verifyOne(ctx, client, sb, root, out[idx])
		if out[idx].PoEResult.Status == finding.PoESuccess {
			out[idx].Confidence = minFloat(out[idx].Confidence+config.C.BoostPoEConfirmed, 1.0)
			out[idx].SeverityLabel = finding.SeverityFromConfidence(out[idx].Confidence)
		}
	}
	return out, nil
}

// verifyOne resolves a route, generates and fires an exploit request, and
// grades the response for a single finding. Never returns nil.
func (v *Verifier) verifyOne(ctx context.Context, client *http.Client, sb *sandbox, root string, f finding.Finding) *finding.PoEResult {
	route, ok := resolveRoute(v.graph, root, f)
	if !ok {
		return &finding.PoEResult{
			Status:   finding.PoEInconclusive,
			DevTrace: "no HTTP entry point found reaching this sink within the call-graph walk bound",
		}
	}

	req, err := generateExploitRequest(ctx, v.llm, f, route)
	if err != nil {
		return &finding.PoEResult{Status: finding.PoEFailedSandbox, DevTrace: truncate(err.Error(), 500)}
	}

	statusCode, body, err := fireRequest(ctx, client, sb.baseURL(), route.Method, req)
	if err != nil {
		return &finding.PoEResult{
			Status:       finding.PoEFailedTimeout,
			ExploitInput: fmt.Sprintf("%s %s", route.Method, req.Path),
			DevTrace:     truncate(err.Error(), 500),
		}
	}

	v2, rationale, err := gradeExploitResult(ctx, v.llm, f, statusCode, body)
	if err != nil {
		return &finding.PoEResult{
			Status:       finding.PoEInconclusive,
			ExploitInput: fmt.Sprintf("%s %s", route.Method, req.Path),
			DevTrace:     truncate(err.Error(), 500),
		}
	}

	result := &finding.PoEResult{
		ExploitInput: fmt.Sprintf("%s %s", route.Method, req.Path),
		DevTrace:     fmt.Sprintf("status=%d rationale=%s", statusCode, rationale),
		ExecSummary:  rationale,
	}
	switch v2 {
	case verdictConfirmed:
		result.Status = finding.PoESuccess
		result.Confidence = 1.0
	case verdictNoEffect:
		result.Status = finding.PoEFailedNoEffect
	default:
		result.Status = finding.PoEInconclusive
	}
	return result
}

// fireRequest sends an HTTP request built from req against baseURL and
// returns the status code and a size-capped response body.
func fireRequest(ctx context.Context, client *http.Client, baseURL, method string, req exploitRequest) (int, string, error) {
	path := req.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, baseURL+path, strings.NewReader(req.Body))
	if err != nil {
		return 0, "", err
	}
	for k, val := range req.Headers {
		httpReq.Header.Set(k, val)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

// partitionEligible splits findings into ones worth verifying (severity at or
// above config.C.PoEMinSeverity, in a config.C.PoESupportedLanguages
// language) and a map of index -> PoEStatus for ones that are not. Both gates
// are declarative config (see internal/config's "PoE eligibility policy"
// section) rather than hardcoded Go conditionals, so the escalation policy is
// inspectable/changeable via calibration.json without a code change.
func partitionEligible(findings []finding.Finding) (eligible []int, ineligible map[int]finding.PoEStatus) {
	minSeverity, ok := parseSeverityLabel(config.C.PoEMinSeverity)
	if !ok {
		minSeverity = finding.SeverityHigh // matches the compile-time default
	}
	languages := make(map[string]bool, len(config.C.PoESupportedLanguages))
	for _, lang := range config.C.PoESupportedLanguages {
		languages[lang] = true
	}

	ineligible = make(map[int]finding.PoEStatus)
	for i, f := range findings {
		// SeverityLabel constants are ordered most-to-least severe (BLOCK=0),
		// so "meets the minimum" means the label's value is <= the threshold's.
		if f.SeverityLabel > minSeverity {
			ineligible[i] = finding.PoENotAttempted
			continue
		}
		if !languages[finding.LangFromPath(f.Path)] {
			ineligible[i] = finding.PoELanguageUnsupported
			continue
		}
		eligible = append(eligible, i)
	}
	return eligible, ineligible
}

// parseSeverityLabel converts a canonical uppercase severity name ("BLOCK",
// "HIGH", ...) into its finding.SeverityLabel. Unlike finding.SeverityLabel's
// own UnmarshalJSON (which silently leaves the zero value — SeverityBlock —
// on an unrecognized string), this returns ok=false so callers can fall back
// to a safe compile-time default instead of misreading "unrecognized" as "BLOCK".
func parseSeverityLabel(name string) (finding.SeverityLabel, bool) {
	switch name {
	case "BLOCK":
		return finding.SeverityBlock, true
	case "HIGH":
		return finding.SeverityHigh, true
	case "MEDIUM":
		return finding.SeverityMedium, true
	case "LOW":
		return finding.SeverityLow, true
	case "SUPPRESSED":
		return finding.SeveritySuppressed, true
	default:
		return 0, false
	}
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
