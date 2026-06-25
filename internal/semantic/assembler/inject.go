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

// CPG-derived field injection (T5).
//
// InjectCPGFields populates each FunctionContext frame with structured ground-truth
// facts derived from the CPG (taint source params, sanitizer calls, auth annotations)
// and then strips the raw Code field. The LLM Semantic Scan therefore never receives
// raw source code — only structured CPG-derived signals plus its own ReAct reasoning.
//
// This separation of ground-truth (CPG) from interpretation (LLM) is the key
// architectural constraint from LLMxCPG (USENIX 2025).

package assembler

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// InjectCPGFields populates TaintSourceParams, SanitizerCalls, and AuthAnnotations
// for every frame in cc using CPG edge queries, then clears Code so raw source never
// reaches the LLM reasoning payload.
//
// Must be called after Assemble and before the context is serialised for the LLM.
func (a *Assembler) InjectCPGFields(ctx context.Context, cc *CallChainContext) error {
	slog.Debug("injecting CPG fields", slog.String("surface_id", cc.SurfaceID), slog.Int("frames", len(cc.Frames)))
	sinks, err := a.graph.PreFlaggedSinks()
	if err != nil {
		slog.Error("pre-flagged sinks query failed", "err", err)
		return fmt.Errorf("pre-flagged sinks: %w", err)
	}
	sinkIDs := make(map[string]struct{}, len(sinks))
	for _, s := range sinks {
		sinkIDs[s.NodeID] = struct{}{}
	}

	for i := range cc.Frames {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.injectFrame(&cc.Frames[i], sinkIDs); err != nil {
			slog.Error("inject frame failed", "err", err, slog.String("node_id", cc.Frames[i].NodeID))
			return fmt.Errorf("inject frame %s: %w", cc.Frames[i].NodeID, err)
		}
		cc.Frames[i].Code = "" // raw source must not reach the LLM payload
	}
	return nil
}

// injectFrame populates a single frame's CPG-derived fields using PDG edges and
// CallsMade heuristics.
func (a *Assembler) injectFrame(f *FunctionContext, sinkIDs map[string]struct{}) error {
	edges, err := a.graph.QueryEdges(f.NodeID, "")
	if err != nil {
		return fmt.Errorf("query edges: %w", err)
	}
	for _, e := range edges {
		// PDG edge whose target is a pre-flagged sink: the label is the tainted variable.
		if e.Type == cpg.EdgePDG && e.Label != "" {
			if _, ok := sinkIDs[e.ToID]; ok {
				f.TaintSourceParams = appendUnique(f.TaintSourceParams, e.Label)
			}
		}
	}
	for _, call := range f.CallsMade {
		if isSanitizer(call) {
			f.SanitizerCalls = appendUnique(f.SanitizerCalls, call)
		}
		if isAuthGuard(call) {
			f.AuthAnnotations = appendUnique(f.AuthAnnotations, call)
		}
	}
	return nil
}

// sanitizerPatterns are case-insensitive substrings that indicate a sanitizer call.
var sanitizerPatterns = []string{
	"sanitize", "validate", "escape", "encode", "clean", "strip", "filter",
}

// authGuardPatterns are case-insensitive substrings that indicate an auth check call.
var authGuardPatterns = []string{
	"preauthorize", "secured", "rolesallowed", "login_required", "requireauth",
	"checkpermission", "authorize", "authenticated", "verifypermission",
	"getsubject", "getprincipal", "currentuser", "sessionuser",
}

func isSanitizer(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range sanitizerPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isAuthGuard(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range authGuardPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// appendUnique appends s to slice only if not already present.
func appendUnique(slice []string, s string) []string {
	if slices.Contains(slice, s) {
		return slice
	}
	return append(slice, s)
}
