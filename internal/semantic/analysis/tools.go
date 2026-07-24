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

package analysis

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/pkg/llm"
)

// CPG tool-calling: lets a bounded number of Analysis calls investigate the
// graph directly (who calls this, what does this call, what's within N hops)
// instead of committing to a verdict from only the pre-fetched evidence
// bundle. This is deliberately narrow — four read-only Graph queries, no
// taint re-analysis, no code mutation — and bounded by maxToolCalls in
// analysis.go, not by how many calls the model decides it wants.

// toolNodeSummary is the compact JSON shape returned for each cpg_engine.Node
// a tool call surfaces.
//
// Code is a small ±toolCodeContextLines window of the node's actual source,
// not just its bare declaration line — added after a real bug: get_callers/
// get_callees originally returned only {id, name, file, line}, so a model
// investigating a caller for an authorization annotation had no way to
// actually see one, ever, regardless of how well it investigated. It
// couldn't verify a claim like "caller has @PreAuthorize" — it could only
// guess, and it did: fabricated framework-mechanism claims turned up in
// several real litemall findings. Reading the real file (the same
// readSinkContext helper used for the SINK CONTEXT prompt section) instead
// of trusting Joern's METHOD.code property specifically, since that
// property is typically just the declaration line and doesn't include
// annotations/decorators sitting on the line(s) above it — which is exactly
// where a real @PreAuthorize, @RequiresPermissions, or similar would be.
type toolNodeSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	File string `json:"file"`
	Line int    `json:"line"`
	Code string `json:"code,omitempty"`
}

// toolCodeContextLines bounds the code window attached to each tool-result
// node: enough to catch an annotation/decorator directly above a
// declaration plus the first few lines of the body, without letting a
// caller list with many results balloon the prompt (a get_callers call can
// return a dozen+ nodes; unbounded per-node code would multiply badly).
const toolCodeContextLines = 3

// maxToolResultNodes caps how many nodes any single tool call returns.
// get_callers/get_callees are naturally small in practice (a function
// usually has a handful of direct callers), but get_neighbours_at_depth (a
// BFS in both directions) and query_nodes_by_file have no such natural
// ceiling — found live on a real Grafana scan: a single depth-2
// get_neighbours_at_depth call returned 1,361 nodes, ballooning the running
// conversation to ~560,000 characters (~8.5x over NumCtx=16384 tokens' worth
// of budget). The model's next call came back as unparseable garbage, and
// that surface's verdict silently defaulted to the zero-value Verdict{} —
// losing a surface that had otherwise done the most genuinely diligent
// investigation of the whole scan. 25 is generous enough to show real
// evidence (a handful of callers/callees plus their code) while keeping the
// worst case bounded and predictable.
const maxToolResultNodes = 25

// toolResultPayload is the wire shape for every CPG tool call. Always an
// object, never a bare array — a capped result MUST say so explicitly
// (Truncated/Total), because a bare truncated array is indistinguishable
// from a complete one, and "I searched and found nothing" is exactly the
// claim the investigation-gate machinery in analysis.go treats as strong
// evidence. Silently truncating without saying so would manufacture false
// "no guard found" evidence out of an incomplete search.
type toolResultPayload struct {
	Results   []toolNodeSummary `json:"results"`
	Total     int               `json:"total"`
	Truncated bool              `json:"truncated,omitempty"`
}

func summarize(nodes []cpg_engine.Node, root string) toolResultPayload {
	total := len(nodes)
	truncated := false
	if len(nodes) > maxToolResultNodes {
		nodes = nodes[:maxToolResultNodes]
		truncated = true
	}
	out := make([]toolNodeSummary, len(nodes))
	for i, n := range nodes {
		out[i] = toolNodeSummary{
			ID: n.ID, Name: n.Name, File: n.File, Line: n.Line,
			Code: readSinkContext(root, n.File, n.Line, toolCodeContextLines),
		}
	}
	return toolResultPayload{Results: out, Total: total, Truncated: truncated}
}

// functionIDArgs is the argument shape shared by get_callers, get_callees,
// and get_neighbours_at_depth — all keyed off a CPG node ID.
type functionIDArgs struct {
	FunctionID string `json:"function_id"`
	Depth      int    `json:"depth,omitempty"` // only used by get_neighbours_at_depth
}

type queryNodesByFileArgs struct {
	File     string `json:"file"`
	NodeType string `json:"node_type"` // e.g. "METHOD", "CALL"
}

// analysisTools returns the tool schemas offered to the model. graph is
// captured by the returned dispatch closures — see dispatchTool.
func analysisToolDefs() []llm.ToolDef {
	const truncationNote = " The result is an object with \"results\" (an array, capped at 25 entries), " +
		"\"total\" (the real count, which can be larger), and \"truncated\" (true if you're only seeing " +
		"part of it). If truncated is true, the shown results are a SAMPLE, not the full picture — do not " +
		"conclude \"no guard exists\" just because none of the shown entries have one; a guard could be " +
		"among the entries you weren't shown."
	return []llm.ToolDef{
		{
			Name: "get_callers",
			Description: "List the functions that directly call the given CPG function ID, each with a short " +
				"source-code snippet (a few lines around its declaration, including any annotation/decorator " +
				"directly above it). function_id must be a real CPG node ID — either \"This surface's CPG node " +
				"ID\" given in the evidence above, or an ID returned by a previous tool call. Never guess a " +
				"file:function-name string as function_id; it will not match anything and will silently return " +
				"an empty result. Base any claim about a caller's authorization mechanism ONLY on that caller's " +
				"own \"code\" field in the result — an empty or absent code field means you could not verify " +
				"anything about it, not that a check exists." + truncationNote,
			Parameters: json.RawMessage(`{"type":"object","properties":{"function_id":{"type":"string"}},"required":["function_id"]}`),
		},
		{
			Name: "get_callees",
			Description: "List the functions directly called by the given CPG function ID, each with a short " +
				"source-code snippet (a few lines around its declaration). function_id must be a real CPG node " +
				"ID — either \"This surface's CPG node ID\" given in the evidence above, or an ID returned by a " +
				"previous tool call. Never guess a file:function-name string as function_id; it will not match " +
				"anything and will silently return an empty result." + truncationNote,
			Parameters: json.RawMessage(`{"type":"object","properties":{"function_id":{"type":"string"}},"required":["function_id"]}`),
		},
		{
			Name: "get_neighbours_at_depth",
			Description: "BFS from the given CPG function ID up to depth hops in both caller and callee " +
				"directions, each result with a short source-code snippet. Use this to check for an auth check " +
				"or sanitizer within a few calls of this function. function_id must be a real CPG node ID — " +
				"either \"This surface's CPG node ID\" given in the evidence above, or an ID returned by a " +
				"previous tool call. A wide/dense codebase can have hundreds of nodes within a couple of hops — " +
				"prefer depth=2 first; only increase depth if you have tool-call budget left and depth=2 wasn't " +
				"enough." + truncationNote,
			Parameters: json.RawMessage(`{"type":"object","properties":{"function_id":{"type":"string"},"depth":{"type":"integer","minimum":1,"maximum":5}},"required":["function_id","depth"]}`),
		},
		{
			Name:        "query_nodes_by_file",
			Description: "List all CPG nodes of a given type (e.g. METHOD, CALL) in a specific source file." + truncationNote,
			Parameters:  json.RawMessage(`{"type":"object","properties":{"file":{"type":"string"},"node_type":{"type":"string"}},"required":["file","node_type"]}`),
		},
	}
}

// toolCache memoizes dispatchTool results within a single scan run. Safe
// because the CPG is an immutable snapshot for the duration of a scan — the
// same tool name + arguments always produces the same result, so this is a
// pure latency/DB-load win with zero behavior change. Found live: many
// surfaces in the same file/package investigate overlapping parts of the
// call graph (shared callers, shared proxy sinks) — e.g. several different
// surfaces in pluginproxy/ds_proxy.go all independently call get_callers on
// the same ApplyRoute node. Scoped to one Scanner instance (one scan run),
// never shared across scans/projects, since different CPG builds have
// different graphs.
type toolCache struct {
	mu sync.Mutex
	m  map[string]string
}

func newToolCache() *toolCache {
	return &toolCache{m: make(map[string]string)}
}

// dispatchToolCached wraps dispatchTool with the cache above. cache may be
// nil (caching disabled). Error results are deliberately never cached: a
// failed call means "this couldn't be resolved," not "the answer is empty,"
// and errors are cheap to retry rather than risk replaying a transient
// failure forever.
func dispatchToolCached(graph cpg_engine.Graph, root, name, argumentsJSON string, cache *toolCache) string {
	if cache == nil {
		return dispatchTool(graph, root, name, argumentsJSON)
	}
	key := name + "|" + argumentsJSON

	cache.mu.Lock()
	if cached, ok := cache.m[key]; ok {
		cache.mu.Unlock()
		slog.Debug("analysis: tool cache hit", "tool", name, "args", truncateStr(argumentsJSON, 200))
		return cached
	}
	cache.mu.Unlock()

	result := dispatchTool(graph, root, name, argumentsJSON)

	if !strings.Contains(result, `"error"`) {
		cache.mu.Lock()
		cache.m[key] = result
		cache.mu.Unlock()
	}
	return result
}

// dispatchTool executes one tool call against graph and returns a
// JSON-encoded result string — always valid JSON, even on error (an
// {"error":"..."} object), since the result is fed straight back to the
// model as a tool-result message.
func dispatchTool(graph cpg_engine.Graph, root, name, argumentsJSON string) string {
	slog.Debug("dispatching analysis tool",
		"tool", name, "args", truncateStr(argumentsJSON, 200))

	switch name {
	case "get_callers":
		var args functionIDArgs
		if err := json.Unmarshal([]byte(argumentsJSON), &args); err != nil {
			slog.Warn("tool get_callers: invalid args", "error", err)
			return toolError(err)
		}
		nodes, err := graph.GetCallers(args.FunctionID)
		if err != nil {
			return toolError(err)
		}
		result := toolResult(summarize(nodes, root))
		slog.Debug("tool get_callers completed", "function_id", args.FunctionID, "results", len(nodes), "truncated", len(nodes) > maxToolResultNodes)
		return result

	case "get_callees":
		var args functionIDArgs
		if err := json.Unmarshal([]byte(argumentsJSON), &args); err != nil {
			slog.Warn("tool get_callees: invalid args", "error", err)
			return toolError(err)
		}
		nodes, err := graph.GetCallees(args.FunctionID)
		if err != nil {
			return toolError(err)
		}
		result := toolResult(summarize(nodes, root))
		slog.Debug("tool get_callees completed", "function_id", args.FunctionID, "results", len(nodes), "truncated", len(nodes) > maxToolResultNodes)
		return result

	case "get_neighbours_at_depth":
		var args functionIDArgs
		if err := json.Unmarshal([]byte(argumentsJSON), &args); err != nil {
			slog.Warn("tool get_neighbours_at_depth: invalid args", "error", err)
			return toolError(err)
		}
		if args.Depth <= 0 {
			args.Depth = 2
		}
		if args.Depth > 5 {
			args.Depth = 5
		}
		nodes, err := graph.GetNeighboursAtDepth(args.FunctionID, args.Depth)
		if err != nil {
			return toolError(err)
		}
		result := toolResult(summarize(nodes, root))
		slog.Debug("tool get_neighbours_at_depth completed",
			"function_id", args.FunctionID, "depth", args.Depth, "results", len(nodes), "truncated", len(nodes) > maxToolResultNodes)
		return result

	case "query_nodes_by_file":
		var args queryNodesByFileArgs
		if err := json.Unmarshal([]byte(argumentsJSON), &args); err != nil {
			slog.Warn("tool query_nodes_by_file: invalid args", "error", err)
			return toolError(err)
		}
		nodes, err := graph.QueryNodesByFile(args.File, cpg_engine.NodeType(args.NodeType))
		if err != nil {
			return toolError(err)
		}
		result := toolResult(summarize(nodes, root))
		slog.Debug("tool query_nodes_by_file completed",
			"file", args.File, "node_type", args.NodeType, "results", len(nodes), "truncated", len(nodes) > maxToolResultNodes)
		return result

	default:
		slog.Warn("unknown analysis tool called", "tool", name)
		return toolError(fmt.Errorf("unknown tool %q", name))
	}
}

func toolResult(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return toolError(err)
	}
	return string(b)
}

func toolError(err error) string {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return string(b)
}

// toolResultIsEmpty reports whether result (a toolResultPayload-shaped JSON
// string) represents a genuinely empty search (total=0), as opposed to an
// error (a failed call isn't "we searched and found nothing", it's "we
// couldn't search") or a non-empty/truncated result. Used by the
// investigation gate's chase-nudge to pick the right corrective wording —
// "no callers exist" needs different guidance than "a caller exists but has
// no guard".
func toolResultIsEmpty(result string) bool {
	var payload struct {
		Total int    `json:"total"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(result), &payload); err != nil {
		return false
	}
	if payload.Error != "" {
		return false
	}
	return payload.Total == 0
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
