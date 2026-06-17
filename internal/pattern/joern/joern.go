// Package joern wraps the Joern CPG engine HTTP API (Apache 2.0).
//
// Joern is pre-started at CLI launch (before file ingestion) to eliminate JVM
// cold-start latency. It builds the Universal Code Property Graph (AST + CFG + PDG
// + call graph) for all in-scope source files and serves inter-procedural taint
// queries via an HTTP JSON API.
//
// The CPG is shared between both detection paths via the pkg/cpg.Graph interface:
//   - Path A's Joern taint analysis queries TaintPaths directly.
//   - Path B's Heuristic Targeting and Call Chain Assembler query nodes and edges.
//
// Incremental CPG patching (repeat scans):
// On repeat scans, the CPG is loaded from a serialized snapshot and patched with
// a depth-5 BFS update rooted at each changed function (IncrementalPatch).
// Depth 5 is the taint-correctness bound from Li et al. (ICSE 2024) and
// Effendi et al. (SOAP/PLDI 2025, Joern core team). If any changed function has
// ≥50 callers (hub module), a full CPG rebuild is triggered instead.
package joern

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

const defaultServerURL = "http://localhost:8080"

// Client wraps the Joern HTTP server API.
type Client struct {
	// serverURL is the base URL of the pre-started Joern server (e.g. "http://localhost:8080").
	serverURL string
}

// BuildConfig controls how Joern builds the initial CPG.
type BuildConfig struct {
	// Paths is the list of source file or directory paths to ingest.
	Paths []string
	// Language overrides Joern's auto-detection (e.g. "python", "javasrc", "golang").
	// Empty string uses auto-detection.
	Language string
	// SerializedCPGPath is the file path where the built CPG will be serialized
	// for use in subsequent incremental patches. Empty string disables serialization.
	SerializedCPGPath string
}

// IncrementalPatchConfig controls the depth-5 BFS CPG patch for repeat scans.
type IncrementalPatchConfig struct {
	// ChangedFunctions lists the function identifiers (Joern METHOD node names) to patch from.
	ChangedFunctions []string
	// RemovedFiles lists source files that have been deleted; their nodes must be evicted.
	RemovedFiles []string
	// MaxDepth is the BFS traversal depth (default 5; must not exceed 6 per SOAP 2025).
	MaxDepth int
	// HubCallerThreshold is the max callers a function may have before triggering full rebuild.
	// Default 50; exceeding this causes IncrementalPatch to return ErrHubModuleDetected.
	HubCallerThreshold int
	// SerializedCPGPath is the file path from which the existing CPG snapshot is loaded.
	SerializedCPGPath string
}

// ErrHubModuleDetected is returned by IncrementalPatch when a changed function
// exceeds HubCallerThreshold. The caller must fall back to a full CPG rebuild.
var ErrHubModuleDetected = &hubModuleError{}

type hubModuleError struct{}

func (e *hubModuleError) Error() string {
	return "joern: hub module detected — incremental patch aborted, full rebuild required"
}

// New returns a Client targeting the Joern server at serverURL.
// If serverURL is empty, localhost:8080 is used.
//
// Parameters:
//   - serverURL: base URL of the Joern HTTP server (e.g. "http://localhost:8080").
func New(serverURL string) *Client {
	if serverURL == "" {
		serverURL = defaultServerURL
	}
	return &Client{serverURL: serverURL}
}

// BuildCPG requests Joern to build a Code Property Graph from the given source paths.
// This is the full (non-incremental) build used on first scan or after hub detection.
//
// Parameters:
//   - ctx: cancellation context; CPG builds can take minutes for large codebases.
//   - cfg: build configuration including source paths and optional CPG serialization path.
//
// Returns non-nil error if Joern rejects the request or the HTTP call fails.
func (c *Client) BuildCPG(ctx context.Context, cfg BuildConfig) error {
	// implemented in G2.M2.3
	return nil
}

// IncrementalPatch applies a depth-5 BFS patch to the loaded CPG, updating only the
// inter-procedural graph neighbourhood of each changed function.
//
// Returns ErrHubModuleDetected if any changed function exceeds cfg.HubCallerThreshold.
// In that case the caller must invoke BuildCPG for a full rebuild.
//
// Parameters:
//   - ctx: cancellation context.
//   - cfg: patch configuration including changed functions, removed files, and depth cap.
func (c *Client) IncrementalPatch(ctx context.Context, cfg IncrementalPatchConfig) error {
	// implemented in G2.M2.3
	return nil
}

// SaveCPG serializes the current CPG state to the file at destPath.
// Called after BuildCPG or IncrementalPatch completes to persist the snapshot
// for the next scan's IncrementalPatch.
//
// Parameters:
//   - ctx: cancellation context.
//   - destPath: absolute path where the serialized CPG will be written.
func (c *Client) SaveCPG(ctx context.Context, destPath string) error {
	// implemented in G2.M2.3
	return nil
}

// LoadCPG instructs Joern to load a previously serialized CPG snapshot from srcPath.
// Must be called before IncrementalPatch on repeat scans.
//
// Parameters:
//   - ctx: cancellation context.
//   - srcPath: absolute path to the serialized CPG file.
func (c *Client) LoadCPG(ctx context.Context, srcPath string) error {
	// implemented in G2.M2.3
	return nil
}

// Ping checks that the Joern HTTP server is reachable and responsive.
// Returns nil if the server responds with HTTP 200 to a health-check request.
//
// Parameters:
//   - ctx: cancellation context.
func (c *Client) Ping(ctx context.Context) error {
	// implemented in G2.M2.3
	return nil
}

// Graph returns a cpg.Graph backed by this Joern server instance.
// The returned graph is safe to share across both detection paths concurrently.
// Graph() must be called after BuildCPG (or LoadCPG + IncrementalPatch) completes.
func (c *Client) Graph() cpg.Graph {
	return &joernGraph{client: c}
}

// joernGraph implements cpg.Graph via Joern HTTP JSON queries (Gremlin over HTTP).
type joernGraph struct {
	client *Client
}

// QueryNodes returns all nodes of nodeType across all ingested source files.
func (g *joernGraph) QueryNodes(nodeType cpg.NodeType) ([]cpg.Node, error) {
	// implemented in G2.M2.3
	return nil, nil
}

// QueryNodesByFile returns all nodes of nodeType in the given source file.
func (g *joernGraph) QueryNodesByFile(relPath string, nodeType cpg.NodeType) ([]cpg.Node, error) {
	// implemented in G2.M2.3
	return nil, nil
}

// QueryEdges returns directed edges where fromID and toID match; "" matches any.
func (g *joernGraph) QueryEdges(fromID, toID string) ([]cpg.Edge, error) {
	// implemented in G2.M2.3
	return nil, nil
}

// GetCallGraph returns the full inter-procedural call graph.
func (g *joernGraph) GetCallGraph() (cpg.CallGraph, error) {
	// implemented in G2.M2.3
	return nil, nil
}

// GetCallers returns all functions that directly call functionID.
func (g *joernGraph) GetCallers(functionID string) ([]cpg.Node, error) {
	// implemented in G2.M2.3
	return nil, nil
}

// GetCallees returns all functions directly called by functionID.
func (g *joernGraph) GetCallees(functionID string) ([]cpg.Node, error) {
	// implemented in G2.M2.3
	return nil, nil
}

// GetNeighboursAtDepth performs a bidirectional BFS from rootID up to depth hops.
func (g *joernGraph) GetNeighboursAtDepth(rootID string, depth int) ([]cpg.Node, error) {
	// implemented in G2.M2.3
	return nil, nil
}

// TaintPaths runs inter-procedural taint analysis and returns source-to-sink paths.
func (g *joernGraph) TaintPaths(sources []cpg.TaintSource, sinks []cpg.TaintSink) ([]cpg.TaintPath, error) {
	// implemented in G2.M2.3
	return nil, nil
}

// PreFlaggedSinks returns all dangerous sink nodes flagged by Tree-sitter pre-scan.
func (g *joernGraph) PreFlaggedSinks() ([]cpg.TaintSink, error) {
	// implemented in G2.M2.3
	return nil, nil
}
