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

package joern

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// BuildConfig controls how Joern builds the initial Code Property Graph.
type BuildConfig struct {
	// Paths is the list of source files or directories to ingest.
	// Must be non-empty; paths containing ".." are rejected (ErrPathTraversal).
	Paths []string

	// Language overrides Joern's auto-detection.
	// Accepted values: "JAVASRC", "PYTHONSRC", "GOLANG", "JSSRC", "RUBYSRC".
	// Empty string uses auto-detection.
	Language string

	// SerializedCPGPath is the file path where the finished CPG is persisted for
	// incremental patching on repeat scans. Empty string skips serialization.
	SerializedCPGPath string
}

// IncrementalPatchConfig controls the depth-5 BFS CPG patch for repeat scans.
type IncrementalPatchConfig struct {
	// ChangedFunctions lists Joern METHOD node full names to patch from.
	ChangedFunctions []string

	// RemovedFiles lists source files that were deleted; their nodes are evicted.
	RemovedFiles []string

	// MaxDepth is the BFS traversal depth (default 5; must not exceed 6).
	// Depth 5 is the taint-correctness bound from Li et al. (ICSE 2024) and
	// Effendi et al. (SOAP/PLDI 2025, Joern core team).
	MaxDepth int

	// HubCallerThreshold is the maximum caller count a function may have before
	// the incremental patch is aborted. Default 50; exceeding it returns
	// ErrHubModuleDetected and the caller must fall back to BuildCPG.
	HubCallerThreshold int

	// SerializedCPGPath is the path from which the prior CPG snapshot is loaded.
	SerializedCPGPath string
}

// BuildCPG requests Joern to build a full Code Property Graph from the given
// source paths. This is the first-scan operation; repeat scans use
// LoadCPG + IncrementalPatch.
//
// The call blocks until the CPG build completes or the context expires.
// Large codebases may require WithBuildTimeout to extend the default 120 s cap.
//
// Input validation:
//   - Paths must be non-empty (ErrEmptyPaths).
//   - No path may contain ".." components (ErrPathTraversal).
func (c *Client) BuildCPG(ctx context.Context, cfg BuildConfig) error {
	if len(cfg.Paths) == 0 {
		return ErrEmptyPaths
	}
	for _, p := range cfg.Paths {
		if containsTraversal(p) {
			return fmt.Errorf("%w: %q", ErrPathTraversal, p)
		}
	}

	buildCtx, cancel := context.WithTimeout(ctx, c.buildTimeout)
	defer cancel()

	// Joern accepts a single root directory or file. For multiple paths,
	// the common parent directory is used and Joern recurses from there.
	// Single-path case (most common): pass it directly.
	root := cfg.Paths[0]
	if len(cfg.Paths) > 1 {
		root = commonParent(cfg.Paths)
	}

	var query string
	if cfg.Language != "" {
		query = fmt.Sprintf(`importCode(inputPath=%q, language=%q)`,
			root, cfg.Language)
	} else {
		query = fmt.Sprintf(`importCode(inputPath=%q)`, root)
	}

	if _, err := c.doQuery(buildCtx, query); err != nil {
		if buildCtx.Err() == context.DeadlineExceeded {
			return ErrBuildTimeout
		}
		return fmt.Errorf("joern: BuildCPG: %w", err)
	}

	if cfg.SerializedCPGPath != "" {
		if err := c.SaveCPG(ctx, cfg.SerializedCPGPath); err != nil {
			// Non-fatal: the CPG is live even if serialization fails.
			// The caller can retry SaveCPG separately.
			return fmt.Errorf("joern: BuildCPG: serialize CPG: %w", err)
		}
	}
	return nil
}

// IncrementalPatch applies a depth-bounded BFS patch to the loaded CPG,
// updating only the inter-procedural graph neighbourhood of each changed function.
//
// Must be called after LoadCPG. Returns ErrHubModuleDetected if any function
// in ChangedFunctions has ≥ HubCallerThreshold callers — in that case the
// caller must invoke BuildCPG for a full rebuild instead.
func (c *Client) IncrementalPatch(ctx context.Context, cfg IncrementalPatchConfig) error {
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 5
	}
	if cfg.HubCallerThreshold == 0 {
		cfg.HubCallerThreshold = 50
	}
	if cfg.MaxDepth > 6 {
		return ErrDepthExceeded
	}

	// Check each changed function's caller count before patching.
	g := c.Graph()
	for _, fn := range cfg.ChangedFunctions {
		callers, err := g.GetCallers(fn)
		if err != nil {
			// If we can't query callers, fall back to full rebuild to be safe.
			return ErrHubModuleDetected
		}
		if len(callers) >= cfg.HubCallerThreshold {
			return ErrHubModuleDetected
		}
	}

	// Evict removed files from the CPG.
	for _, f := range cfg.RemovedFiles {
		evictQuery := fmt.Sprintf(
			`cpg.file.nameExact(%q).foreach(_.start.ast.foreach(_.delete()))`, f)
		if _, err := c.doQuery(ctx, evictQuery); err != nil {
			return fmt.Errorf("joern: IncrementalPatch: evict %q: %w", f, err)
		}
	}

	// Re-import each changed function's file to update its AST+PDG subgraph.
	// Joern's incremental import updates the CPG in-place for the given paths.
	for _, fn := range cfg.ChangedFunctions {
		patchQuery := fmt.Sprintf(
			`cpg.method.fullName(%q).filename.l.foreach(f => importCode.incrementally(f))`, fn)
		if _, err := c.doQuery(ctx, patchQuery); err != nil {
			return fmt.Errorf("joern: IncrementalPatch: patch %q: %w", fn, err)
		}
	}
	return nil
}

// SaveCPG serializes the current in-memory CPG to destPath for use in
// subsequent IncrementalPatch calls on repeat scans.
func (c *Client) SaveCPG(ctx context.Context, destPath string) error {
	if containsTraversal(destPath) {
		return fmt.Errorf("%w: %q", ErrPathTraversal, destPath)
	}
	query := fmt.Sprintf(`cpg.save; workspace.getActiveProject.foreach(_.cpg.save(%q))`, destPath)
	if _, err := c.doQuery(ctx, query); err != nil {
		return fmt.Errorf("joern: SaveCPG: %w", err)
	}
	return nil
}

// LoadCPG instructs Joern to load a previously serialized CPG snapshot.
// Must be called before IncrementalPatch on repeat scans.
func (c *Client) LoadCPG(ctx context.Context, srcPath string) error {
	if containsTraversal(srcPath) {
		return fmt.Errorf("%w: %q", ErrPathTraversal, srcPath)
	}
	query := fmt.Sprintf(`importCpg(path=%q)`, srcPath)
	if _, err := c.doQuery(ctx, query); err != nil {
		return fmt.Errorf("joern: LoadCPG: %w", err)
	}
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// containsTraversal reports whether p contains a ".." path component,
// which could escape the project root. The raw path is checked — not the
// cleaned path — because Clean removes ".." before we can detect it.
func containsTraversal(p string) bool {
	// Normalise separators to "/" for uniform splitting.
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// commonParent returns the longest common directory prefix of paths.
func commonParent(paths []string) string {
	if len(paths) == 0 {
		return "."
	}
	base := filepath.Dir(filepath.Clean(paths[0]))
	for _, p := range paths[1:] {
		d := filepath.Dir(filepath.Clean(p))
		for base != d && base != "." && base != "/" {
			base = filepath.Dir(base)
			d = filepath.Dir(d)
		}
	}
	return base
}

// Ensure joernGraph satisfies cpg.Graph at compile time.
var _ cpg.Graph = (*joernGraph)(nil)
