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

package joern

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/config"
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

	// ProjectRoot overrides the root directory passed to importCode. When set,
	// commonParent(Paths) is ignored — Joern ingests from this directory.
	// Use when Paths are individual changed files spread across a larger repo.
	ProjectRoot string

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
	slog.Info("joern: BuildCPG starting", slog.Int("paths", len(cfg.Paths)), slog.String("language", cfg.Language))
	for _, p := range cfg.Paths {
		if containsTraversal(p) {
			slog.Error("joern: path traversal rejected", slog.String("path", p))
			return fmt.Errorf("%w: %q", ErrPathTraversal, p)
		}
	}

	buildCtx, cancel := context.WithTimeout(ctx, c.buildTimeout)
	defer cancel()
	buildStart := time.Now()

	// Abs-path all inputs so commonParent never collapses relative paths to ".".
	absPaths := make([]string, len(cfg.Paths))
	for i, p := range cfg.Paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("joern: BuildCPG: resolve path %q: %w", p, err)
		}
		absPaths[i] = abs
	}

	// Caller-supplied ProjectRoot takes priority; otherwise derive from paths.
	var root string
	if cfg.ProjectRoot != "" {
		var err error
		root, err = filepath.Abs(cfg.ProjectRoot)
		if err != nil {
			return fmt.Errorf("joern: BuildCPG: resolve project root %q: %w", cfg.ProjectRoot, err)
		}
	} else {
		root = absPaths[0]
		if len(absPaths) > 1 {
			root = commonParent(absPaths)
		}
		// For JVM languages walk up to the Maven/Gradle project root.
		if cfg.Language == "JAVASRC" || cfg.Language == "KOTLIN" {
			if projectRoot := findJVMProjectRoot(root); projectRoot != "" {
				root = projectRoot
			}
		}
	}

	// Try importCode with up to 2 language attempts:
	//   1. cfg.Language (empty = auto-detection)
	//   2. detectProjectLanguage fallback if auto-detection fails/cpg unusable
	// After each successful import, verify the CPG is actually queryable.
	var languages []string
	if cfg.Language != "" {
		languages = append(languages, cfg.Language)
	} else {
		languages = append(languages, "") // sentinel: auto-detection
		if lang := DetectProjectLanguage(absPaths); lang != "" {
			languages = append(languages, lang)
		}
	}
	slog.Info("joern: BuildCPG resolved root", "root", root, "languages", languages)
	var cpgReady bool
	for _, lang := range languages {
		q := fmt.Sprintf(`importCode(inputPath=%q)`, root)
		if lang != "" {
			q = fmt.Sprintf(`importCode(inputPath=%q, language=%q)`, root, lang)
			if cfg.Language == "" {
				slog.Warn("joern: BuildCPG retrying with explicit language", "language", lang)
			}
		}

		slog.Debug("joern: BuildCPG importCode", "query", q)
		if _, err := c.doQuery(buildCtx, q); err != nil {
			slog.Warn("joern: BuildCPG importCode failed", "language", lang, "err", err)
			continue
		}
		// Verify the CPG is actually loaded and queryable. importCode can
		// return success=true while the active project has no CPG (e.g.
		// partial frontend failure in multi-language repos).
		slog.Debug("joern: BuildCPG verifying CPG", "query", "cpg.method.size")
		if _, verr := c.doQuery(buildCtx, "cpg.method.size"); verr != nil {
			slog.Warn("joern: BuildCPG verification failed", "language", lang, "err", verr)
			continue
		}
		cpgReady = true
		break
	}
	if !cpgReady {
		if buildCtx.Err() == context.DeadlineExceeded {
			slog.Error("joern: CPG build timed out")
			return ErrBuildTimeout
		}
		slog.Error("joern: BuildCPG failed")
		return fmt.Errorf("joern: BuildCPG: no language succeeded")
	}
	slog.Info(
		"joern: CPG build complete",
		slog.Int("paths", len(cfg.Paths)),
		slog.Duration("elapsed", time.Since(buildStart)),
	)

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
	slog.Debug(
		"joern: IncrementalPatch starting",
		slog.Int("changed_functions", len(cfg.ChangedFunctions)),
		slog.Int("removed_files", len(cfg.RemovedFiles)),
		slog.Int("max_depth", cfg.MaxDepth),
	)
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = config.C.CPGDefaultMaxDepth
	}
	if cfg.HubCallerThreshold == 0 {
		cfg.HubCallerThreshold = config.C.CPGHubCallerThreshold
	}
	if cfg.MaxDepth > config.C.CPGHardMaxDepth {
		return ErrDepthExceeded
	}

	// Check each changed function's caller count before patching.
	g := c.GraphWithContext(ctx)
	for _, fn := range cfg.ChangedFunctions {
		callers, err := g.GetCallers(fn)
		if err != nil {
			slog.Warn("joern: failed to query callers, falling back to full rebuild", slog.String("function", fn), "err", err)
			// If we can't query callers, fall back to full rebuild to be safe.
			return ErrHubModuleDetected
		}
		if len(callers) >= cfg.HubCallerThreshold {
			slog.Warn("joern: hub module detected, full rebuild required", slog.String("function", fn), slog.Int("callers", len(callers)))
			return ErrHubModuleDetected
		}
	}

	// Evict removed files from the CPG.
	for _, f := range cfg.RemovedFiles {
		evictQuery := fmt.Sprintf(
			`cpg.file.nameExact(%q).foreach(_.start.ast.foreach(_.delete()))`, f,
		)
		slog.Debug("joern: IncrementalPatch evicting file", "query", evictQuery)
		if _, err := c.doQuery(ctx, evictQuery); err != nil {
			return fmt.Errorf("joern: IncrementalPatch: evict %q: %w", f, err)
		}
	}

	// Re-import each changed function's file to update its AST+PDG subgraph.
	// Joern's incremental import updates the CPG in-place for the given paths.
	for _, fn := range cfg.ChangedFunctions {
		patchQuery := fmt.Sprintf(
			`cpg.method.fullName(%q).filename.l.foreach(f => importCode.incrementally(f))`, fn,
		)
		slog.Debug("joern: IncrementalPatch patching function", "query", patchQuery)
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
	// TODO: Verify that this change is correct (Wed, Jul 1, 2026)
	// Joern's 'save' is a top-level shell command, not a method on the cpg object.
	// We run 'save' to flush the in-memory graph to the workspace, then use Java
	// utilities to copy the resulting 'cpg.bin' file to our custom destPath.

	// query := fmt.Sprintf(`cpg.save; workspace.getActiveProject.foreach(_.cpg.save(%q))`, destPath)
	query := fmt.Sprintf(
		`save; workspace
			.getActiveProject
			.foreach(p => java.nio.file.Files.copy(
				java.nio.file.Paths.get(p.path.toString)
					.resolve("cpg.bin"),
				java.nio.file.Paths.get(%q),
				java.nio.file.StandardCopyOption.REPLACE_EXISTING
			))`, destPath,
	)
	slog.Debug("joern: SaveCPG query", "query", query, "dest", destPath)
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
	query := fmt.Sprintf(`importCpg(%q)`, srcPath)
	slog.Debug("joern: LoadCPG query", "query", query, "src", srcPath)
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
// It operates on path components (not characters) so /a/b and /a/c → /a.
func commonParent(paths []string) string {
	if len(paths) == 0 {
		return "."
	}
	// Split each path's directory into components.
	split := func(p string) []string {
		return strings.Split(filepath.Dir(filepath.Clean(p)), string(filepath.Separator))
	}
	common := split(paths[0])
	for _, p := range paths[1:] {
		parts := split(p)
		end := len(common)
		if len(parts) < end {
			end = len(parts)
		}
		i := 0
		for i < end && common[i] == parts[i] {
			i++
		}
		common = common[:i]
	}
	if len(common) == 0 {
		return "/"
	}
	// filepath.Join drops leading empty component from absolute-path splits.
	joined := filepath.Join(common...)
	if filepath.IsAbs(paths[0]) && !filepath.IsAbs(joined) {
		joined = string(filepath.Separator) + joined
	}
	return joined
}

// findJVMProjectRoot walks up from dir until it finds a Maven or Gradle build
// file, returning that directory as the Joern importCode root. Returns "" if
// none is found before reaching the filesystem root.
func findJVMProjectRoot(dir string) string {
	markers := []string{"pom.xml", "build.gradle", "build.gradle.kts"}
	cur := dir
	for {
		for _, m := range markers {
			if _, err := os.Stat(filepath.Join(cur, m)); err == nil {
				return cur
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "" // reached fs root without finding a marker
		}
		cur = parent
	}
}

// DetectProjectLanguage infers the most likely Joern language code from source
// file extensions in paths. Returns "" when no known extension is found.
func DetectProjectLanguage(paths []string) string {
	extCount := make(map[string]int)
	for _, p := range paths {
		ext := strings.TrimPrefix(filepath.Ext(p), ".")
		if ext != "" {
			extCount[ext]++
		}
	}
	// If the project root directory itself is in paths, recurse into it.
	if len(extCount) == 0 && len(paths) > 0 {
		dirents, err := os.ReadDir(paths[0])
		if err == nil {
			for _, de := range dirents {
				if !de.IsDir() {
					ext := strings.TrimPrefix(filepath.Ext(de.Name()), ".")
					if ext != "" {
						extCount[ext]++
					}
				}
			}
		}
	}

	type langScore struct {
		code  string
		score int
	}
	var candidates []langScore
	for ext, count := range extCount {
		code := extToJoernLang(ext)
		if code != "" {
			candidates = append(candidates, langScore{code, count})
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})
	return candidates[0].code
}

// extToJoernLang maps a file extension to Joern's language code.
func extToJoernLang(ext string) string {
	switch strings.ToLower(ext) {
	case "java", "class", "jar", "gradle", "mvn", "pom":
		return "JAVASRC"
	case "py", "pyw":
		return "PYTHONSRC"
	case "go":
		return "GOLANG"
	case "js", "jsx", "ts", "tsx", "mjs", "cjs":
		return "JSSRC"
	case "rb", "ruby":
		return "RUBYSRC"
	default:
		return ""
	}
}

// Ensure joernGraph satisfies cpg.Graph at compile time.
var _ cpg.Graph = (*joernGraph)(nil)
