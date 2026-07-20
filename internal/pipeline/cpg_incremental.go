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

package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion/diffindex"
	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/scanner/joern"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
	"github.com/hoangharry-tm/zerotrust/pkg/sqlite"
)

func (p *Pipeline) loadCachedCPG(ctx context.Context, ingResult *ingestion.Result) {
	cpgPath := cpgSnapshotPath(p.cfg.ProjectID)
	if _, statErr := os.Stat(cpgPath); statErr == nil {
		if loadErr := p.joern.LoadCPG(ctx, cpgPath); loadErr != nil {
			p.logger.Warn("joern: failed to load cached CPG on no-change scan", "err", loadErr)
		} else {
			p.logger.Info("joern: loaded cached CPG for no-change scan", "path", cpgPath)
		}
	} else if p.db != nil && ingResult.ProjectID != "" {
		states, listErr := p.db.ListScanState(ctx, ingResult.ProjectID)
		if listErr == nil && len(states) > 0 {
			allFiles := make([]string, len(states))
			for i, s := range states {
				allFiles[i] = s.FilePath
			}
			p.logger.Info("joern: cached CPG not found — building fresh CPG from all project files",
				"files", len(allFiles))
			if buildErr := p.buildOrLoadCPG(ctx, ingResult.ProjectID, cpgPath, allFiles); buildErr != nil {
				p.logger.Warn("joern: fresh CPG build failed on no-change scan", "err", buildErr)
			}
		}
	}
}

// buildScopeFromChanges builds the CPG for changed files and expands scope via modules.
func (p *Pipeline) buildScopeFromChanges(ctx context.Context, ingResult *ingestion.Result) []string {
	changed := ingResult.ChangeSet.Changed
	modules := joern.DetectWorkingModules(changed)

	if p.cfg.JoernBin == "" {
		return joern.FilterScopeByLanguage(changed)
	}

	graph := p.joern.GraphWithContext(ctx)

	// Pre-flag dangerous sinks in changed files.
	if preFlagErr := p.joern.PreFlagSinks(ctx, changed); preFlagErr != nil {
		p.logger.Warn("sink pre-flagging failed, continuing without pre-flagged sinks",
			"component", "scan", "err", preFlagErr)
	} else {
		p.logger.Info("sink pre-flagging complete",
			"component", "scan", "sinks", len(p.joern.PreFlaggedSinks()))
	}

	cpgPath := cpgSnapshotPath(p.cfg.ProjectID)
	buildErr := p.buildOrLoadCPG(ctx, ingResult.ProjectID, cpgPath, changed)
	if buildErr != nil {
		output.Emit(p.events, output.Event{
			Kind: output.EventLog,
			Log:  fmt.Sprintf("warn: cpg build: %v — taint analysis disabled", buildErr),
		})
		p.alerts = append(p.alerts, fmt.Sprintf("CPG build failed (%v): taint analysis disabled, pattern-only path active", buildErr))
		return joern.FilterScopeByLanguage(changed)
	}

	depth := moduleDepthForMode(p.cfg.ScanMode)
	if depth > 0 {
		expanded, expandErr := diffindex.ExpandWithCPG(ctx, ingResult.ChangeSet, graph)
		if expandErr != nil {
			p.logger.Error("cpg scope expansion failed, using pre-expansion modules",
				"component", "scan", "err", expandErr)
		} else {
			modules = joern.DetectWorkingModules(expanded.Changed)
		}
		joern.ExpandModuleScope(modules, graph, depth)
	}
	return joern.FilterScopeByLanguage(joern.FlattenScope(modules))
}

// runDedup applies Gate 1-4 dedup and SSVC scoring, emitting stage events.
func countLOC(files []string) (int, error) {
	var total int
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		total += bytes.Count(content, []byte{'\n'})
	}
	return total, nil
}

// buildOrLoadCPG builds a fresh CPG or loads an existing snapshot and applies
// incremental patches. Returns nil on success or an error if the CPG cannot be
// prepared (non-fatal — callers proceed without taint analysis).
//
// The projectID parameter is used to query/update the cpg_cache table for
// fast bypass when no structural changes have occurred since the last scan.
func (p *Pipeline) buildOrLoadCPG(ctx context.Context, projectID, cpgPath string, changedFiles []string) error {
	if p.joern == nil {
		return fmt.Errorf("joern client not initialized")
	}

	// Ensure the CPG snapshot directory exists.
	if dir := filepath.Dir(cpgPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			p.logger.Warn("failed to create CPG snapshot directory",
				"component", "cpg", "dir", dir, "err", err)
		}
	}

	// ── CPG cache gate: query cpg_cache before building ─────────────────────
	// If a previous snapshot exists and changed_functions == 0, the CPG is
	// already up to date — skip the full build/load/patch cycle.
	if projectID != "" && p.db != nil {
		cached, err := p.db.GetCPGCache(ctx, projectID)
		if err == nil && cached.ChangedFunctions == 0 {
			if _, statErr := os.Stat(cached.CPGPath); statErr == nil {
				p.logger.Info(
					"cpg_cache: verified — no structural changes, reusing cached CPG",
					"component", "cpg",
					"path", cached.CPGPath,
					"built_at", cached.BuiltAt,
				)
				if err := p.joern.LoadCPG(ctx, cached.CPGPath); err != nil {
					p.logger.Warn("cpg_cache: cached file not loadable, rebuilding",
						"component", "cpg", "err", err)
				} else {
					return nil
				}
			} else {
				p.logger.Warn("cpg_cache: cached CPG file missing, rebuilding",
					"component", "cpg", "path", cached.CPGPath)
			}
		} else if err != nil {
			p.logger.Debug("cpg_cache: no prior cache entry", "component", "cpg")
		} else {
			p.logger.Debug("cpg_cache: structural changes detected, rebuilding",
				"component", "cpg",
				"changed_functions", cached.ChangedFunctions)
		}
	}

	// Query the current Joern version for snapshot invalidation.
	currentVersion, verErr := p.joern.Version(ctx)
	if verErr != nil {
		p.logger.Warn(
			"could not determine Joern version, proceeding without version check",
			"component", "cpg",
			"err", verErr,
		)
		currentVersion = "unknown"
	}

	// Check if a prior CPG snapshot exists.
	versionPath := joern.VersionSnapshotPath(p.cfg.ProjectID)
	snapshotExists := false
	if _, err := os.Stat(cpgPath); err == nil {
		// Version mismatch check: if the stored version differs from the current
		// Joern version, invalidate the snapshot and force a full rebuild.
		if storedVersion, readErr := os.ReadFile(versionPath); readErr == nil {
			stored := strings.TrimSpace(string(storedVersion))
			if stored != "" && stored != currentVersion {
				output.Emit(p.events, output.Event{
					Kind:  output.EventLog,
					Stage: "cpg",
					Log:   fmt.Sprintf("Joern version changed from %s to %s — invalidating CPG snapshot", stored, currentVersion),
				})
				_ = os.Remove(cpgPath)
				_ = os.Remove(versionPath)
				snapshotExists = false
			} else {
				snapshotExists = true
			}
		} else {
			// No version file — treat as fresh snapshot.
			snapshotExists = true
		}
	}

	if snapshotExists {
		output.Emit(p.events, output.Event{
			Kind:  output.EventLog,
			Stage: "cpg",
			Log:   "loading prior CPG snapshot for incremental update",
		})

		// Load the prior CPG.
		if err := p.joern.LoadCPG(ctx, cpgPath); err != nil {
			return fmt.Errorf("load cpg: %w", err)
		}

		// Build the incremental config from changed files.
		// Map changed files to function names via CPG queries.
		graph := p.joern.GraphWithContext(ctx)
		var changedFunctions []string
		for _, f := range changedFiles {
			nodes, err := graph.QueryNodesByFile(f, cpg.NodeMethod)
			if err != nil || len(nodes) == 0 {
				// If the file is new, we need a full rebuild.
				output.Emit(p.events, output.Event{
					Kind:  output.EventLog,
					Stage: "cpg",
					Log:   fmt.Sprintf("no prior CPG nodes for %s — falling back to full build", f),
				})
				return p.buildFullCPG(ctx, projectID, cpgPath, changedFiles)
			}
			for _, n := range nodes {
				changedFunctions = append(changedFunctions, n.ID)
			}
		}

		if len(changedFunctions) == 0 {
			// No functions changed — CPG is already up to date.
			return nil
		}

		// Apply incremental patch.
		err := p.joern.IncrementalPatch(ctx, joern.IncrementalPatchConfig{
			ChangedFunctions:   changedFunctions,
			RemovedFiles:       nil, // removed not tracked here
			MaxDepth:           config.New().CPGDefaultMaxDepth,
			HubCallerThreshold: config.New().CPGHubCallerThreshold,
			SerializedCPGPath:  cpgPath,
		})
		if err != nil {
			// Hub module detected or patch failed — fall back to full rebuild.
			output.Emit(p.events, output.Event{
				Kind:  output.EventLog,
				Stage: "cpg",
				Log:   fmt.Sprintf("incremental patch aborted (%v) — full rebuild", err),
			})
			return p.buildFullCPG(ctx, projectID, cpgPath, changedFiles)
		}

		// Update cpg_cache after successful incremental patch: mark
		// changed_functions = 0 so the verification gate on the next scan
		// can bypass the build entirely if no further changes occur.
		if p.db != nil && projectID != "" {
			if cacheErr := p.db.UpsertCPGCache(ctx, sqlite.CPGCacheRow{
				ProjectID:        projectID,
				CPGPath:          cpgPath,
				ScopeMode:        p.cfg.ScanMode,
				ChangedFunctions: 0,
			}); cacheErr != nil {
				p.logger.Warn("failed to update CPG cache after incremental patch",
					"component", "cpg", "err", cacheErr)
			}
		}

		return nil
	}

	// No prior snapshot — full build.
	return p.buildFullCPG(ctx, projectID, cpgPath, changedFiles)
}

// buildFullCPG builds a complete CPG from the given files and saves the snapshot.
// Returns nil on success or an error the caller should handle as non-fatal.
// The projectID parameter is used to update the cpg_cache table.
func (p *Pipeline) buildFullCPG(ctx context.Context, projectID, cpgPath string, scopeFiles []string) error {
	if len(scopeFiles) == 0 {
		return fmt.Errorf("no files in scope for CPG build")
	}

	// Enforce the ≤5K LOC gate to keep build times under the 60 s target.
	loc, err := countLOC(scopeFiles)
	if err != nil {
		return fmt.Errorf("count loc: %w", err)
	}
	if loc > config.New().CPGMaxScopeLOC {
		return fmt.Errorf("scope exceeds %d LOC (%d) — CPG build skipped; taint analysis disabled",
			config.New().CPGMaxScopeLOC, loc)
	}

	p.logger.Info(
		"building CPG",
		"component", "cpg",
		"files", len(scopeFiles),
		"loc", loc,
		"target_build_time_seconds", 60,
	)

	buildStart := time.Now()
	// Pre-detect language from file extensions so Joern skips irrelevant
	// frontends (e.g. pysrc2cpg on Java repos breaks on Java 21+).
	detectedLang := joern.DetectProjectLanguage(scopeFiles)
	err = p.joern.BuildCPG(ctx, joern.BuildConfig{
		Paths:             scopeFiles,
		ProjectRoot:       p.cfg.Target,
		Language:          detectedLang,
		SerializedCPGPath: cpgPath,
	})
	buildElapsed := time.Since(buildStart)
	if err != nil {
		p.logger.Error(
			"CPG build failed",
			"component", "cpg",
			"elapsed", buildElapsed,
			"err", err,
		)
		return fmt.Errorf("build cpg: %w", err)
	}

	p.logger.Info(
		"CPG build complete",
		"component", "cpg",
		"elapsed", buildElapsed,
		"files", len(scopeFiles),
		"loc", loc,
	)

	// Ensure project row exists before any FK-dependent writes (cpg_cache, etc.).
	if p.db != nil && projectID != "" {
		if _, err := p.db.UpsertProject(ctx, sqlite.ProjectRow{
			ProjectID:     projectID,
			RootPath:      p.cfg.Target,
			LastScannedAt: time.Now().Unix(),
		}); err != nil {
			p.logger.Warn("buildFullCPG: failed to upsert project", "err", err)
		}
	}

	// Drain CPG from Joern JVM into SQLite so all subsequent graph queries
	// read from the local DB instead of hitting Joern HTTP.
	if p.db != nil && projectID != "" {
		cpgVersion := fmt.Sprintf("%d", time.Now().Unix())
		joernGraph := p.joern.GraphWithContext(ctx)
		if ingestErr := joernGraph.IngestCPGToSQLite(ctx, p.db, projectID, cpgVersion); ingestErr != nil {
			p.logger.Warn("failed to ingest CPG to SQLite, falling back to Joern HTTP",
				"component", "cpg", "err", ingestErr)
		} else {
			// Enable SQLite read path for all subsequent graph consumers.
			p.joern.SetSQLiteBackend(p.db, projectID, cpgVersion)
		}
	}

	// Persist CPG cache entry so the cpg_cache verification gate can skip
	// future builds when no structural changes are detected.
	if p.db != nil && projectID != "" {
		if cacheErr := p.db.UpsertCPGCache(ctx, sqlite.CPGCacheRow{
			ProjectID:        projectID,
			CPGPath:          cpgPath,
			ScopeMode:        p.cfg.ScanMode,
			ChangedFunctions: 0,
		}); cacheErr != nil {
			p.logger.Warn("failed to persist CPG cache entry",
				"component", "cpg", "err", cacheErr)
		}
	}

	// Persist the Joern version alongside the snapshot for invalidation on
	// repeat scans. Non-fatal: a write failure just means the next scan may
	// rebuild unnecessarily.
	versionPath := joern.VersionSnapshotPath(p.cfg.ProjectID)
	if version, verErr := p.joern.Version(ctx); verErr == nil {
		if writeErr := os.WriteFile(versionPath, []byte(version+"\n"), 0o644); writeErr != nil {
			p.logger.Warn(
				"failed to persist Joern version snapshot",
				"component", "cpg",
				"err", writeErr,
			)
		}
	}
	return nil
}

// cpgSnapshotPath returns the path to the serialized CPG snapshot for the given
// project ID. The snapshot lives at ~/.zerotrust/{projectID}.cpg.
func cpgSnapshotPath(projectID string) string {
	if projectID == "" {
		projectID = "default"
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return filepath.Join(".zerotrust", projectID+".cpg")
	}
	return filepath.Join(home, ".zerotrust", projectID+".cpg")
}

// topoSortSurfaces reorders surfaces so callees come before callers.
// This ensures the SCS store has prior inferences ready when a caller surface is scanned
// (prior_context > 0). Without this, high-priority callers are scanned first, their callees
// have not yet been processed, so prior_context is always 0.
// Surfaces not present in neighbours keep their original relative order.
func moduleDepthForMode(mode string) int {
    var confDefault = config.New()
	switch mode {
	case "Thorough":
		return confDefault.ModuleDepthThorough
	case "Full":
		return 0 // 0 means no expansion needed — entire codebase is in scope
	default: // Default
		return confDefault.ModuleDepthDefault
	}
}

// ── Joern taint analysis ──────────────────────────────────────────────────────

// runJoernTaint performs inter-procedural taint analysis on scopeFiles using
// the Joern CPG graph. Returns normalised Finding structs.
func runJoernTaint(_ context.Context, graph cpg.Graph, scopeFiles []string) ([]finding.Finding, error) {
	slog.Debug("joern taint analysis started", "component", "joern", "scope_files", len(scopeFiles))
	// Detect the primary language from scope files.
	lang, ok := joern.DetectLanguageFromFiles(scopeFiles)
	if !ok {
		slog.Debug("joern taint: no recognisable language detected, skipping", "component", "joern")
		return nil, nil
	}
	// Ensure the language has a taint config.
	if _, hasConfig := joern.TaintConfigs[lang]; !hasConfig {
		slog.Debug("joern taint: no taint config for language, skipping", "component", "joern", "lang", lang)
		return nil, nil
	}

	// Build source and sink lists from CPG nodes matching our taxonomy.
	var sources []cpg.TaintSource
	var sinks []cpg.TaintSink

	for _, f := range scopeFiles {
		calls, err := graph.QueryNodesByFile(f, cpg.NodeCall)
		if err != nil {
			continue
		}
		for _, c := range calls {
			// Match against source definitions — use the taxonomy Kind.
			if sd, ok := joern.SourceDefForCall(lang, c.Name); ok {
				sources = append(sources, cpg.TaintSource{
					NodeID: c.ID,
					Kind:   sd.Kind,
					File:   c.File,
					Line:   c.Line,
				})
			}
			// Match against sink definitions — use the taxonomy Kind.
			if sd, ok := joern.SinkDefForCall(lang, c.Name); ok {
				sinks = append(sinks, cpg.TaintSink{
					NodeID: c.ID,
					Kind:   sd.Kind,
					File:   c.File,
					Line:   c.Line,
				})
			}
		}
	}

	if len(sources) == 0 || len(sinks) == 0 {
		slog.Debug(
			"joern taint: no sources or sinks found, skipping",
			"component", "joern",
			"sources", len(sources),
			"sinks", len(sinks),
		)
		return nil, nil
	}

	slog.Info(
		"running joern taint analysis",
		"component", "joern",
		"lang", lang,
		"sources", len(sources),
		"sinks", len(sinks),
	)
	// Run the taint analysis.
	paths, err := graph.TaintPaths(sources, sinks)
	if err != nil {
		slog.Error("joern taint paths failed", "component", "joern", "err", err)
		return nil, fmt.Errorf("taint paths: %w", err)
	}

	// Normalise to Finding structs.
	return joern.TaintPathsToFindings(paths, lang), nil
}

// newRunID generates a random 16-character hex string to uniquely identify a scan run.
// crypto/rand.Read never returns an error on supported platforms.
