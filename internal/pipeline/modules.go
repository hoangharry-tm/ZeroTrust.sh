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
	"log/slog"
	"path/filepath"
	"sort"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/pkg/util"
)

// workingModule represents a detected working module — a directory containing
// changed source files, plus its expanded neighbour scope.
type workingModule struct {
	// dir is the relative directory path of the module (e.g. "src/handlers").
	dir string
	// changedFiles are the files in this module that triggered the scan.
	changedFiles []string
	// scopeFiles are the files within this module's scan scope (module files
	// plus depth-expanded neighbours).
	scopeFiles []string
}

// detectWorkingModules partitions the changed file set into working modules
// based on directory ancestry. A working module is the deepest directory that
// contains two or more changed files, or the parent directory of a single
// changed file.
//
// For example:
//
//	Changed: src/handlers/user.go, src/handlers/order.go, src/services/payment.go
//	Modules: [{dir: "src/handlers", Files: 2}, {dir: "src/services", Files: 1}]
func detectWorkingModules(changedFiles []string) []workingModule {
	if len(changedFiles) == 0 {
		slog.Debug("no changed files, no working modules detected")
		return nil
	}

	slog.Debug("detecting working modules", "changed_files", len(changedFiles))

	dirGroups := make(map[string][]string)
	for _, f := range changedFiles {
		d := filepath.Dir(f)
		dirGroups[d] = append(dirGroups[d], f)
	}

	modules := make([]workingModule, 0, len(dirGroups))
	for dir, files := range dirGroups {
		modules = append(modules, workingModule{
			dir:          dir,
			changedFiles: files,
		})
	}

	sort.Slice(modules, func(i, j int) bool {
		return modules[i].dir < modules[j].dir
	})

	slog.Debug("working modules detected",
		"count", len(modules), "directories", moduleDirs(modules))
	return modules
}

// expandModuleScope expands each working module's scope to include neighbour
// files at the given depth. Neighbours are discovered via the CPG call graph:
// for each method in each module file, find callers/callees up to depth hops
// and add their files to the module's scope.
//
// g may be nil (e.g. Joern not started) — in that case scope is the module
// files themselves.
func expandModuleScope(modules []workingModule, g cpg_engine.Graph, depth int) {
	if g == nil || depth <= 0 {
		slog.Debug("no CPG graph or depth zero, scope = changed files only",
			"graph_available", g != nil, "depth", depth)
		for i := range modules {
			modules[i].scopeFiles = modules[i].changedFiles
		}
		return
	}

	slog.Debug("expanding module scope via CPG neighbours", "depth", depth)
	for i := range modules {
		scopeSet := make(map[string]bool)
		for _, f := range modules[i].changedFiles {
			scopeSet[f] = true
		}

		for _, f := range modules[i].changedFiles {
			nodes, err := g.QueryNodesByFile(f, cpg_engine.NodeMethod)
			if err != nil {
				slog.Debug("failed to query nodes for file", "file", f, "error", err)
				continue
			}
			for _, n := range nodes {
				neighbours, err := g.GetNeighboursAtDepth(n.ID, depth)
				if err != nil {
					slog.Debug("failed to get neighbours", "node", n.ID, "depth", depth, "error", err)
					continue
				}
				for _, nb := range neighbours {
					if nb.File != "" {
						scopeSet[nb.File] = true
					}
				}
			}
		}

		modules[i].scopeFiles = setToSortedSlice(scopeSet)
		slog.Debug("module scope expanded",
			"module", modules[i].dir,
			"changed", len(modules[i].changedFiles),
			"scope", len(modules[i].scopeFiles))
	}
}

// flattenScope returns the union of all scope files across all working modules.
func flattenScope(modules []workingModule) []string {
	seen := make(map[string]bool)
	for _, m := range modules {
		for _, f := range m.scopeFiles {
			seen[f] = true
		}
	}
	result := setToSortedSlice(seen)
	slog.Debug("flattened scope", "total_files", len(result))
	return result
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func setToSortedSlice(s map[string]bool) []string {
	r := make([]string, 0, len(s))
	for k := range s {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}

func moduleDirs(modules []workingModule) []string {
	dirs := make([]string, len(modules))
	for i, m := range modules {
		dirs[i] = m.dir
	}
	return dirs
}

// filterScopeByLanguage filters a file list to include only files that match
// one of the supported languages, and excludes test files via
// filterTestFiles. This reduces the CPG build scope to files that taint
// analysis can actually process and that are actually worth reasoning
// about.
//
// filterTestFiles existed, fully implemented with per-language exclusion
// patterns and its own tests, but was never actually called from anywhere in
// the pipeline — found live on a real Grafana scan: targeting selected 604
// surfaces, and a meaningful fraction were test files (test fixtures,
// mocked SSRF-shaped requests, etc.), including one that got a genuine
// CWE-918 VIOLATION verdict for what was actually test/mock code. Wiring
// the existing, already-correct exclusion in here (the single choke point
// every CPG-scope call site already funnels through) fixes it everywhere
// at once rather than patching each of the three call sites individually.
func filterScopeByLanguage(files []string) []string {
	result := make([]string, 0, len(files))
	for _, f := range filterTestFiles(files) {
		if _, ok := cpg_engine.DetectLanguage(f); ok {
			result = append(result, f)
		}
	}
	slog.Debug("filtered scope by language",
		"input", len(files), "output", len(result))
	return result
}

// filterTestFiles removes test files from files using util.IsTestFile.
func filterTestFiles(files []string) []string {
	result := make([]string, 0, len(files))
	for _, f := range files {
		if !util.IsTestFile(f) {
			result = append(result, f)
		}
	}
	slog.Debug("filtered test files",
		"input", len(files), "output", len(result))
	return result
}
