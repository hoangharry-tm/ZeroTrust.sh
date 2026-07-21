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
	"path/filepath"
	"sort"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
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
		return nil
	}

	// Group by directory.
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

	// Sort by directory for deterministic output.
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].dir < modules[j].dir
	})

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
		for i := range modules {
			modules[i].scopeFiles = modules[i].changedFiles
		}
		return
	}

	for i := range modules {
		scopeSet := make(map[string]bool)
		for _, f := range modules[i].changedFiles {
			scopeSet[f] = true
		}

		// For each changed file, find neighbour functions and add their files.
		for _, f := range modules[i].changedFiles {
			nodes, err := g.QueryNodesByFile(f, cpg_engine.NodeMethod)
			if err != nil {
				continue
			}
			for _, n := range nodes {
				neighbours, err := g.GetNeighboursAtDepth(n.ID, depth)
				if err != nil {
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
	return setToSortedSlice(seen)
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

// filterScopeByLanguage filters a file list to include only files that match
// one of the supported languages. This reduces the CPG build scope to files
// that taint analysis can actually process.
func filterScopeByLanguage(files []string) []string {
	result := make([]string, 0, len(files))
	for _, f := range files {
		if _, ok := cpg_engine.DetectLanguage(f); ok {
			result = append(result, f)
		}
	}
	return result
}

// Source: conventional test-file naming per each language's official toolchain docs
// (Maven/Gradle for Java/Kotlin, go test for Go, pytest/unittest for Python,
// Jest/Vitest for JavaScript/TypeScript).

// isTestFile reports whether path is a test file that should be excluded from
// CPG ingestion. Matches by path pattern, not content.
// Patterns are language-conventional and do not require a file read.
func isTestFile(path string) bool {
	base := filepath.Base(path)
	parts := strings.Split(path, string(filepath.Separator))

	// Java/Kotlin: filename ends with Test.java, Tests.java, IT.java, Spec.kt, Test.kt
	if strings.HasSuffix(base, "Test.java") ||
		strings.HasSuffix(base, "Tests.java") ||
		strings.HasSuffix(base, "IT.java") ||
		strings.HasSuffix(base, "Spec.kt") ||
		strings.HasSuffix(base, "Test.kt") {
		return true
	}

	// Go: filename ends with _test.go
	if strings.HasSuffix(base, "_test.go") {
		return true
	}

	// Python: filename starts with test or ends with _test.py
	if strings.HasPrefix(base, "test") || strings.HasSuffix(base, "_test.py") {
		return true
	}

	// JavaScript/TypeScript: filename ends with .test.js, .spec.js, .test.ts, .spec.ts
	if strings.HasSuffix(base, ".test.js") ||
		strings.HasSuffix(base, ".spec.js") ||
		strings.HasSuffix(base, ".test.ts") ||
		strings.HasSuffix(base, ".spec.ts") {
		return true
	}

	// Path segment matching: check each segment exactly (not substring).
	// This prevents "contest" from matching "test".
	for _, part := range parts {
		switch part {
		case "test", "tests", "__tests__", "androidTest", "testFixtures", "it":
			return true
		}
	}

	return false
}

// filterTestFiles removes test files from files using isTestFile.
func filterTestFiles(files []string) []string {
	result := make([]string, 0, len(files))
	for _, f := range files {
		if !isTestFile(f) {
			result = append(result, f)
		}
	}
	return result
}
