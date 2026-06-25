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
	"path/filepath"
	"sort"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// ScanMode controls the module segmentation scope.
type ScanMode string

const (
	ScanModeDefault   ScanMode = "Default"
	ScanModeThorough  ScanMode = "Thorough"
	ScanModeFull      ScanMode = "Full"
)

// WorkingModule represents a detected working module — a directory containing
// changed source files, plus its expanded neighbour scope.
type WorkingModule struct {
	// Dir is the relative directory path of the module (e.g. "src/handlers").
	Dir string
	// ChangedFiles are the files in this module that triggered the scan.
	ChangedFiles []string
	// ScopeFiles are the files within this module's scan scope (module files
	// plus depth-expanded neighbours).
	ScopeFiles []string
}

// DetectWorkingModules partitions the changed file set into working modules
// based on directory ancestry. A working module is the deepest directory that
// contains two or more changed files, or the parent directory of a single
// changed file.
//
// For example:
//
//	Changed: src/handlers/user.go, src/handlers/order.go, src/services/payment.go
//	Modules: [{Dir: "src/handlers", Files: 2}, {Dir: "src/services", Files: 1}]
func DetectWorkingModules(changedFiles []string) []WorkingModule {
	if len(changedFiles) == 0 {
		return nil
	}

	// Group by directory.
	dirGroups := make(map[string][]string)
	for _, f := range changedFiles {
		d := filepath.Dir(f)
		dirGroups[d] = append(dirGroups[d], f)
	}

	modules := make([]WorkingModule, 0, len(dirGroups))
	for dir, files := range dirGroups {
		modules = append(modules, WorkingModule{
			Dir:          dir,
			ChangedFiles: files,
		})
	}

	// Sort by directory for deterministic output.
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Dir < modules[j].Dir
	})

	return modules
}

// ExpandModuleScope expands each working module's scope to include neighbour
// files at the given depth. Neighbours are discovered via the CPG call graph:
// for each method in each module file, find callers/callees up to depth hops
// and add their files to the module's scope.
//
// Graph may be nil (e.g. Joern not started) — in that case scope is the
// module files themselves.
func ExpandModuleScope(modules []WorkingModule, g cpg.Graph, depth int) {
	if g == nil || depth <= 0 {
		for i := range modules {
			modules[i].ScopeFiles = modules[i].ChangedFiles
		}
		return
	}

	for i := range modules {
		scopeSet := make(map[string]bool)
		for _, f := range modules[i].ChangedFiles {
			scopeSet[f] = true
		}

		// For each changed file, find neighbour functions and add their files.
		for _, f := range modules[i].ChangedFiles {
			nodes, err := g.QueryNodesByFile(f, cpg.NodeMethod)
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

		modules[i].ScopeFiles = setToSortedSlice(scopeSet)
	}
}

// FlattenScope returns the union of all scope files across all working modules.
func FlattenScope(modules []WorkingModule) []string {
	seen := make(map[string]bool)
	for _, m := range modules {
		for _, f := range m.ScopeFiles {
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

// FilterScopeByLanguage filters a file list to include only files that match
// one of the supported languages. This reduces the CPG build scope to files
// that taint analysis can actually process.
func FilterScopeByLanguage(files []string) []string {
	result := make([]string, 0, len(files))
	for _, f := range files {
		if _, ok := DetectLanguage(f); ok {
			result = append(result, f)
		}
	}
	return result
}
