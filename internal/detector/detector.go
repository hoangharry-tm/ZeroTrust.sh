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

// Package detector probes a project directory and returns a StackProfile
// describing its languages and manifest files. Scanners use this to decide
// whether they are applicable to the target.
package detector

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// StackProfile summarises what was found in the target directory.
type StackProfile struct {
	// Languages is the set of detected language names, e.g. "go", "python".
	Languages map[string]struct{}
	// Manifests is the set of manifest/lockfile basenames found, e.g. "go.mod".
	Manifests map[string]struct{}
}

// HasLanguage reports whether lang was detected (case-insensitive).
func (s StackProfile) HasLanguage(lang string) bool {
	_, ok := s.Languages[strings.ToLower(lang)]
	return ok
}

// HasManifest reports whether the given filename basename was found.
func (s StackProfile) HasManifest(name string) bool {
	_, ok := s.Manifests[name]
	return ok
}

// extToLang maps file extensions to canonical language names.
var extToLang = map[string]string{
	".go":    "go",
	".py":    "python",
	".js":    "javascript",
	".ts":    "typescript",
	".mjs":   "javascript",
	".rs":    "rust",
	".java":  "java",
	".rb":    "ruby",
	".php":   "php",
	".cs":    "csharp",
	".kt":    "kotlin",
	".kts":   "kotlin",
	".swift": "swift",
	".dart":  "dart",
	".c":     "c",
	".cpp":   "cpp",
	".h":     "c",
	".hpp":   "cpp",
}

// knownManifests lists files whose presence signals a package ecosystem.
var knownManifests = map[string]struct{}{
	"go.mod":           {},
	"go.sum":           {},
	"cargo.toml":       {},
	"cargo.lock":       {},
	"package.json":     {},
	"package-lock.json": {},
	"yarn.lock":        {},
	"requirements.txt": {},
	"pipfile.lock":     {},
	"poetry.lock":      {},
	"gemfile":          {},
	"gemfile.lock":     {},
	"mix.exs":          {},
	"mix.lock":         {},
	"pom.xml":          {},
	"build.gradle":     {},
}

// Detect walks target and returns a StackProfile.
// It skips hidden directories and common vendor/generated paths.
func Detect(target string) (StackProfile, error) {
	profile := StackProfile{
		Languages: make(map[string]struct{}),
		Manifests: make(map[string]struct{}),
	}

	err := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		name := d.Name()
		if d.IsDir() {
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules" || name == "target" {
				return filepath.SkipDir
			}
			return nil
		}
		lower := strings.ToLower(name)
		if _, ok := knownManifests[lower]; ok {
			profile.Manifests[lower] = struct{}{}
		}
		ext := strings.ToLower(filepath.Ext(name))
		if lang, ok := extToLang[ext]; ok {
			profile.Languages[lang] = struct{}{}
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return profile, err
	}
	return profile, nil
}
