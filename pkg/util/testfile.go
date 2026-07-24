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

// Package util holds small, dependency-free helpers shared across internal
// packages that would otherwise need to import each other (and cycle) to
// reuse them.
package util

import (
	"path/filepath"
	"strings"
)

// Source: conventional test-file naming per each language's official toolchain docs
// (Maven/Gradle for Java/Kotlin, go test for Go, pytest/unittest for Python,
// Jest/Vitest for JavaScript/TypeScript).

// IsTestFile reports whether path is a test file that should be excluded from
// CPG ingestion and surface selection. Matches by path pattern, not content.
// Patterns are language-conventional and do not require a file read.
//
// Single source of truth for this check — internal/pipeline (incremental
// changed-file-list scans) and internal/semantic/targeting (surface seed
// selection over CPG method nodes, which applies regardless of how the CPG
// was built) both need it, and neither can import the other without an
// import cycle. Previously duplicated between the two; centralized here
// after the duplication caused the two copies to drift slightly out of sync
// (one used HasPrefix(base, "test"), the other the narrower
// HasPrefix(base, "test_")).
func IsTestFile(path string) bool {
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
