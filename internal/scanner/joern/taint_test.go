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
	"fmt"
	"testing"
)

// ─── DetectLanguage ───────────────────────────────────────────────────────────

func TestDetectLanguage_JavaExtension(t *testing.T) {
	lang, ok := DetectLanguage("src/main/UserController.java")
	if !ok || lang != LanguageJava {
		t.Errorf("got (%q, %v), want (java, true)", lang, ok)
	}
}

func TestDetectLanguage_PythonExtension(t *testing.T) {
	lang, ok := DetectLanguage("api/auth.py")
	if !ok || lang != LanguagePython {
		t.Errorf("got (%q, %v), want (python, true)", lang, ok)
	}
}

func TestDetectLanguage_GoExtension(t *testing.T) {
	lang, ok := DetectLanguage("internal/db/query.go")
	if !ok || lang != LanguageGo {
		t.Errorf("got (%q, %v), want (go, true)", lang, ok)
	}
}

func TestDetectLanguage_JSVariants(t *testing.T) {
	cases := []string{
		"src/app.js",
		"src/app.jsx",
		"src/app.ts",
		"src/app.tsx",
		"src/app.mjs",
		"src/app.cjs",
	}
	for _, path := range cases {
		lang, ok := DetectLanguage(path)
		if !ok || lang != LanguageJS {
			t.Errorf("DetectLanguage(%q) = (%q, %v), want (js, true)", path, lang, ok)
		}
	}
}

func TestDetectLanguage_ExtensionCaseInsensitive(t *testing.T) {
	lang, ok := DetectLanguage("Controller.JAVA")
	if !ok || lang != LanguageJava {
		t.Errorf("uppercase extension: got (%q, %v), want (java, true)", lang, ok)
	}
}

func TestDetectLanguage_UnknownExtensionReturnsFalse(t *testing.T) {
	unsupported := []string{
		"app.rb",
		"main.php",
		"app.rs",
		"App.kt",
		"main.c",
		"main.cpp",
		"main.swift",
		"no_extension",
		"",
	}
	for _, path := range unsupported {
		lang, ok := DetectLanguage(path)
		if ok {
			t.Errorf("DetectLanguage(%q) = (%q, true), want ('', false)", path, lang)
		}
	}
}

// ─── TaintConfigs structural integrity ───────────────────────────────────────

// All four languages must be present in TaintConfigs.
func TestTaintConfigs_AllLanguagesPresent(t *testing.T) {
	required := []Language{LanguageJava, LanguagePython, LanguageJS, LanguageGo}
	for _, lang := range required {
		if _, ok := TaintConfigs[lang]; !ok {
			t.Errorf("TaintConfigs missing entry for language %q", lang)
		}
	}
}

// Every config's Language field must match its map key.
func TestTaintConfigs_LanguageFieldMatchesKey(t *testing.T) {
	for key, cfg := range TaintConfigs {
		if cfg.Language != key {
			t.Errorf("TaintConfigs[%q].Language = %q, want %q", key, cfg.Language, key)
		}
	}
}

// Each language must have at least one source, one sink, and one sanitizer.
// An empty list means zero taint findings for that language with no diagnostic.
func TestTaintConfigs_EachLanguageHasNonEmptyLists(t *testing.T) {
	for lang, cfg := range TaintConfigs {
		if len(cfg.Sources) == 0 {
			t.Errorf("language %q has 0 sources", lang)
		}
		if len(cfg.Sinks) == 0 {
			t.Errorf("language %q has 0 sinks", lang)
		}
		if len(cfg.Sanitizers) == 0 {
			t.Errorf("language %q has 0 sanitizers", lang)
		}
	}
}

// Every source must have a non-empty Name and a recognised Kind.
func TestTaintConfigs_SourcesHaveValidFields(t *testing.T) {
	validKinds := map[string]bool{
		"http_param":  true,
		"http_body":   true,
		"http_header": true,
		"env_var":     true,
		"stdin":       true,
		"file_read":   true,
	}
	for lang, cfg := range TaintConfigs {
		for i, src := range cfg.Sources {
			if src.Name == "" {
				t.Errorf("lang %q source[%d]: empty Name", lang, i)
			}
			if !validKinds[src.Kind] {
				t.Errorf("lang %q source[%d] %q: unrecognised Kind %q", lang, i, src.Name, src.Kind)
			}
		}
	}
}

// Every sink must have a non-empty Name, a non-empty CWE, and a non-zero Kind.
// An empty CWE produces findings with CWE:"" which breaks Gate 1 dedup keying.
func TestTaintConfigs_SinksHaveValidFields(t *testing.T) {
	for lang, cfg := range TaintConfigs {
		for i, sink := range cfg.Sinks {
			if sink.Name == "" {
				t.Errorf("lang %q sink[%d]: empty Name", lang, i)
			}
			if sink.CWE == "" {
				t.Errorf("lang %q sink[%d] %q: empty CWE (breaks Gate 1 dedup)", lang, i, sink.Name)
			}
			if sink.Kind == "" {
				t.Errorf("lang %q sink[%d] %q: empty Kind", lang, i, sink.Name)
			}
		}
	}
}

// Every sanitizer must have a non-empty Name.
func TestTaintConfigs_SanitizersHaveValidFields(t *testing.T) {
	for lang, cfg := range TaintConfigs {
		for i, san := range cfg.Sanitizers {
			if san.Name == "" {
				t.Errorf("lang %q sanitizer[%d]: empty Name", lang, i)
			}
		}
	}
}

// CWE identifiers must follow the pattern "CWE-<number>".
func TestTaintConfigs_SinkCWEsFollowConvention(t *testing.T) {
	for lang, cfg := range TaintConfigs {
		for _, sink := range cfg.Sinks {
			if len(sink.CWE) < 5 || sink.CWE[:4] != "CWE-" {
				t.Errorf("lang %q sink %q: CWE %q does not follow CWE-NNN convention", lang, sink.Name, sink.CWE)
			}
		}
	}
}

// Each language must cover the four highest-risk sink categories.
func TestTaintConfigs_EachLanguageCoversHighRiskSinks(t *testing.T) {
	required := []string{"CWE-89", "CWE-78", "CWE-502", "CWE-22"}
	for lang, cfg := range TaintConfigs {
		for _, wantCWE := range required {
			found := false
			for _, sink := range cfg.Sinks {
				if sink.CWE == wantCWE {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("language %q missing a sink for %s", lang, wantCWE)
			}
		}
	}
}

// ─── SinkDefForCall ───────────────────────────────────────────────────────────

func TestSinkDefForCall_MatchesSubstring(t *testing.T) {
	// "executeQuery" contains "execute" — the Java sink pattern.
	def, ok := SinkDefForCall(LanguageJava, "executeQuery")
	if !ok {
		t.Fatal("expected match for 'executeQuery' in Java sinks")
	}
	if def.CWE != "CWE-89" {
		t.Errorf("expected CWE-89, got %q", def.CWE)
	}
}

func TestSinkDefForCall_NoMatchReturnsEmpty(t *testing.T) {
	_, ok := SinkDefForCall(LanguageJava, "completelySafeMethod")
	if ok {
		t.Error("expected no match for unknown method")
	}
}

func TestSinkDefForCall_UnknownLanguageReturnsFalse(t *testing.T) {
	_, ok := SinkDefForCall("ruby", "puts")
	if ok {
		t.Error("expected false for unsupported language")
	}
}

func TestSinkDefForCall_AllLanguagesResolveSQLSink(t *testing.T) {
	// Each language must have at least one SQL sink reachable by substring match.
	cases := map[Language]string{
		LanguageJava:   "executeQuery",
		LanguagePython: "execute",
		LanguageJS:     "query",
		LanguageGo:     "Query",
	}
	for lang, call := range cases {
		def, ok := SinkDefForCall(lang, call)
		if !ok {
			t.Errorf("lang %q: no sink match for %q", lang, call)
			continue
		}
		if def.CWE != "CWE-89" {
			t.Errorf("lang %q call %q: expected CWE-89, got %q", lang, call, def.CWE)
		}
	}
}

// ─── SourceDefForCall ─────────────────────────────────────────────────────────

func TestSourceDefForCall_JavaHTTPParam(t *testing.T) {
	def, ok := SourceDefForCall(LanguageJava, "getParameter")
	if !ok {
		t.Fatal("expected match for 'getParameter' in Java sources")
	}
	if def.Kind != "http_param" {
		t.Errorf("expected http_param, got %q", def.Kind)
	}
}

func TestSourceDefForCall_GoEnvVar(t *testing.T) {
	def, ok := SourceDefForCall(LanguageGo, "os.Getenv")
	if !ok {
		t.Fatal("expected match for 'os.Getenv' in Go sources")
	}
	if def.Kind != "env_var" {
		t.Errorf("expected env_var, got %q", def.Kind)
	}
}

func TestSourceDefForCall_NoMatchReturnsEmpty(t *testing.T) {
	_, ok := SourceDefForCall(LanguagePython, "pureSafeFunction")
	if ok {
		t.Error("expected no match for unknown function")
	}
}

// ─── DetectSanitizer ──────────────────────────────────────────────────────────

func TestDetectSanitizer_KnownSanitizerMatches(t *testing.T) {
	cases := []struct {
		lang Language
		name string
	}{
		{LanguageJava, "PreparedStatement"},
		{LanguagePython, "html.escape"},
		{LanguageJS, "DOMPurify"},
		{LanguageGo, "html.EscapeString"},
	}
	for _, tc := range cases {
		if !DetectSanitizer(tc.lang, tc.name) {
			t.Errorf("lang %q: expected %q to be recognised as a sanitizer", tc.lang, tc.name)
		}
	}
}

func TestDetectSanitizer_UnknownFunctionReturnsFalse(t *testing.T) {
	if DetectSanitizer(LanguageGo, "completelyUnknownFunc") {
		t.Error("unknown function must not be detected as a sanitizer")
	}
}

func TestDetectSanitizer_UnknownLanguageReturnsFalse(t *testing.T) {
	if DetectSanitizer("cobol", "sanitize") {
		t.Error("unknown language must return false")
	}
}

// ─── DetectLanguageFromFiles ──────────────────────────────────────────────────

func TestDetectLanguageFromFiles_MajorityWins(t *testing.T) {
	files := []string{
		"a.py", "b.py", "c.py",
		"Main.java", "Helper.java",
	}
	lang, ok := DetectLanguageFromFiles(files)
	if !ok {
		t.Fatal("expected a result for mixed file list")
	}
	if lang != LanguagePython {
		t.Errorf("expected python (majority), got %q", lang)
	}
}

func TestDetectLanguageFromFiles_AllUnsupportedReturnsFalse(t *testing.T) {
	files := []string{"app.rb", "script.sh", "style.css"}
	_, ok := DetectLanguageFromFiles(files)
	if ok {
		t.Error("expected false for all-unsupported file list")
	}
}

func TestDetectLanguageFromFiles_EmptySliceReturnsFalse(t *testing.T) {
	_, ok := DetectLanguageFromFiles(nil)
	if ok {
		t.Error("expected false for nil slice")
	}
}

func TestDetectLanguageFromFiles_TieResolvesToNonZero(t *testing.T) {
	// Tie between java and python: both have 1 file each.
	// The result must be one of them — no panic or empty result.
	files := []string{"Main.java", "app.py"}
	lang, ok := DetectLanguageFromFiles(files)
	if !ok {
		t.Fatal("expected a valid result for tie")
	}
	if lang != LanguageJava && lang != LanguagePython {
		t.Errorf("unexpected language %q for tie", lang)
	}
}

// ─── No duplicate sink names within a language ────────────────────────────────

// Duplicate sink names cause SinkDefForCall to silently return the first match,
// hiding any later correction made to a duplicated entry.
func TestTaintConfigs_NoDuplicateSinkNames(t *testing.T) {
	for lang, cfg := range TaintConfigs {
		seen := make(map[string]int)
		for i, sink := range cfg.Sinks {
			if prev, exists := seen[sink.Name]; exists {
				t.Errorf("lang %q: sink name %q appears at index %d and %d (duplicate)", lang, sink.Name, prev, i)
			}
			seen[sink.Name] = i
		}
	}
}

// ─── No duplicate source names within a language ──────────────────────────────

func TestTaintConfigs_NoDuplicateSourceNames(t *testing.T) {
	for lang, cfg := range TaintConfigs {
		seen := make(map[string]int)
		for i, src := range cfg.Sources {
			key := fmt.Sprintf("%s|%s", src.Name, src.Kind)
			if prev, exists := seen[key]; exists {
				t.Errorf("lang %q: source %q (kind %q) appears at index %d and %d", lang, src.Name, src.Kind, prev, i)
			}
			seen[key] = i
		}
	}
}
