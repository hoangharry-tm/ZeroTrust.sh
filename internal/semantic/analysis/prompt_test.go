package analysis

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

func TestBuildPrompt_MidModeHasScaffold(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	prompt := buildPrompt(surface, "mid", "")
	for _, step := range []string{"Step 1", "Step 2", "Step 3", "Step 4", "Step 5"} {
		if !strings.Contains(prompt, step) {
			t.Errorf("mid-mode prompt should contain %q", step)
		}
	}
}

func TestBuildPrompt_FrontierModeHasFewShot(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	prompt := buildPrompt(surface, "frontier", "")
	if !strings.Contains(prompt, "FEW-SHOT EXAMPLES") {
		t.Errorf("frontier-mode prompt should contain 'FEW-SHOT EXAMPLES', got:\n%s", prompt)
	}
}

func TestObfuscateCode_StripsPackageDeclaration(t *testing.T) {
	// Package declarations are removed regardless of language or project name.
	input := "package com.acme.payments.controller\n\nfunc foo() {}"
	got := obfuscateCode(input)
	if strings.Contains(got, "package ") {
		t.Errorf("obfuscateCode should strip package declarations, got:\n%s", got)
	}
	if !strings.Contains(got, "foo") {
		t.Errorf("obfuscateCode should preserve non-package lines, got:\n%s", got)
	}
}

func TestObfuscateCode_StripsImports(t *testing.T) {
	// Import lines removed for both single-line and block form.
	single := "import java.util.List\nint x = 1;"
	got := obfuscateCode(single)
	if strings.Contains(got, "import") {
		t.Errorf("single-line import not stripped, got:\n%s", got)
	}

	block := "import (\n\t\"fmt\"\n\t\"os\"\n)\nfunc f() {}"
	got2 := obfuscateCode(block)
	if strings.Contains(got2, "import") || strings.Contains(got2, "fmt") {
		t.Errorf("block import not stripped, got:\n%s", got2)
	}
}

func TestObfuscateCode_StripsLineComments(t *testing.T) {
	// // # and "-- " (SQL with space) stripped; "--i" decrement preserved.
	input := "// java comment\n# python comment\n-- sql comment\nreal code"
	got := obfuscateCode(input)
	if strings.Contains(got, "comment") {
		t.Errorf("line comments not stripped, got:\n%s", got)
	}
	if !strings.Contains(got, "real code") {
		t.Errorf("non-comment lines must be preserved, got:\n%s", got)
	}
}

func TestObfuscateCode_PreservesDecrementOperator(t *testing.T) {
	// "--i" and "i--" are decrement operators, not SQL comments — must not be stripped.
	input := "for (int i = 10; i > 0; ) {\n\t--i;\n\tcount--;\n}"
	got := obfuscateCode(input)
	if !strings.Contains(got, "--i") {
		t.Errorf("prefix decrement '--i' must be preserved, got:\n%s", got)
	}
	if !strings.Contains(got, "count--") {
		t.Errorf("postfix decrement 'count--' must be preserved, got:\n%s", got)
	}
}

func TestObfuscateCode_BlanksStringLiterals(t *testing.T) {
	// String contents blanked; quotes and code structure preserved.
	input := `stmt.executeQuery("SELECT * FROM users WHERE name='" + userInput + "'");`
	got := obfuscateCode(input)
	if strings.Contains(got, "SELECT") {
		t.Errorf("string literal contents should be blanked, got:\n%s", got)
	}
	// concatenation structure must survive
	if !strings.Contains(got, "+") {
		t.Errorf("code structure (concatenation) must be preserved, got:\n%s", got)
	}
}

func TestObfuscateCode_PreservesVulnerablePattern(t *testing.T) {
	// A raw SQLi pattern must remain structurally visible after obfuscation.
	input := `String q = "SELECT * FROM t WHERE id='" + id + "'";
stmt.executeQuery(q);`
	got := obfuscateCode(input)
	if !strings.Contains(got, "executeQuery") {
		t.Errorf("sink method name must survive obfuscation, got:\n%s", got)
	}
	if !strings.Contains(got, "+ id +") {
		t.Errorf("taint concatenation pattern must survive, got:\n%s", got)
	}
}

func TestShortPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "src/main/java/org/owasp/webgoat/container/mailbox/MailboxController.java",
			expected: "mailbox/MailboxController.java",
		},
		{
			input:    "MailboxController.java",
			expected: "MailboxController.java",
		},
		{
			input:    "a/b",
			expected: "a/b",
		},
		{
			input:    "",
			expected: "",
		},
	}
	for _, tc := range tests {
		got := shortPath(tc.input)
		if got != tc.expected {
			t.Errorf("shortPath(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestBuildCFP_ShortPath(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "src/main/java/org/owasp/webgoat/container/MailboxController.java",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	cfp := buildCFP(surface)
	if strings.Contains(cfp, "owasp") {
		t.Errorf("buildCFP output should not contain 'owasp', got:\n%s", cfp)
	}
	if strings.Contains(cfp, "webgoat") {
		t.Errorf("buildCFP output should not contain 'webgoat', got:\n%s", cfp)
	}
	if !strings.Contains(cfp, "container/MailboxController.java") {
		t.Errorf("buildCFP output should contain last 2 path components, got:\n%s", cfp)
	}
}

// ── H1: CFP sink contamination filter ─────────────────────────────────────

func TestFilterSinksByCWE_RemovesIrrelevantSinksForCWE862(t *testing.T) {
	// CWE-862 (Missing Auth) must NOT see executeQuery/readObject in CFP.
	// These are CWE-89/CWE-502 sinks that Joern injects globally.
	sinks := []string{"executeQuery", "exec", "readObject"}
	got := filterSinksByCWE(sinks, "CWE-862")
	for _, banned := range []string{"executeQuery", "readObject"} {
		for _, g := range got {
			if g == banned {
				t.Errorf("CWE-862 CFP should NOT contain %q, got %v", banned, got)
			}
		}
	}
}

func TestFilterSinksByCWE_RemovesIrrelevantSinksForCWE22(t *testing.T) {
	// CWE-22 (Path Traversal) must NOT receive executeQuery in its CFP.
	sinks := []string{"executeQuery", "Files.copy", "exec"}
	got := filterSinksByCWE(sinks, "CWE-22")
	for _, g := range got {
		if g == "executeQuery" {
			t.Errorf("CWE-22 CFP should NOT contain executeQuery, got %v", got)
		}
	}
	found := false
	for _, g := range got {
		if g == "Files.copy" {
			found = true
		}
	}
	if !found {
		t.Errorf("CWE-22 CFP should contain Files.copy, got %v", got)
	}
}

func TestFilterSinksByCWE_PreservesRelevantSinksForCWE89(t *testing.T) {
	// CWE-89: executeQuery IS the relevant sink — must pass through.
	sinks := []string{"executeQuery", "exec", "readObject"}
	got := filterSinksByCWE(sinks, "CWE-89")
	found := false
	for _, g := range got {
		if g == "executeQuery" {
			found = true
		}
	}
	if !found {
		t.Errorf("CWE-89 CFP must contain executeQuery, got %v", got)
	}
}

func TestFilterSinksByCWE_EmptySinksReturnsNil(t *testing.T) {
	got := filterSinksByCWE(nil, "CWE-89")
	if got != nil {
		t.Errorf("nil sinks should return nil, got %v", got)
	}
	got = filterSinksByCWE([]string{}, "CWE-89")
	if got != nil {
		t.Errorf("empty sinks should return nil, got %v", got)
	}
}

func TestFilterSinksByCWE_UnknownCWEPassesThrough(t *testing.T) {
	// If CWE has no rulebook entry, don't filter anything.
	sinks := []string{"executeQuery", "exec"}
	got := filterSinksByCWE(sinks, "CWE-9999")
	if len(got) != len(sinks) {
		t.Errorf("unknown CWE should pass through all sinks, got %v", got)
	}
}

func TestFilterSinksByCWE_EmptyCWEPassesThrough(t *testing.T) {
	sinks := []string{"executeQuery", "exec"}
	got := filterSinksByCWE(sinks, "")
	if len(got) != len(sinks) {
		t.Errorf("empty CWE should pass through all sinks, got %v", got)
	}
}

func TestFilterSinksByCWE_IntersectionEmptyReturnsNil(t *testing.T) {
	// CWE-22 anchors are file sinks — if only SQL sinks provided, result is empty.
	sinks := []string{"executeQuery", "db.Query"}
	got := filterSinksByCWE(sinks, "CWE-22")
	if len(got) != 0 {
		t.Errorf("no matching anchors should return empty, got %v", got)
	}
}

func TestBuildCFP_CWE862OmitsSinkLine(t *testing.T) {
	// When filtered sinks are empty for CWE-862, the "Sink nodes:" line must be absent.
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "auth/Controller.java",
			Kind: targeting.SurfaceExternalInput,
		},
		SinkNodes:   []string{"executeQuery", "readObject"},
		ContractCWE: "CWE-862",
	}
	cfp := buildCFP(surface)
	if strings.Contains(cfp, "Sink nodes") {
		t.Errorf("CWE-862 CFP should omit 'Sink nodes' line when no relevant sinks, got:\n%s", cfp)
	}
	if strings.Contains(cfp, "executeQuery") {
		t.Errorf("CWE-862 CFP must not contain executeQuery, got:\n%s", cfp)
	}
}

func TestBuildCFP_CWE89IncludesSinkLine(t *testing.T) {
	// CWE-89: executeQuery is relevant and must appear.
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "sql/Repo.java",
			Kind: targeting.SurfaceExternalInput,
		},
		SinkNodes:   []string{"executeQuery", "readObject"},
		ContractCWE: "CWE-89",
	}
	cfp := buildCFP(surface)
	if !strings.Contains(cfp, "Sink nodes") {
		t.Errorf("CWE-89 CFP should include 'Sink nodes' line, got:\n%s", cfp)
	}
	if !strings.Contains(cfp, "executeQuery") {
		t.Errorf("CWE-89 CFP must contain executeQuery, got:\n%s", cfp)
	}
	if strings.Contains(cfp, "readObject") {
		t.Errorf("CWE-89 CFP should not contain readObject (CWE-502 sink), got:\n%s", cfp)
	}
}

func TestBuildCFP_CWE22FiltersExecuteQuery(t *testing.T) {
	// CWE-22: file sinks pass through, SQL sinks are stripped.
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "file/Upload.java",
			Kind: targeting.SurfaceExternalInput,
		},
		SinkNodes:   []string{"executeQuery", "Files.copy", "exec"},
		ContractCWE: "CWE-22",
	}
	cfp := buildCFP(surface)
	if strings.Contains(cfp, "executeQuery") {
		t.Errorf("CWE-22 CFP must not contain executeQuery, got:\n%s", cfp)
	}
	if !strings.Contains(cfp, "Files.copy") {
		t.Errorf("CWE-22 CFP must contain Files.copy, got:\n%s", cfp)
	}
}

func TestBuildCFP_NoSinksNoSinkLine(t *testing.T) {
	// Surface with no SinkNodes at all: Sink nodes line must be omitted.
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "Controller.java",
			Kind: targeting.SurfaceExternalInput,
		},
		ContractCWE: "CWE-89",
	}
	cfp := buildCFP(surface)
	if strings.Contains(cfp, "Sink nodes") {
		t.Errorf("CFP with no sinks should omit 'Sink nodes' line, got:\n%s", cfp)
	}
}

// ── Fix 1: String literal preservation in B5 prompts ─────────────────────

func TestBuildPromptMid_PreservesStringLiterals(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
		Code: `executeQuery("SELECT * FROM users WHERE id='" + id + "'")`,
	}
	prompt := buildPromptMid(surface, "")
	if !strings.Contains(prompt, "SELECT") {
		t.Errorf("buildPromptMid should preserve string literal contents, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "users") {
		t.Errorf("buildPromptMid should preserve 'users' in string, got:\n%s", prompt)
	}
}

func TestBuildPromptFrontier_PreservesStringLiterals(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
		Code: `executeQuery("SELECT * FROM users WHERE id='" + id + "'")`,
	}
	prompt := buildPromptFrontier(surface, "")
	if !strings.Contains(prompt, "SELECT") {
		t.Errorf("buildPromptFrontier should preserve string literal contents, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "users") {
		t.Errorf("buildPromptFrontier should preserve 'users' in string, got:\n%s", prompt)
	}
}

func TestBuildPromptSmall_PreservesStringLiterals(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
		Code: `executeQuery("SELECT * FROM users WHERE id='" + id + "'")`,
	}
	prompt := buildPromptSmall(surface, "")
	if !strings.Contains(prompt, "SELECT") {
		t.Errorf("buildPromptSmall should preserve string literal contents, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "users") {
		t.Errorf("buildPromptSmall should preserve 'users' in string, got:\n%s", prompt)
	}
}

// ── Fix 3: Narrow taint_mismatch instruction in B5 prompts ────────────────

func TestBuildPromptMid_TaintMismatchInstructionIsNarrow(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	prompt := buildPromptMid(surface, "")
	if !strings.Contains(prompt, "absent from BOTH") {
		t.Errorf("mid prompt should contain narrow taint_mismatch definition with 'absent from BOTH', got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "SINK CONTEXT' block is shown") {
		t.Errorf("mid prompt should mention SINK CONTEXT block in taint_mismatch instruction, got:\n%s", prompt)
	}
}

func TestBuildPromptFrontier_HasMismatchExample(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	prompt := buildPromptFrontier(surface, "")
	if !strings.Contains(prompt, "TAINT MISMATCH") {
		t.Errorf("frontier prompt should contain 'TAINT MISMATCH' example, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "mis-attributed") {
		t.Errorf("frontier prompt should contain 'mis-attributed' in mismatch example, got:\n%s", prompt)
	}
}

func TestBuildPromptFrontier_HasNotMismatchExample(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	prompt := buildPromptFrontier(surface, "")
	if !strings.Contains(prompt, "prepareStatement") {
		t.Errorf("frontier prompt should contain 'prepareStatement' in NOT a mismatch example, got:\n%s", prompt)
	}
}

func TestBuildPrompt_NoWorldKnowledge(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	prompt := buildPrompt(surface, "mid", "")
	if !strings.Contains(prompt, "Do NOT use prior knowledge") {
		t.Errorf("buildPrompt should contain 'Do NOT use prior knowledge', got:\n%s", prompt)
	}
}

// ── Fix 2: prompt NOTE for weak confidence ────────────────────────────────

func TestBuildPromptMid_WeakConfidenceContainsNOTE(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "weak-surface",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
		ContractCWE:     "CWE-89",
		TaintConfidence: "weak",
	}
	prompt := buildPrompt(surface, "mid", "")
	if !strings.Contains(prompt, "No inter-procedural taint path was confirmed") {
		t.Errorf("mid prompt with TaintConfidence=weak should contain the NOTE, got:\n%s", prompt)
	}
}

func TestBuildPromptMid_EmptyConfidenceNoNOTE(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "normal-surface",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
		ContractCWE: "CWE-89",
	}
	prompt := buildPrompt(surface, "mid", "")
	if strings.Contains(prompt, "No inter-procedural taint path was confirmed") {
		t.Errorf("mid prompt without TaintConfidence=weak should NOT contain the NOTE, got:\n%s", prompt)
	}
}

func TestBuildPromptFrontier_WeakConfidenceContainsNOTE(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "weak-surface-frontier",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
		ContractCWE:     "CWE-89",
		TaintConfidence: "weak",
	}
	prompt := buildPrompt(surface, "frontier", "")
	if !strings.Contains(prompt, "No inter-procedural taint path was confirmed") {
		t.Errorf("frontier prompt with TaintConfidence=weak should contain the NOTE, got:\n%s", prompt)
	}
}

func TestBuildPromptFrontier_EmptyConfidenceNoNOTE(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "normal-surface-frontier",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
		ContractCWE: "CWE-89",
	}
	prompt := buildPrompt(surface, "frontier", "")
	if strings.Contains(prompt, "No inter-procedural taint path was confirmed") {
		t.Errorf("frontier prompt without TaintConfidence=weak should NOT contain the NOTE, got:\n%s", prompt)
	}
}

// ── Fix 2 regression: B5 prompts do NOT obfuscateCode string literals ─────

// ── Fix 5: Sink context in B5 prompts ──────────────────────────────────

func TestBuildPromptMid_SinkContext(t *testing.T) {
	tmpDir := t.TempDir()
	sinkFile := tmpDir + "/UserDao.java"
	sinkContent := "package dao;\n\npublic class UserDao {\n    public void findUser(String id) {\n        stmt.executeQuery(input);\n    }\n}"
	require.NoError(t, os.WriteFile(sinkFile, []byte(sinkContent), 0o644))

	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:           "s1",
			File:         "src/controller/UserController.java",
			FunctionName: "getUser",
			Kind:         targeting.SurfaceExternalInput,
		},
		Code:     "public User getUser(String id) { return dao.findUser(id); }",
		SinkFile: sinkFile,
		SinkLine: 5,
	}
	prompt := buildPrompt(surface, "mid", "")
	if !strings.Contains(prompt, "SINK CONTEXT") {
		t.Errorf("mid prompt should contain 'SINK CONTEXT' section, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "→ 5:") {
		t.Errorf("mid prompt should mark sink line 5 with →, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "executeQuery") {
		t.Errorf("mid prompt sink context should contain executeQuery, got:\n%s", prompt)
	}
}

func TestBuildPromptMid_SinkContextOmittedWhenSameFile(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "src/controller/UserController.java",
			Kind: targeting.SurfaceExternalInput,
		},
		Code:     "public User getUser(String id) { return dao.findUser(id); }",
		SinkFile: "src/controller/UserController.java",
		SinkLine: 5,
	}
	prompt := buildPrompt(surface, "mid", "")
	if strings.Contains(prompt, "=== SINK CONTEXT ") {
		t.Errorf("mid prompt should NOT show SINK CONTEXT section when sink is in same file, got:\n%s", prompt)
	}
}

func TestB5PromptPreservesStringLiterals(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:           "test-sqli",
			FunctionName: "injectableQuery",
			File:         "SqlInjectionLesson5a.java",
			Kind:         targeting.SurfaceExternalInput,
		},
		ContractCWE: "CWE-89",
		Code: `protected AttackResult injectableQuery(String accountName) {
    String query = "SELECT * FROM user_data WHERE last_name = '" + accountName + "'";
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    return success(this).build();
}`,
	}

	for _, mode := range []string{"small", "mid", "frontier"} {
		t.Run(mode, func(t *testing.T) {
			got := buildPrompt(surface, mode, "")
			if strings.Contains(got, `""`) && !strings.Contains(got, `"SELECT`) {
				t.Errorf("mode=%s: obfuscateCode appears to have blanked string literals; got:\n%s", mode, got[:500])
			}
			if !strings.Contains(got, "SELECT") {
				t.Errorf("mode=%s: SQL query string not preserved in B5 prompt; got:\n%s", mode, got[:500])
			}
		})
	}
}
