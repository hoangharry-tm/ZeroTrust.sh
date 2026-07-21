package analysis

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

func TestBuildPrompt_HasReasoningScaffold(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	prompt := buildPrompt(surface, "")
	for _, step := range []string{"Step 1", "Step 2", "Step 3", "Step 4", "Step 5"} {
		if !strings.Contains(prompt, step) {
			t.Errorf("prompt should contain %q", step)
		}
	}
}

func TestBuildPrompt_HasFewShotExamples(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	prompt := buildPrompt(surface, "")
	if !strings.Contains(prompt, "FEW-SHOT EXAMPLES") {
		t.Errorf("prompt should contain 'FEW-SHOT EXAMPLES', got:\n%s", prompt)
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

func TestBuildPrompt_PreservesStringLiterals(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
		Code: `executeQuery("SELECT * FROM users WHERE id='" + id + "'")`,
	}
	prompt := buildPrompt(surface, "")
	if !strings.Contains(prompt, "SELECT") {
		t.Errorf("buildPrompt should preserve string literal contents, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "users") {
		t.Errorf("buildPrompt should preserve 'users' in string, got:\n%s", prompt)
	}
}

// ── Fix 3: Narrow taint_mismatch instruction in B5 prompts ────────────────

func TestBuildPrompt_TaintMismatchInstructionIsNarrow(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	prompt := buildPrompt(surface, "")
	if !strings.Contains(prompt, "absent from BOTH") {
		t.Errorf("prompt should contain narrow taint_mismatch definition with 'absent from BOTH', got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "SINK CONTEXT' block is shown") {
		t.Errorf("prompt should mention SINK CONTEXT block in taint_mismatch instruction, got:\n%s", prompt)
	}
}

func TestBuildPrompt_HasMismatchExample(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	prompt := buildPrompt(surface, "")
	if !strings.Contains(prompt, "TAINT MISMATCH") {
		t.Errorf("prompt should contain 'TAINT MISMATCH' example, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "mis-attributed") {
		t.Errorf("prompt should contain 'mis-attributed' in mismatch example, got:\n%s", prompt)
	}
}

func TestBuildPrompt_HasNotMismatchExample(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	prompt := buildPrompt(surface, "")
	if !strings.Contains(prompt, "prepareStatement") {
		t.Errorf("prompt should contain 'prepareStatement' in NOT a mismatch example, got:\n%s", prompt)
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
	prompt := buildPrompt(surface, "")
	if !strings.Contains(prompt, "Do NOT use prior knowledge") {
		t.Errorf("buildPrompt should contain 'Do NOT use prior knowledge', got:\n%s", prompt)
	}
}

// ── Fix 2: prompt NOTE for weak confidence ────────────────────────────────

func TestBuildPrompt_WeakConfidenceContainsNOTE(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "weak-surface",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
		ContractCWE:     "CWE-89",
		TaintConfidence: "weak",
	}
	prompt := buildPrompt(surface, "")
	if !strings.Contains(prompt, "No inter-procedural taint path was confirmed") {
		t.Errorf("prompt with TaintConfidence=weak should contain the NOTE, got:\n%s", prompt)
	}
}

func TestBuildPrompt_EmptyConfidenceNoNOTE(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "normal-surface",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
		ContractCWE: "CWE-89",
	}
	prompt := buildPrompt(surface, "")
	if strings.Contains(prompt, "No inter-procedural taint path was confirmed") {
		t.Errorf("prompt without TaintConfidence=weak should NOT contain the NOTE, got:\n%s", prompt)
	}
}

// ── Fix 5: Sink context in B5 prompts ──────────────────────────────────

func TestBuildPrompt_SinkContext(t *testing.T) {
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
	prompt := buildPrompt(surface, "")
	if !strings.Contains(prompt, "SINK CONTEXT") {
		t.Errorf("prompt should contain 'SINK CONTEXT' section, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "→ 5:") {
		t.Errorf("prompt should mark sink line 5 with →, got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "executeQuery") {
		t.Errorf("prompt sink context should contain executeQuery, got:\n%s", prompt)
	}
}

func TestBuildPrompt_SinkContextOmittedWhenSameFile(t *testing.T) {
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
	prompt := buildPrompt(surface, "")
	if strings.Contains(prompt, "=== SINK CONTEXT ") {
		t.Errorf("prompt should NOT show SINK CONTEXT section when sink is in same file, got:\n%s", prompt)
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

	got := buildPrompt(surface, "")
	if strings.Contains(got, `""`) && !strings.Contains(got, `"SELECT`) {
		t.Errorf("obfuscateCode appears to have blanked string literals; got:\n%s", got[:500])
	}
	if !strings.Contains(got, "SELECT") {
		t.Errorf("SQL query string not preserved in B5 prompt; got:\n%s", got[:500])
	}
}
