package contracts

import (
	"context"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

// ── Fix 2: hasSafeNode ──────────────────────────────────────────────────────

func TestHasSafeNode_CallPath(t *testing.T) {
	if !hasSafeNode([]string{"parameterize", "execute"}, []string{"parameterize"}, "") {
		t.Error("expected match via call path")
	}
}

func TestHasSafeNode_CodeBodyFallback(t *testing.T) {
	// Joern call path has only variable names — fallback to code body must kick in.
	// Use actual CWE-89 safe node strings from the rulebook.
	callPath := []string{"results", "results", "getMetaData"}
	safeNodes := []string{"paramQuery", "prepareStmt", "boundParam"}
	code := `PreparedStatement ps = conn.prepareStmt("SELECT * FROM t WHERE id=?"); ps.setInt(1, id);`
	if !hasSafeNode(callPath, safeNodes, code) {
		t.Error("expected match via code body fallback when call path is only variable names")
	}
}

func TestHasSafeNode_NoMatch(t *testing.T) {
	callPath := []string{"results", "executeQuery"}
	safeNodes := []string{"preparedStatement", "parameterize"}
	code := `stmt.executeQuery("SELECT * FROM t WHERE id='" + id + "'");`
	if hasSafeNode(callPath, safeNodes, code) {
		t.Error("expected no match — no safe sanitizer present")
	}
}

func TestHasSafeNode_EmptySafeNodes(t *testing.T) {
	if hasSafeNode([]string{"preparedStatement"}, []string{}, "preparedStatement") {
		t.Error("empty safe nodes list must always return false")
	}
}

func TestHasSafeNode_EmptyEverything(t *testing.T) {
	if hasSafeNode([]string{}, []string{"parameterize"}, "") {
		t.Error("empty call path and empty code must return false")
	}
}

// ── Fix 5: CWE-89 excluded from code-body fallback ──────────────────────────

func TestCWE89NotFiredViaCodeBody(t *testing.T) {
	// Surface has executeQuery in Code but empty SinkNodes (no taint-confirmed path).
	// CWE-89 must NOT fire via code-body fallback — only via confirmed SinkNodes.
	c := New()
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "test-cwe89-guard",
			Kind: targeting.SurfaceExternalInput,
		},
		SinkNodes: []string{}, // no taint-confirmed sink
		CallPath:  []string{},
		Code:      `stmt.executeQuery("SELECT * FROM users WHERE id='" + id + "'");`,
	}
	result := c.Check(context.Background(), surface)
	if result.Verdict == VerdictViolation && result.CWE == "CWE-89" {
		t.Errorf("CWE-89 must not fire via code-body fallback (no SinkNodes); got VerdictViolation CWE-89")
	}
}

func TestCWE22FiredViaCodeBody(t *testing.T) {
	// CWE-22 SHOULD fire via code-body fallback when function body contains file sink.
	c := New()
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "test-cwe22-code",
			Kind: targeting.SurfaceExternalInput,
		},
		SinkNodes: []string{}, // no BFS sink — relies on code fallback
		CallPath:  []string{},
		Code:      `FileWriter fw = new FileWriter(userInput); fw.write(data);`,
	}
	result := c.Check(context.Background(), surface)
	if result.CWE != "CWE-22" {
		t.Errorf("expected CWE-22 via code-body fallback, got verdict=%s cwe=%s", result.Verdict, result.CWE)
	}
}
