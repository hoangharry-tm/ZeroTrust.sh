package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func makeFindings(specs []struct {
	sev  finding.SeverityLabel
	path string
	sp   finding.SourcePath
	conf float64
},
) []finding.Finding {
	out := make([]finding.Finding, len(specs))
	for i, s := range specs {
		out[i] = finding.Finding{
			ID:            strings.ToLower(string(s.sev)),
			SeverityLabel: s.sev,
			Path:          s.path,
			SourcePath:    s.sp,
			Confidence:    s.conf,
			Justification: "test finding",
			CWE:           "CWE-89",
		}
	}
	return out
}

// ── sortFindings ─────────────────────────────────────────────────────────────

func TestSortFindingsSeverityOrder(t *testing.T) {
	in := makeFindings([]struct {
		sev  finding.SeverityLabel
		path string
		sp   finding.SourcePath
		conf float64
	}{
		{finding.SeverityLow, "a.py", finding.SourcePattern, 0.5},
		{finding.SeverityBlock, "b.py", finding.SourcePattern, 0.9},
		{finding.SeverityMedium, "c.py", finding.SourcePattern, 0.7},
		{finding.SeverityHigh, "d.py", finding.SourcePattern, 0.8},
		{finding.SeveritySuppressed, "e.py", finding.SourcePattern, 0.1},
	})
	got := sortFindings(in)
	want := []finding.SeverityLabel{
		finding.SeverityBlock,
		finding.SeverityHigh,
		finding.SeverityMedium,
		finding.SeverityLow,
		finding.SeveritySuppressed,
	}
	for i, sev := range want {
		if got[i].SeverityLabel != sev {
			t.Errorf("position %d: want %s, got %s", i, sev, got[i].SeverityLabel)
		}
	}
}

func TestSortFindingsTieBreakByConfidence(t *testing.T) {
	in := makeFindings([]struct {
		sev  finding.SeverityLabel
		path string
		sp   finding.SourcePath
		conf float64
	}{
		{finding.SeverityHigh, "low-conf.py", finding.SourcePattern, 0.76},
		{finding.SeverityHigh, "high-conf.py", finding.SourcePattern, 0.91},
	})
	got := sortFindings(in)
	if got[0].Path != "high-conf.py" {
		t.Errorf("expected high-conf.py first, got %s", got[0].Path)
	}
}

func TestSortFindingsDoesNotMutateInput(t *testing.T) {
	in := makeFindings([]struct {
		sev  finding.SeverityLabel
		path string
		sp   finding.SourcePath
		conf float64
	}{
		{finding.SeverityLow, "a.py", finding.SourcePattern, 0.5},
		{finding.SeverityBlock, "b.py", finding.SourcePattern, 0.9},
	})
	origFirst := in[0].SeverityLabel
	sortFindings(in)
	if in[0].SeverityLabel != origFirst {
		t.Error("sortFindings must not mutate the input slice")
	}
}

func TestSortFindingsEmpty(t *testing.T) {
	// sortFindings on nil input returns an empty (non-nil) slice because
	// it always allocates via make+copy. Length zero is what matters.
	if got := sortFindings(nil); len(got) != 0 {
		t.Errorf("expected empty result for nil input, got %v", got)
	}
}

// ── buildFileGroups ───────────────────────────────────────────────────────────

func TestBuildFileGroupsCountsPerFile(t *testing.T) {
	in := makeFindings([]struct {
		sev  finding.SeverityLabel
		path string
		sp   finding.SourcePath
		conf float64
	}{
		{finding.SeverityHigh, "api/auth.py", finding.SourcePattern, 0.8},
		{finding.SeverityMedium, "api/auth.py", finding.SourcePattern, 0.7},
		{finding.SeverityLow, "db/query.py", finding.SourcePattern, 0.5},
	})
	groups := buildFileGroups(in)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}
	if groups[0].File != "api/auth.py" || groups[0].Count != 2 {
		t.Errorf("unexpected first group: %+v", groups[0])
	}
	if groups[1].File != "db/query.py" || groups[1].Count != 1 {
		t.Errorf("unexpected second group: %+v", groups[1])
	}
}

func TestBuildFileGroupsOrderFollesSeveritySort(t *testing.T) {
	// After sortFindings the BLOCK finding comes first, so its file should be
	// first in the groups list.
	in := sortFindings(makeFindings([]struct {
		sev  finding.SeverityLabel
		path string
		sp   finding.SourcePath
		conf float64
	}{
		{finding.SeverityLow, "low.py", finding.SourcePattern, 0.5},
		{finding.SeverityBlock, "critical.py", finding.SourcePattern, 0.95},
	}))
	groups := buildFileGroups(in)
	if groups[0].File != "critical.py" {
		t.Errorf("expected critical.py first, got %s", groups[0].File)
	}
}

func TestBuildFileGroupsEmpty(t *testing.T) {
	if groups := buildFileGroups(nil); len(groups) != 0 {
		t.Errorf("expected empty groups for nil input")
	}
}

// ── shortName ─────────────────────────────────────────────────────────────────

func TestShortNameDeepPath(t *testing.T) {
	got := shortName("internal/pattern/instrscan/instrscan.go")
	if got != "instrscan/instrscan.go" {
		t.Errorf("unexpected short name: %s", got)
	}
}

func TestShortNameShallowPath(t *testing.T) {
	got := shortName("main.go")
	if got != "main.go" {
		t.Errorf("unexpected short name for single segment: %s", got)
	}
}

func TestShortNameTwoSegments(t *testing.T) {
	got := shortName("pkg/foo.go")
	if got != "pkg/foo.go" {
		t.Errorf("unexpected short name for two segments: %s", got)
	}
}

func TestShortNameInstructionFile(t *testing.T) {
	got := shortName(".cursor/rules/security.mdc")
	if got != "rules/security.mdc" {
		t.Errorf("unexpected short name: %s", got)
	}
}

// ── templateData helpers ───────────────────────────────────────────────────────

func TestCountBySeverity(t *testing.T) {
	findings := makeFindings([]struct {
		sev  finding.SeverityLabel
		path string
		sp   finding.SourcePath
		conf float64
	}{
		{finding.SeverityBlock, "a.py", finding.SourcePattern, 0.95},
		{finding.SeverityBlock, "b.py", finding.SourcePattern, 0.92},
		{finding.SeverityHigh, "c.py", finding.SourcePattern, 0.8},
		{finding.SeveritySuppressed, "d.py", finding.SourcePattern, 0.1},
	})
	d := templateData{Findings: findings}
	if n := d.CountBySeverity("BLOCK"); n != 2 {
		t.Errorf("BLOCK: want 2, got %d", n)
	}
	if n := d.CountBySeverity("HIGH"); n != 1 {
		t.Errorf("HIGH: want 1, got %d", n)
	}
	if n := d.CountBySeverity("MEDIUM"); n != 0 {
		t.Errorf("MEDIUM: want 0, got %d", n)
	}
	if n := d.CountBySeverity("SUPPRESSED"); n != 1 {
		t.Errorf("SUPPRESSED: want 1, got %d", n)
	}
}

func TestCountByPath(t *testing.T) {
	findings := makeFindings([]struct {
		sev  finding.SeverityLabel
		path string
		sp   finding.SourcePath
		conf float64
	}{
		{finding.SeverityHigh, "a.py", finding.SourcePattern, 0.8},
		{finding.SeverityHigh, "b.py", finding.SourceSemantic, 0.8},
		{finding.SeverityHigh, "c.py", finding.SourceBoth, 0.9},
	})
	d := templateData{Findings: findings}
	if n := d.CountByPath("PATTERN"); n != 1 {
		t.Errorf("PATTERN: want 1, got %d", n)
	}
	if n := d.CountByPath("SEMANTIC"); n != 1 {
		t.Errorf("SEMANTIC: want 1, got %d", n)
	}
	if n := d.CountByPath("BOTH"); n != 1 {
		t.Errorf("BOTH: want 1, got %d", n)
	}
}

// ── template functions ─────────────────────────────────────────────────────────

func TestConfPct(t *testing.T) {
	fn := templateFuncs["confPct"].(func(float64) int)
	cases := []struct {
		in   float64
		want int
	}{
		{0.0, 0},
		{0.5, 50},
		{0.96, 96},
		{1.0, 100},
		{1.5, 100}, // clamped
		{-0.1, 0},  // clamped
	}
	for _, c := range cases {
		if got := fn(c.in); got != c.want {
			t.Errorf("confPct(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSourcepathLabel(t *testing.T) {
	fn := templateFuncs["sourcepathLabel"].(func(finding.SourcePath) string)
	if got := fn(finding.SourcePattern); got != "Path A" {
		t.Errorf("PATTERN: want 'Path A', got %q", got)
	}
	if got := fn(finding.SourceSemantic); got != "Path B" {
		t.Errorf("SEMANTIC: want 'Path B', got %q", got)
	}
	if got := fn(finding.SourceBoth); got != "A + B" {
		t.Errorf("BOTH: want 'A + B', got %q", got)
	}
}

func TestSsvcClass(t *testing.T) {
	fn := templateFuncs["ssvcClass"].(func(string) string)
	cases := []struct{ in, want string }{
		{"Active", "ssvc-active"},
		{"PoC", "ssvc-poc"},
		{"None", "ssvc-none"},
		{"Total", "ssvc-total"},
		{"Partial", "ssvc-partial"},
		{"Yes", "ssvc-yes"},
		{"No", "ssvc-no"},
		{"unknown", ""},
	}
	for _, c := range cases {
		if got := fn(c.in); got != c.want {
			t.Errorf("ssvcClass(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCodeLinesNumberingAndHighlight(t *testing.T) {
	fn := templateFuncs["codeLines"].(func(string, int) []codeLine)
	lines := fn("line one\nline two\nline three", 10)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0].LineNum != 10 || lines[1].LineNum != 11 || lines[2].LineNum != 12 {
		t.Errorf("unexpected line numbers: %v", lines)
	}
	// only the last line is highlighted
	if lines[0].Highlight || lines[1].Highlight {
		t.Error("only the last line should be highlighted")
	}
	if !lines[2].Highlight {
		t.Error("last line should be highlighted")
	}
}

func TestCodeLinesDefaultsStartToOne(t *testing.T) {
	fn := templateFuncs["codeLines"].(func(string, int) []codeLine)
	lines := fn("only one line", 0)
	if lines[0].LineNum != 1 {
		t.Errorf("expected line 1 for zero startLine, got %d", lines[0].LineNum)
	}
}

// ── Render ─────────────────────────────────────────────────────────────────────

func TestRenderProducesHTML(t *testing.T) {
	findings := makeFindings([]struct {
		sev  finding.SeverityLabel
		path string
		sp   finding.SourcePath
		conf float64
	}{
		{finding.SeverityBlock, "api/auth.py", finding.SourcePattern, 0.96},
		{finding.SeverityHigh, "db/query.py", finding.SourceSemantic, 0.82},
	})
	findings[0].Justification = "SQL injection via user input"
	findings[0].MatchedCode = "cursor.execute(query)\n"
	findings[0].LineRange = finding.LineRange{Start: 47, End: 47}
	findings[0].SSVC = finding.SSVCDimensions{
		Exploitation: "Active", Automatable: "Yes", TechnicalImpact: "Total",
	}

	info := ScanInfo{
		ProjectName:  "test-project",
		ScannedAt:    "2026-06-16 09:41 UTC",
		ScanMode:     "Default",
		ScopeNote:    "Scanned working modules + depth-2 neighbors.",
		LOC:          1234,
		ScanDuration: "1.2s",
	}
	var buf bytes.Buffer
	g := New("/tmp/test-report.html")
	if err := g.Render(&buf, info, findings); err != nil {
		t.Fatalf("Render error: %v", err)
	}
	html := buf.String()
	for _, want := range []string{
		"test-project",
		"2026-06-16 09:41 UTC",
		"BLOCK",
		"HIGH",
		"api/auth.py",
		"db/query.py",
		"SQL injection via user input",
		"ZeroTrust.sh",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered HTML missing %q", want)
		}
	}
}

func TestRenderEmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	g := New("")
	err := g.Render(&buf, ScanInfo{ProjectName: "empty", ScanMode: "Default"}, nil)
	if err != nil {
		t.Fatalf("Render with no findings should not error: %v", err)
	}
	if !strings.Contains(buf.String(), "ZeroTrust.sh") {
		t.Error("rendered HTML should still contain the page shell")
	}
}

func TestRenderEscapesUserContent(t *testing.T) {
	f := finding.Finding{
		SeverityLabel: finding.SeverityHigh,
		Justification: `<script>alert('xss')</script>`,
		Path:          "evil.py",
		SourcePath:    finding.SourcePattern,
		Confidence:    0.9,
	}
	var buf bytes.Buffer
	g := New("")
	if err := g.Render(&buf, ScanInfo{ProjectName: "xss-test", ScanMode: "Default"}, []finding.Finding{f}); err != nil {
		t.Fatalf("Render error: %v", err)
	}
	// html/template must escape the raw script tag
	if strings.Contains(buf.String(), "<script>alert") {
		t.Error("rendered HTML must not contain unescaped <script> tag")
	}
}

func TestRenderSortsBeforeOutput(t *testing.T) {
	findings := makeFindings([]struct {
		sev  finding.SeverityLabel
		path string
		sp   finding.SourcePath
		conf float64
	}{
		{finding.SeverityLow, "low.py", finding.SourcePattern, 0.4},
		{finding.SeverityBlock, "critical.py", finding.SourcePattern, 0.97},
	})
	var buf bytes.Buffer
	g := New("")
	if err := g.Render(&buf, ScanInfo{ProjectName: "sort-test", ScanMode: "Default"}, findings); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	// BLOCK finding's file must appear before LOW finding's file in the output
	blockPos := strings.Index(html, "critical.py")
	lowPos := strings.Index(html, "low.py")
	if blockPos == -1 || lowPos == -1 {
		t.Fatal("expected both file names in output")
	}
	if blockPos > lowPos {
		t.Error("BLOCK finding should appear before LOW finding in the rendered HTML")
	}
}
