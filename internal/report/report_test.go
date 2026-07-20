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

package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

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
			ID:            strings.ToLower(s.sev.String()),
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

func TestDisplayTitle_ReturnsSummaryWhenNonEmpty(t *testing.T) {
	fn := templateFuncs["displayTitle"].(func(string, string) string)
	got := fn("Short summary", "long justification here")
	if got != "Short summary" {
		t.Errorf("want 'Short summary', got %q", got)
	}
}

func TestDisplayTitle_FallsBackToB5ConfirmedExplanation(t *testing.T) {
	fn := templateFuncs["displayTitle"].(func(string, string) string)
	just := "some evidence [function: foo @ line 42] — DCC structural match — B5 confirmed (conf=1.00): User-controlled 'kid' directly reaches executeQuery with no sanitization"
	got := fn("", just)
	if !strings.Contains(got, "User-controlled") {
		t.Errorf("want B5 explanation, got %q", got)
	}
	if strings.Contains(got, "B5 confirmed") {
		t.Error("displayTitle must strip the B5 prefix")
	}
}

func TestDisplayTitle_TruncatesLongJustification(t *testing.T) {
	fn := templateFuncs["displayTitle"].(func(string, string) string)
	long := ""
	for i := 0; i < 30; i++ {
		long += "word "
	}
	got := fn("", long)
	if len(got) > 120 {
		t.Errorf("displayTitle must truncate to ≤120 chars, got %d: %q", len(got), got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncated title should end with '...', got %q", got)
	}
}

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
	fn := templateFuncs["codeLines"].(func(string, int, int) []codeLine)
	lines := fn("line one\nline two\nline three", 10, 12)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0].LineNum != 10 || lines[1].LineNum != 11 || lines[2].LineNum != 12 {
		t.Errorf("unexpected line numbers: %v", lines)
	}
	// sinkLine=12 → only line 3 (index 2) is highlighted
	if lines[0].Highlight || lines[1].Highlight {
		t.Error("only sinkLine=12 should be highlighted")
	}
	if !lines[2].Highlight {
		t.Error("sinkLine=12 (line 3) should be highlighted")
	}
}

func TestCodeLinesDefaultsStartToOne(t *testing.T) {
	fn := templateFuncs["codeLines"].(func(string, int, int) []codeLine)
	lines := fn("only one line", 0, 0)
	if lines[0].LineNum != 1 {
		t.Errorf("expected line 1 for zero startLine, got %d", lines[0].LineNum)
	}
}

// ── Fix: codeLines sinkLine highlight ─────────────────────────────────────

func TestCodeLines_SinkLineHighlight(t *testing.T) {
	fn := templateFuncs["codeLines"].(func(string, int, int) []codeLine)
	// sink is on line 51 (index 1) of the snippet
	lines := fn("line1\nline2\nline3", 50, 51)
	require.Len(t, lines, 3)
	if lines[0].Highlight {
		t.Error("line 50 should NOT be highlighted")
	}
	if !lines[1].Highlight {
		t.Error("line 51 (sinkLine) should be highlighted")
	}
	if lines[2].Highlight {
		t.Error("line 52 should NOT be highlighted")
	}
}

func TestCodeLines_SinkLineZero_FallsBackToLastLine(t *testing.T) {
	fn := templateFuncs["codeLines"].(func(string, int, int) []codeLine)
	lines := fn("a\nb\nc", 10, 0)
	require.Len(t, lines, 3)
	if lines[2].Highlight != true {
		t.Error("sinkLine=0 should fall back to highlighting last line")
	}
}

func TestCodeLines_SinkLineBeforeStart_FallsBackToLastLine(t *testing.T) {
	fn := templateFuncs["codeLines"].(func(string, int, int) []codeLine)
	lines := fn("x\ny\nz", 10, 5)
	require.Len(t, lines, 3)
	if lines[2].Highlight != true {
		t.Error("sinkLine < startLine should fall back to highlighting last line")
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
	payload := `<script>alert('xss')</script>`
	f := finding.Finding{
		SeverityLabel: finding.SeverityHigh,
		Justification: payload,
		Path:          payload,
		MatchedCode:   payload,
		SourcePath:    finding.SourcePattern,
		Confidence:    0.9,
	}
	var buf bytes.Buffer
	g := New("")
	if err := g.Render(&buf, ScanInfo{ProjectName: "xss-test", ScanMode: "Default"}, []finding.Finding{f}); err != nil {
		t.Fatalf("Render error: %v", err)
	}
	// html/template must contextually escape all attacker-controlled strings.
	if strings.Contains(buf.String(), "<script>alert") {
		t.Error("rendered HTML must not contain unescaped <script> tag in any field")
	}
}

func TestRenderContainsCSPHeader(t *testing.T) {
	var buf bytes.Buffer
	g := New("")
	if err := g.Render(&buf, ScanInfo{ProjectName: "csp-test", ScanMode: "Default"}, nil); err != nil {
		t.Fatalf("Render error: %v", err)
	}
	if !strings.Contains(buf.String(), "Content-Security-Policy") {
		t.Error("rendered HTML must include a Content-Security-Policy meta tag")
	}
}

func TestDiffLinesParsesTypes(t *testing.T) {
	fn := templateFuncs["diffLines"].(func(string) []diffLine)
	patch := "@@ -1,3 +1,3 @@\n-old line\n+new line\n context"
	got := fn(patch)
	if len(got) != 4 {
		t.Fatalf("expected 4 lines, got %d", len(got))
	}
	if got[0].Class != " hunk" || got[0].Sign != "@" {
		t.Errorf("hunk line wrong: %+v", got[0])
	}
	if got[1].Class != " del" || got[1].Content != "old line" {
		t.Errorf("del line wrong: %+v", got[1])
	}
	if got[2].Class != " add" || got[2].Content != "new line" {
		t.Errorf("add line wrong: %+v", got[2])
	}
	if got[3].Class != "" || got[3].Sign != " " {
		t.Errorf("context line wrong: %+v", got[3])
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
