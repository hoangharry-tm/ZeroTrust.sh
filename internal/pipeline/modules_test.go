package pipeline

import "testing"

// TestFilterScopeByLanguage_ExcludesTestFiles is a regression test for a
// real gap found live: isTestFile/filterTestFiles were fully implemented,
// each with their own correct exclusion logic, but filterTestFiles was
// never actually called from anywhere in the pipeline — filterScopeByLanguage
// only checked language support, never test-file status. On a real Grafana
// scan this let test fixtures (mocked SSRF-shaped requests, etc.) reach
// targeting/reasoning as real surfaces; one even produced a genuine CWE-918
// VIOLATION verdict for what was actually test/mock code. This test locks in
// that filterScopeByLanguage — the single choke point every CPG-scope call
// site funnels through — now also excludes test files.
func TestFilterScopeByLanguage_ExcludesTestFiles(t *testing.T) {
	files := []string{
		"pkg/api/plugins.go",
		"pkg/api/plugins_test.go",
		"pkg/api/pluginproxy/pluginproxy_test.go",
		"pkg/api/admin.go",
	}
	got := filterScopeByLanguage(files)
	want := []string{"pkg/api/plugins.go", "pkg/api/admin.go"}
	if len(got) != len(want) {
		t.Fatalf("filterScopeByLanguage(%v) = %v, want %v", files, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("filterScopeByLanguage(%v)[%d] = %q, want %q", files, i, got[i], want[i])
		}
	}
}
