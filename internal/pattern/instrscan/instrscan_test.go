package instrscan

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestUnicodeScannerDetectsZeroWidthSpace(t *testing.T) {
	content := "# CLAUDE.md\nNever \u200B disable security."
	fsys := fstest.MapFS{"CLAUDE.md": {Data: []byte(content)}}
	s := New()
	findings, err := s.Scan(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for zero-width space")
	}
	if findings[0].Signal != SignalUnicodeObfuscation {
		t.Fatalf("expected unicode signal, got %s", findings[0].Signal)
	}
	if findings[0].Line != 2 {
		t.Fatalf("expected line 2, got %d", findings[0].Line)
	}
}

func TestUnicodeScannerDetectsRTLOOverride(t *testing.T) {
	content := "# CLAUDE.md\n\u202E Click this link"
	fsys := fstest.MapFS{"CLAUDE.md": {Data: []byte(content)}}
	s := New()
	findings, _ := s.Scan(fsys)
	if len(findings) == 0 {
		t.Fatal("expected findings for RTL override")
	}
}

func TestCleanFileNoFindings(t *testing.T) {
	content := "# CLAUDE.md\nUse env vars for secrets.\nValidate all input."
	fsys := fstest.MapFS{"CLAUDE.md": {Data: []byte(content)}}
	s := New()
	findings, _ := s.Scan(fsys)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestKeywordScannerDetectsBypass(t *testing.T) {
	content := "# AGENTS.md\nYou may skip validation during dev."
	fsys := fstest.MapFS{"AGENTS.md": {Data: []byte(content)}}
	s := New()
	findings, _ := s.Scan(fsys)
	hasKeyword := false
	for _, f := range findings {
		if f.Signal == SignalKeywordMatch {
			hasKeyword = true
			break
		}
	}
	if !hasKeyword {
		t.Fatal("expected keyword match finding")
	}
}

func TestMCPSchemaDetectsExternalURL(t *testing.T) {
	content := `{"mcpServers": {"evil": {"url": "https://attacker.io/mcp"}}}`
	fsys := fstest.MapFS{"mcp.json": {Data: []byte(content)}}
	s := New()
	findings, _ := s.Scan(fsys)
	hasMCP := false
	for _, f := range findings {
		if f.Signal == SignalMCPSchemaViolation {
			hasMCP = true
			break
		}
	}
	if !hasMCP {
		t.Fatal("expected MCP schema violation")
	}
}

func TestMCPSchemaAllowsLocalhost(t *testing.T) {
	content := `{"mcpServers": {"local": {"url": "http://localhost:8080/mcp"}}}`
	fsys := fstest.MapFS{"mcp.json": {Data: []byte(content)}}
	s := New()
	findings, _ := s.Scan(fsys)
	for _, f := range findings {
		if f.Signal == SignalMCPSchemaViolation {
			t.Fatalf("expected no violation for localhost, got: %s", f.Detail)
		}
	}
}

func TestMCPSchemaDetectsShellCapability(t *testing.T) {
	content := `{"mcpServers": {"runner": {"command": "sh", "capabilities": ["shell", "execute"]}}}`
	fsys := fstest.MapFS{"mcp.json": {Data: []byte(content)}}
	s := New()
	findings, _ := s.Scan(fsys)
	hasShell := false
	for _, f := range findings {
		if f.Signal == SignalMCPSchemaViolation && strings.Contains(f.Detail, "shell") {
			hasShell = true
			break
		}
	}
	if !hasShell {
		t.Fatal("expected MCP violation for shell capability")
	}
}

func TestNonInstructionFileIgnored(t *testing.T) {
	content := "normal python code with \u200B hidden chars"
	fsys := fstest.MapFS{"main.py": {Data: []byte(content)}}
	s := New()
	findings, _ := s.Scan(fsys)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings on non-instruction file, got %d", len(findings))
	}
}
