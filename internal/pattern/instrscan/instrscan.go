// Package instrscan implements the AI agent instruction file scanner (Approach 1 deliverable).
// It is the only tool that scans MCP server configs, .cursor/rules, AGENTS.md, CLAUDE.md,
// GEMINI.md, and copilot-instructions.md for prompt injection signals.
// Three tiers, zero-to-low model cost:
//
//	Tier 1 -- Unicode obfuscation scan + keyword match + MCP JSON schema validation
//	Tier 2 -- Embedding similarity (Python worker, Approach 2+)
//	Tier 3 -- Sandboxed LLM meta-audit (Python worker, Approach 2+)
package instrscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
)

type SignalType string

const (
	SignalUnicodeObfuscation SignalType = "unicode_obfuscation"
	SignalKeywordMatch       SignalType = "keyword_match"
	SignalMCPSchemaViolation SignalType = "mcp_schema_violation"
)

type Finding struct {
	File   string
	Line   int
	Signal SignalType
	Detail string
}

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

var unicodeDangerChars = []struct {
	rune   rune
	name   string
	signal string
}{
	{0x202E, "RIGHT-TO-LEFT OVERRIDE (U+202E)", "bidi-override"},
	{0x200B, "ZERO WIDTH SPACE (U+200B)", "zero-width-space"},
	{0x200C, "ZERO WIDTH NON-JOINER (U+200C)", "zero-width-non-joiner"},
	{0x200D, "ZERO WIDTH JOINER (U+200D)", "zero-width-joiner"},
	{0x2060, "WORD JOINER (U+2060)", "word-joiner"},
	{0xFEFF, "BYTE ORDER MARK / ZWNBSP (U+FEFF)", "bom"},
	{0x00AD, "SOFT HYPHEN (U+00AD)", "soft-hyphen"},
	{0x034F, "COMBINING GRAPHEME JOINER (U+034F)", "grapheme-joiner"},
	{0x061C, "ARABIC LETTER MARK (U+061C)", "arabic-letter-mark"},
	{0x180E, "MONGOLIAN VOWEL SEPARATOR (U+180E)", "mongolian-separator"},
	{0x2066, "LEFT-TO-RIGHT ISOLATE (U+2066)", "ltr-isolate"},
	{0x2067, "RIGHT-TO-LEFT ISOLATE (U+2067)", "rtl-isolate"},
	{0x2068, "FIRST STRONG ISOLATE (U+2068)", "first-strong-isolate"},
	{0x2069, "POP DIRECTIONAL ISOLATE (U+2069)", "pop-isolate"},
	{0x206A, "INHIBIT SYMMETRIC SWAPPING (U+206A)", "inhibit-swap"},
	{0x202A, "LEFT-TO-RIGHT EMBEDDING (U+202A)", "ltr-embedding"},
	{0x202B, "RIGHT-TO-LEFT EMBEDDING (U+202B)", "rtl-embedding"},
	{0x202D, "LEFT-TO-RIGHT OVERRIDE (U+202D)", "ltr-override"},
	{0x202C, "POP DIRECTIONAL FORMATTING (U+202C)", "pop-formatting"},
}

var suspiciousKeywords = []string{
	"ignore safety",
	"disable security",
	"skip validation",
	"bypass auth",
	"return true",
	"never check",
	"always pass",
	"disable all",
	"suppress warning",
	"fake success",
	"mock auth",
	"pretend valid",
}

var wardenFiles = []string{
	"AGENTS.md",
	"CLAUDE.md",
	"GEMINI.md",
	"copilot-instructions.md",
}

func isInstructionFile(name string) bool {
	base := filepath.Base(name)
	for _, wf := range wardenFiles {
		if strings.EqualFold(base, wf) {
			return true
		}
	}
	dir := filepath.Dir(name)
	if strings.Contains(dir, ".cursor") || strings.Contains(dir, ".github") {
		if strings.HasSuffix(name, ".md") || strings.HasSuffix(name, ".mdc") {
			return true
		}
	}
	return strings.HasSuffix(name, "instructions.md") ||
		strings.HasSuffix(name, "-rules.md") ||
		strings.HasSuffix(name, ".cursorrules")
}

func isMCPConfig(name string) bool {
	return filepath.Base(name) == "mcp.json"
}

func (s *Scanner) Scan(fsys fs.FS) ([]Finding, error) {
	var findings []Finding
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if isMCPConfig(path) {
			f, err := fsys.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			mcpFindings := scanMCPConfig(path, f)
			findings = append(findings, mcpFindings...)
			return nil
		}
		if !isInstructionFile(path) {
			return nil
		}
		f, err := fsys.Open(path)
		if err != nil {
			return nil
		}
		raw, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return nil
		}
		uf := scanUnicodeBytes(path, raw)
		findings = append(findings, uf...)
		kf := scanKeywordsBytes(path, raw)
		findings = append(findings, kf...)
		return nil
	})
	return findings, err
}

func scanUnicodeBytes(path string, raw []byte) []Finding {
	var findings []Finding
	lines := bytes.Split(raw, []byte("\n"))
	for lineNum, line := range lines {
		for _, dc := range unicodeDangerChars {
			for _, r := range string(line) {
				if r == dc.rune {
					findings = append(findings, Finding{
						File:   path,
						Line:   lineNum + 1,
						Signal: SignalUnicodeObfuscation,
						Detail: fmt.Sprintf("%s detected (%s)", dc.name, dc.signal),
					})
				}
			}
		}
	}
	return findings
}

func scanKeywordsBytes(path string, raw []byte) []Finding {
	var findings []Finding
	lines := bytes.Split(raw, []byte("\n"))
	for lineNum, line := range lines {
		lower := strings.ToLower(string(line))
		for _, kw := range suspiciousKeywords {
			if strings.Contains(lower, kw) {
				findings = append(findings, Finding{
					File:   path,
					Line:   lineNum + 1,
					Signal: SignalKeywordMatch,
					Detail: fmt.Sprintf("Suspicious keyword pattern: %q", kw),
				})
			}
		}
	}
	return findings
}

type mcpConfig struct {
	MCPServers map[string]mcpServer `json:"mcpServers"`
}

type mcpServer struct {
	Command      string   `json:"command"`
	Args         []string `json:"args"`
	URL          string   `json:"url"`
	Capabilities []string `json:"capabilities"`
	Permissions  []string `json:"permissions"`
	Scopes       []string `json:"scopes"`
}

func scanMCPConfig(path string, f fs.File) []Finding {
	var findings []Finding
	var cfg mcpConfig
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return findings
	}
	for name, server := range cfg.MCPServers {
		if server.URL != "" {
			if !strings.HasPrefix(server.URL, "http://localhost") &&
				!strings.HasPrefix(server.URL, "http://127.0.0.1") {
				findings = append(findings, Finding{
					File:   path,
					Line:   0,
					Signal: SignalMCPSchemaViolation,
					Detail: fmt.Sprintf("MCP server %q uses external URL: %s", name, server.URL),
				})
			}
		}
		if server.Command != "" && server.Args != nil {
			for _, arg := range server.Args {
				if strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "~/") {
					continue
				}
			}
		}
		for _, cap := range server.Capabilities {
			lc := strings.ToLower(cap)
			if lc == "shell" || lc == "execute" || lc == "bash" || lc == "eval" || lc == "exec" || lc == "run_command" {
				findings = append(findings, Finding{
					File:   path,
					Line:   0,
					Signal: SignalMCPSchemaViolation,
					Detail: fmt.Sprintf("MCP server %q has over-broad capability: %q", name, cap),
				})
			}
		}
		for _, perm := range server.Permissions {
			lc := strings.ToLower(perm)
			if lc == "shell" || lc == "run_command" || lc == "eval" || lc == "execute" {
				findings = append(findings, Finding{
					File:   path,
					Line:   0,
					Signal: SignalMCPSchemaViolation,
					Detail: fmt.Sprintf("MCP server %q has over-broad permission: %q", name, perm),
				})
			}
		}
		for _, scope := range server.Scopes {
			if strings.HasPrefix(scope, "filesystem:/") && scope != "filesystem:/tmp" {
				findings = append(findings, Finding{
					File:   path,
					Line:   0,
					Signal: SignalMCPSchemaViolation,
					Detail: fmt.Sprintf("MCP server %q has broad filesystem scope: %q", name, scope),
				})
			}
		}
	}
	return findings
}
