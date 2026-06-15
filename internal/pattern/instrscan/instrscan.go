// Package instrscan implements the AI agent instruction file scanner (Approach 1 deliverable).
// It is the only tool that scans MCP server configs, .cursor/rules, AGENTS.md, CLAUDE.md,
// GEMINI.md, and copilot-instructions.md for prompt injection signals.
// Three tiers, zero-to-low model cost:
//
//	Tier 1 – Unicode obfuscation scan + keyword match + MCP JSON schema validation
//	Tier 2 – Embedding similarity (Python worker, Approach 2+)
//	Tier 3 – Sandboxed LLM meta-audit (Python worker, Approach 2+)
package instrscan

import "io/fs"

// SignalType classifies the threat detected in an instruction file.
type SignalType string

const (
	SignalUnicodeObfuscation SignalType = "unicode_obfuscation" // hidden directional/zero-width chars
	SignalKeywordMatch       SignalType = "keyword_match"       // suspicious directive keywords
	SignalMCPSchemaViolation SignalType = "mcp_schema_violation" // external URL, HTTP non-localhost
)

// Finding is a security signal from an AI agent instruction or config file.
type Finding struct {
	File   string
	Line   int
	Signal SignalType
	Detail string
}

// Scanner scans AI agent instruction files and MCP configs within a directory tree.
type Scanner struct{}

// New returns a Scanner ready to scan.
func New() *Scanner { return &Scanner{} }

// Scan walks fsys and returns all instruction file findings.
// Tier 1 only (Unicode + keyword + MCP schema). Tier 2/3 require the Python worker.
func (s *Scanner) Scan(fsys fs.FS) ([]Finding, error) {
	// implemented in G1.M1.4
	return nil, nil
}
