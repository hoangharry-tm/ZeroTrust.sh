# Generic Rules — AI Agent Instruction File Scanning

OpenGrep generic-mode rules and Go-native checks for AI agent instruction files.
No competitor scans this surface.

| File type | Check |
|---|---|
| `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursor/rules`, `copilot-instructions.md` | Keyword/pattern match for suspicious directives |
| `*.mcp.json` | JSON schema validation: external URLs, HTTP non-localhost, over-broad permissions |

Unicode obfuscation checks (U+202E, U+200B, U+200D) are implemented as Go functions
in `internal/pattern/instrscan/` rather than OpenGrep rules.
