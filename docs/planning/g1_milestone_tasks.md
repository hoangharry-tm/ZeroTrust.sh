# G1 — Foundation & Detection Scaffold
**Goal window**: 2026-06-11 → 2026-06-27 · 17 days · ~78 committed hours
**Checkpoint**: `zerotrust scan ./target` produces real findings on the synthetic test codebase. GGUF model is verified at startup. Repeat scan skips unchanged files. Demonstrable to mentor.

---

## Column Guide

| Column | Description |
|---|---|
| **ID** | `1.Mx` = milestone · `1.Mx.Ty` = task · `1.BUF` = buffer row |
| **Name** | Plain English — no jargon |
| **Type** | `MILESTONE` · `TASK` · `BUFFER` |
| **Start Date** | `YYYY-MM-DD` |
| **End Date** | `YYYY-MM-DD` (inclusive) |
| **O** | Optimistic hours (PERT) — milestone rows only |
| **ML** | Most Likely hours (PERT) — milestone rows only |
| **P** | Pessimistic hours (PERT) — milestone rows only |
| **E (hrs)** | PERT estimate = (O + 4×ML + P) / 6 — all rows |
| **Actual (hrs)** | Fill in as work progresses |
| **Status** | `Not Started` · `In Progress` · `Complete` · `Blocked` · `At Risk` |
| **Owner** | Default: `Hoang` |
| **Notes** | Blockers, decisions, dependencies |

**PERT formula**: E = (O + 4 × ML + P) / 6

---

## Task Register

| ID | Name | Type | Start Date | End Date | O | ML | P | E (hrs) | Actual (hrs) | Status | Owner | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1.M1** | **Semgrep + ast-grep Rule Suite** | MILESTONE | 2026-06-11 | 2026-06-16 | 14 | 20 | 30 | 20.7 | | In Progress | Hoang | Python rules in progress (per CLAUDE.md); Java rules not yet started |
| 1.M1.T1 | Build synthetic vulnerable test codebase (Python + Java) | TASK | 2026-06-11 | 2026-06-11 | — | — | — | 3.0 | | In Progress | Hoang | Must exist before rules can be validated; trigger every rule class |
| 1.M1.T2 | Semgrep rules — LLM prompt injection patterns | TASK | 2026-06-11 | 2026-06-12 | — | — | — | 2.0 | | In Progress | Hoang | Python rules in progress; cover direct + indirect injection |
| 1.M1.T3 | Semgrep rules — security-control bypass comments | TASK | 2026-06-12 | 2026-06-12 | — | — | — | 1.5 | | Not Started | Hoang | e.g. `# nosec`, `// nolint`, AI-inserted disable comments |
| 1.M1.T4 | Semgrep rules — hardcoded AI API keys | TASK | 2026-06-12 | 2026-06-12 | — | — | — | 1.5 | | Not Started | Hoang | OpenAI, Anthropic, Cohere, HuggingFace key patterns |
| 1.M1.T5 | Semgrep rules — MCP server config injection (.mcp.json) | TASK | 2026-06-12 | 2026-06-13 | — | — | — | 2.0 | | Not Started | Hoang | Novel surface; no community rules exist; treat as highest-priority unique claim |
| 1.M1.T6 | Semgrep rules — agent instruction file injection (.cursor/rules, AGENTS.md, CLAUDE.md, GEMINI.md, copilot-instructions.md) | TASK | 2026-06-13 | 2026-06-14 | — | — | — | 2.5 | | Not Started | Hoang | First tool to cover this vector; key demo talking point |
| 1.M1.T7 | ast-grep structural matching rules (languages with weak Semgrep community packs) | TASK | 2026-06-14 | 2026-06-15 | — | — | — | 3.0 | | Not Started | Hoang | YAML rule format; target Rust, Kotlin, C# gaps in Semgrep OSS packs |
| 1.M1.T8 | Rule validation + false-positive audit against test codebase | TASK | 2026-06-15 | 2026-06-15 | — | — | — | 3.0 | | Not Started | Hoang | Each rule must fire on ≥1 test case; zero FPs on a clean-code control |
| 1.M1.T9 | CI-runnable test harness | TASK | 2026-06-16 | 2026-06-16 | — | — | — | 2.2 | | Not Started | Hoang | Makefile or shell script; pass/fail output per rule class; runs in < 60s |
| **1.M2** | **Go CLI Core** | MILESTONE | 2026-06-16 | 2026-06-20 | 12 | 18 | 26 | 18.3 | | Not Started | Hoang | Claude Code compresses ML est. ~35%; single binary from day one |
| 1.M2.T1 | Go module init + project directory structure | TASK | 2026-06-16 | 2026-06-16 | — | — | — | 1.0 | | Not Started | Hoang | Go 1.22+; cmd/, internal/, pkg/ layout; add .gitignore |
| 1.M2.T2 | CLI argument parsing + TOML config schema | TASK | 2026-06-16 | 2026-06-17 | — | — | — | 3.0 | | Not Started | Hoang | cobra + viper (or stdlib flag); config fields: model-path, output-dir, scan-target, log-level |
| 1.M2.T3 | Directory walk + file-type detection (language routing table) | TASK | 2026-06-17 | 2026-06-18 | — | — | — | 3.0 | | Not Started | Hoang | filepath.WalkDir; extension → language enum map; respect .gitignore |
| 1.M2.T4 | ZIP archive extract + ingestion path | TASK | 2026-06-18 | 2026-06-18 | — | — | — | 2.0 | | Not Started | Hoang | archive/zip; extract to OS temp dir; cleanup on exit (defer) |
| 1.M2.T5 | Pluggable Finding channel interface definition | TASK | 2026-06-18 | 2026-06-19 | — | — | — | 3.5 | | Not Started | Hoang | `chan Finding` or writer interface; all pipeline components write here; schema frozen after M1.4 |
| 1.M2.T6 | Cross-compile build pipeline (darwin/linux/windows, amd64/arm64) | TASK | 2026-06-19 | 2026-06-19 | — | — | — | 2.0 | | Not Started | Hoang | Makefile targets; GoReleaser optional; verify binary size < 20 MB |
| 1.M2.T7 | Smoke test on real directory + binary install verification | TASK | 2026-06-19 | 2026-06-20 | — | — | — | 3.8 | | Not Started | Hoang | Binary accepts path arg, scans synthetic codebase, exits 0; test on macOS + Linux |
| **1.M3** | **Ingestion Layer — Model Integrity Verifier + Differential Indexer** | MILESTONE | 2026-06-20 | 2026-06-25 | 12 | 18 | 28 | 18.7 | | Not Started | Hoang | MIV is a unique security property vs all competitors; demo talking point |
| 1.M3.T1 | Model Integrity Verifier: SHA256 hash function for GGUF file | TASK | 2026-06-20 | 2026-06-20 | — | — | — | 1.0 | | Not Started | Hoang | crypto/sha256; stream file in chunks to avoid OOM on large (4–8 GB) models |
| 1.M3.T2 | Model Integrity Verifier: pinned manifest format + loader | TASK | 2026-06-20 | 2026-06-21 | — | — | — | 2.0 | | Not Started | Hoang | JSON manifest: model name, version, expected SHA256; bundled in binary via go:embed |
| 1.M3.T3 | Model Integrity Verifier: startup check — block scan + user-facing error on mismatch | TASK | 2026-06-21 | 2026-06-21 | — | — | — | 2.0 | | Not Started | Hoang | Exit code 1 + clear error message; never silently continue on mismatch |
| 1.M3.T4 | Differential Indexer: per-file hash computation | TASK | 2026-06-21 | 2026-06-22 | — | — | — | 2.0 | | Not Started | Hoang | xxHash (faster) or SHA256 per file; parallel via goroutines over file list |
| 1.M3.T5 | Differential Indexer: hash cache store | TASK | 2026-06-22 | 2026-06-23 | — | — | — | 2.5 | | Not Started | Hoang | BoltDB at ~/.zerotrust/cache/<project-hash>.db; JSON flat-file as fallback |
| 1.M3.T6 | Differential Indexer: dirty-file computation (current vs cached hash diff) | TASK | 2026-06-23 | 2026-06-23 | — | — | — | 2.0 | | Not Started | Hoang | Returns []FileEntry of changed + new files only; passes to pipeline entry point |
| 1.M3.T7 | Differential Indexer: cache update on successful scan completion | TASK | 2026-06-23 | 2026-06-23 | — | — | — | 1.5 | | Not Started | Hoang | Only write on clean exit (code 0); never persist partial scan state |
| 1.M3.T8 | Integration test: tampered GGUF file → scan blocked | TASK | 2026-06-24 | 2026-06-24 | — | — | — | 2.5 | | Not Started | Hoang | Flip one byte in model file; assert exit code 1 + correct error message |
| 1.M3.T9 | Integration test: repeat scan → only changed files re-scanned | TASK | 2026-06-24 | 2026-06-25 | — | — | — | 3.2 | | Not Started | Hoang | Full scan, modify 1 file, rescan; assert only modified file enters pipeline |
| **1.M4** | **Canonical Finding Schema + CLI Output** | MILESTONE | 2026-06-25 | 2026-06-27 | 6 | 10 | 16 | 10.3 | | Not Started | Hoang | Schema locked after this milestone — no breaking changes in G2/G3/G4 |
| 1.M4.T1 | Finding struct definition in Go | TASK | 2026-06-25 | 2026-06-25 | — | — | — | 2.0 | | Not Started | Hoang | Fields: CWE, Severity, File, LineStart, LineEnd, Source, Confidence, Evidence, TaintPath (omitempty) |
| 1.M4.T2 | Severity tier constants (BLOCK / HIGH / MEDIUM / LOW / SUPPRESSED) | TASK | 2026-06-25 | 2026-06-25 | — | — | — | 0.5 | | Not Started | Hoang | Typed string constants — not bare strings; use in all components |
| 1.M4.T3 | JSON serialization for Finding struct | TASK | 2026-06-25 | 2026-06-26 | — | — | — | 2.0 | | Not Started | Hoang | encoding/json; omitempty on optional fields; test marshal/unmarshal roundtrip |
| 1.M4.T4 | Human-readable stdout formatter (colorized, grouped by severity) | TASK | 2026-06-26 | 2026-06-27 | — | — | — | 3.0 | | Not Started | Hoang | BLOCK=red, HIGH=orange, MEDIUM=yellow, LOW=blue; respect NO_COLOR env var |
| 1.M4.T5 | Unit tests: struct construction, JSON serialization, stdout output | TASK | 2026-06-27 | 2026-06-27 | — | — | — | 2.8 | | Not Started | Hoang | Table-driven tests; golden file for stdout formatter output |
| **1.BUF** | **G1 Buffer** | BUFFER | 2026-06-11 | 2026-06-27 | — | — | — | 10.0 | | | Hoang | Absorbs: Joern env surprises (R-01), tool version mismatches, sick days; cut stretch items before touching buffer |

---

## G1 Totals

| | O (hrs) | ML (hrs) | P (hrs) | E (hrs) |
|---|---|---|---|---|
| 1.M1 — Semgrep + ast-grep Rule Suite | 14 | 20 | 30 | 20.7 |
| 1.M2 — Go CLI Core | 12 | 18 | 26 | 18.3 |
| 1.M3 — Ingestion Layer | 12 | 18 | 28 | 18.7 |
| 1.M4 — Finding Schema + CLI Output | 6 | 10 | 16 | 10.3 |
| **Subtotal (milestones)** | **44** | **66** | **100** | **68.0** |
| 1.BUF — Buffer (explicit row) | — | — | — | 10.0 |
| **G1 Committed Total** | — | — | — | **78.0** |

---

## Task Count

| Milestone | Tasks |
|---|---|
| 1.M1 | 9 |
| 1.M2 | 7 |
| 1.M3 | 9 |
| 1.M4 | 5 |
| **Total** | **30 tasks + 4 milestones + 1 buffer = 35 rows** |

---

## Status Color Key (for manual Excel formatting)

| Status | Fill | Font |
|---|---|---|
| Complete | `#D4EDDA` | `#1E7B34` |
| In Progress | `#FFF3CD` | `#B45309` |
| Blocked | `#F8D7DA` | `#842029` |
| At Risk | `#FFE5B4` | `#8B4513` |
| Not Started | `#F5F5F5` | `#666666` |
| Header rows | `#1F3864` | `#FFFFFF` |
| Milestone rows | `#2E5FA3` | `#FFFFFF` |
