# Data Pipeline & Rules Generation Plan

**Status:** Queued — start after `implementation-plan.md` Layer 4 delivery (Aug 6, 2026)

---

## Overview

Two parallel tracks that feed each other. The pipeline produces a curated corpus of real, labeled, AI-generated vulnerable code. The rules generation engine consumes that corpus to produce defensible, coverage-grounded rules economically.

---

## Track 1 — Data Pipeline (`pipeline/`)

### Phase 1 — Collectors

One script per source, all idempotent and schedulable via cron.

| Collector | Source | What you get | Notes |
|---|---|---|---|
| `collectors/github.py` | GitHub code search API | Real AI-generated PRs/commits | Filter by description mentioning Copilot/Cursor/Claude/Devin; Python, Java, Go, JS/TS only |
| `collectors/bigvul.py` | BigVul dataset | 188K labeled C/C++ vulnerabilities | One-time download; ground-truth bad/ok pairs with CWE labels |
| `collectors/cvefixes.py` | CVEFixes SQLite DB | Real fix commits per CVE | Vulnerable version = bad fixture; patched = ok fixture; CWE label attached |
| `collectors/osv.py` | OSV database | Fix commits for Python/Java/Go packages | Each fix = (bad, ok) pair with CVE/CWE |
| `collectors/nvd_arxiv.py` | NVD CVE feed + arXiv cs.CR | Structured CVE metadata + paper abstracts | Not code — fills the research substrate DuckDB for rule derivation sessions |

### Phase 2 — Normalizer

Converts all sources into a unified schema stored in DuckDB (`pipeline/corpus.db`):

```json
{
  "id": "string",
  "source": "github | bigvul | cvefixes | osv",
  "language": "python | java | go | js | ...",
  "cwe_id": "CWE-798",
  "ai_generated": true,
  "code_snippet": "...",
  "file_context": "surrounding 10 lines",
  "cve_id": "CVE-2024-XXXXX",
  "fix_commit": "sha"
}
```

DuckDB enables direct SQL queries — "give me all Python CWE-798 samples from AI-generated code" is a single query, no web search needed.

### Phase 3 — Labeler

Semi-automated. Runs existing rules against the corpus, marks each sample with `{rule_id, matched: bool}`. Directly produces FP/FN rate per rule with zero manual work. The benchmark notebook reads from this table.

### Phase 4 — Fixture Exporter

Selects high-quality samples from the labeled corpus and promotes them to `tests/fixtures/bad/` and `tests/fixtures/ok/` with provenance metadata:

```python
# source: CVE-2024-12345, BigVul ID: 67890, corpus_id: abc123
```

Fixtures are cited, not invented — makes coverage claims publicly defensible.

### Phase 5 — Benchmark Notebook

`pipeline/notebooks/benchmark.ipynb` reads from DuckDB and outputs:

- Rule coverage heatmap (which CWEs are covered, which aren't)
- FP rate per rule vs. Semgrep on the same corpus
- AI-generated vs. human-written vulnerability distribution
- Fixture provenance table

This notebook is the public evidence artifact. "Our rules achieve X% recall on Y real CVEs at Z% FP rate" with a runnable notebook behind the claim is publishable. Eventually feeds a live-updating page on the GitHub Pages site.

---

## Track 2 — Rule Generation Engine

### Step 1 — MCP Tool Layer over the Corpus

A local MCP server (`pipeline/mcp_server.py`) exposing tools that make a Claude Code rule derivation session cheap:

| Tool | Returns |
|---|---|
| `query_corpus(language, cwe_id, ai_generated)` | Structured samples from DuckDB |
| `get_coverage_gaps()` | CWE IDs with zero or weak rule coverage, ranked |
| `check_semgrep_registry(keyword)` | Whether a pattern is already community-covered |
| `get_nvd_cve(cwe_id, limit)` | Structured CVE records with code context |

With these tools active, a rule derivation session changes from "research from scratch" to "query the substrate, identify the gap, derive the logic." Token spend goes to the logic, not the literature search.

### Step 2 — Rule Specification Template

A structured Markdown spec written by Claude Code before any YAML is produced:

```markdown
## Rule Spec: PY-NEW-JWT-FALLBACK

**Threat**: JWT secret with insecure default via os.getenv fallback
**Evidence**: 23 corpus samples, CVE-2024-XXXXX, Clinejection chain
**Pattern description**: os.getenv($KEY, $DEFAULT) where $DEFAULT matches dev|secret|test...
**Variants**: V1 direct assignment, V2 config class, V3 settings.py
**Exclusions**: $DEFAULT is empty string (no fallback = safe), test files
**FP risk**: Medium — needs metavariable-regex on $DEFAULT, not just pattern presence
**Test fixtures**: corpus IDs [12345, 67890] promoted to bad/, [11111] to ok/
```

Claude Code writes the spec. YAML transcription and fixture wiring is handed to a free agent (OpenCode, etc.). Clean separation: reasoning stays expensive, execution is cheap.

### Step 3 — Batch Rule Generation Sessions

With the MCP tools and spec template in place, a session runs as:

1. `get_coverage_gaps()` → ranked list of uncovered CWEs
2. `query_corpus(cwe=CWE-330)` → real weak-randomness samples
3. Derive spec for PY-NEW-WEAK-RANDOM
4. Hand spec to free agent → receive YAML + fixtures
5. Run `scripts/rules/test_rules.sh` → verify green
6. Labeler re-runs → coverage improvement reflected in DuckDB

Target throughput: 5–10 well-specified, corpus-grounded rules per session.

---

## Sequencing

Pipeline before rules — the pipeline is what makes rules defensible.

| Week | Work |
|---|---|
| 1 | BigVul + OSV collectors → DuckDB schema → labeler (one-time, straightforward) |
| 2 | MCP server over DuckDB → test in a rule derivation session |
| 3 | GitHub collector (harder — rate limits, noise filtering) |
| 4 | Benchmark notebook → first public coverage report |
| Ongoing | Rule batch sessions using MCP tools + free agent transcription |

---

## Priority Gap Rules to Write First

From the rules audit, these are uncovered by current rules and not reliably covered by Semgrep on AI-generated code:

| Rule ID | Pattern | CWE | Evidence |
|---|---|---|---|
| PY-NEW-JWT-FALLBACK | `os.getenv($KEY, "dev-secret")` | CWE-321 | Universal in AI-generated FastAPI/Django/Flask |
| PY-NEW-TLS-DISABLED | `requests.get(url, verify=False)` | CWE-295 | No legitimate production use |
| PY-NEW-WILDCARD-CORS | `allow_origins=["*"], allow_credentials=True` | CWE-942 | Dangerous combination, common in AI scaffolding |
| PY-NEW-LOG-INJECTION | `logger.info(f"...{user_input}...")` | CWE-117 | 88% rate in CSA data |
| PY-NEW-WEAK-RANDOM | `random.*()` → token/secret variable | CWE-330 | Highest CWE frequency in ACM corpus |
| AG-NEW-MCP-INJECTION | `tools[].description` fields in `*.mcp.json` | CWE-77 | CVE-2025-54135 attack vector |

---

## Connection to Existing Plans

- **A-18 Resolution** (`implementation-plan.md` Bonus section): CVEFixes collector (Phase 1 above) is the same data source needed for QLoRA fine-tuning. Run the collector once, it serves both the fixture pipeline and the fine-tuning pipeline.
- **Benchmark notebook**: directly feeds `docs/benchmarks/` outputs referenced throughout `implementation-plan.md` (tier1_elimination, a18_gap, token_footprint, final_eval).
- **MCP server**: can be extended to expose the Joern CPG query interface for use in rule derivation sessions, giving rule authors access to real taint paths without running a full scan.
