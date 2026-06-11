# Sheet 3 — Approach 2: Hybrid AST + Local LLM Scanner

**Sheet name:** `Approach 2 - Hybrid LLM`
**Goal ID:** 2
**Goal name:** Approach 2 — Hybrid AST + Local LLM Scanner
**Description:** Build a Go-based production scanner introducing the full two-path architecture: Path A (Semgrep + LLM Verifier) and Path B (three-tier cost funnel: Heuristic Targeting → UniXcoder Classifier → Token Budget + LLM Semantic Scan), with a Differential Indexer for 80-95% repeat-scan cost reduction.
**Date range:** 2026-06-23 → 2026-07-28
**Total milestones:** 10
**Total tasks:** 51
**Constraint:** Go learning curve applies — ML estimates for M1–M3 increased by 20%.

---

## Sheet Header Rows

| Row | Content | Style |
|---|---|---|
| 1 | `ZeroTrust.sh  ·  Approach 2 — Hybrid AST + Local LLM Scanner` | 20pt bold white on `#1F3864`, height 50px |
| 2 | `Intern: Ton Minh Hoang  ·  VNG ZingPlay Studio  ·  Goal: Go engine + Two-Path detection  ·  Deadline: 2026-07-28` | 11pt italic white on `#2E5FA3`, height 22px |
| 3 | *(spacer)* | height 6px |
| 4 | Column headers | 20pt bold white on `#2E5FA3`, height 50px |

---

## Data Entries

### Milestone 2.M1 — Core Engine Setup

| Field | Value |
|---|---|
| ID | `2.M1` |
| Name | Core Engine Setup |
| Type | MILESTONE |
| Start | 2026-06-23 |
| End | 2026-06-26 |
| PERT O | 8.0 |
| PERT ML | 21.6 |
| PERT P | 32.0 |
| PERT E | 21.1 |
| Status | Not Started |
| Notes | Go learning curve applied (+20% ML). Initialize Go module, wire Cobra CLI, implement directory walker and ZIP ingestion, define core domain types. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 2.M1.T1 | Initialize Go module, directory layout, and .gitignore | 0.5 | 1.2 | 2.0 | 1.22 | Not Started |
| 2.M1.T2 | Wire Cobra CLI framework: root command, --input flag, --output flag, --verbose flag | 1.0 | 3.6 | 6.0 | 3.43 | Not Started |
| 2.M1.T3 | Implement directory walker: recursively enumerate files, respect .gitignore patterns, return file metadata structs | 1.0 | 3.6 | 6.0 | 3.43 | Not Started |
| 2.M1.T4 | Implement ZIP ingestion: detect ZIP input, extract to temp directory, reuse directory walker | 1.0 | 3.6 | 6.0 | 3.43 | Not Started |
| 2.M1.T5 | Define core domain types: FileRecord, Finding, Severity, ConfidenceTier, ScanConfig structs | 1.0 | 3.6 | 6.0 | 3.43 | Not Started |
| 2.M1.T6 | Write unit tests for directory walker and ZIP ingestion; add Makefile targets: build, test, lint | 1.5 | 4.8 | 8.0 | 4.72 | Not Started |

---

### Milestone 2.M2 — Differential Indexer

| Field | Value |
|---|---|
| ID | `2.M2` |
| Name | Differential Indexer |
| Type | MILESTONE |
| Start | 2026-06-29 |
| End | 2026-06-30 |
| PERT O | 4.0 |
| PERT ML | 12.0 |
| PERT P | 18.0 |
| PERT E | 11.7 |
| Status | Not Started |
| Notes | Hash-compares input vs previous scan cache. Only changed/new files enter the pipeline. ~80-95% cost reduction on repeat scans. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 2.M2.T1 | Design and implement scan cache schema: SHA-256 per file, last-scanned timestamp, stored as JSON on disk | 1.0 | 3.0 | 5.0 | 2.83 | Not Started |
| 2.M2.T2 | Implement hash-compare logic: load previous cache, diff against current file tree, return new/changed/deleted sets | 1.0 | 3.0 | 5.0 | 2.83 | Not Started |
| 2.M2.T3 | Integrate differential indexer into CLI pipeline: skip unchanged files, persist updated cache after scan | 0.5 | 2.4 | 4.0 | 2.32 | Not Started |
| 2.M2.T4 | Write unit tests for hash-compare logic covering new, changed, deleted, and no-change scenarios | 0.5 | 1.8 | 3.0 | 1.80 | Not Started |

---

### Milestone 2.M3 — Path A: Semgrep + LLM Verifier

| Field | Value |
|---|---|
| ID | `2.M3` |
| Name | Path A — Semgrep + LLM Verifier |
| Type | MILESTONE |
| Start | 2026-07-01 |
| End | 2026-07-04 |
| PERT O | 10.0 |
| PERT ML | 24.0 |
| PERT P | 36.0 |
| PERT E | 23.7 |
| Status | Not Started |
| Notes | Go learning curve applied (+20% ML). LLM Verifier only sees structured findings — not raw code. Targets 88-93% FP reduction. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 2.M3.T1 | Install Semgrep binary as subprocess dependency; implement SemgrepRunner: invoke semgrep --json, parse output into []Finding | 1.0 | 3.6 | 6.0 | 3.43 | Not Started |
| 2.M3.T2 | Author 5+ custom Semgrep YAML rules for AI-specific threats: hallucinated package imports, security control bypasses, prompt injection in comments | 2.0 | 6.0 | 10.0 | 6.00 | Not Started |
| 2.M3.T3 | Integrate community Semgrep rulesets (p/owasp-top-ten, p/secrets) into the scan config | 0.5 | 1.8 | 3.0 | 1.80 | Not Started |
| 2.M3.T4 | Implement LLM Verifier: serialize each Finding into structured prompt (taint flow path + sink type + reachability condition); send to local Ollama; parse true/false/uncertain response | 3.0 | 7.2 | 12.0 | 7.20 | Not Started |
| 2.M3.T5 | Wire LLM Verifier into Path A output: filter findings flagged false by LLM, retain true/uncertain; log suppression count | 0.5 | 1.8 | 3.0 | 1.80 | Not Started |
| 2.M3.T6 | Write integration tests for Path A end-to-end using a synthetic vulnerable Go/Java file; assert findings contain expected CWEs | 1.0 | 3.6 | 6.0 | 3.43 | Not Started |

---

### Milestone 2.M4 — Path B Tier 1: Heuristic Targeting + Call Graph

| Field | Value |
|---|---|
| ID | `2.M4` |
| Name | Path B Tier 1 — Heuristic Targeting + Call Graph |
| Type | MILESTONE |
| Start | 2026-07-07 |
| End | 2026-07-09 |
| PERT O | 8.0 |
| PERT ML | 18.0 |
| PERT P | 30.0 |
| PERT E | 18.3 |
| Status | Not Started |
| Notes | Endpoints, auth functions, AI-modified regions — ~95% of files eliminated at zero LLM cost. CVE exact match → auto-flag, skip all further analysis. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 2.M4.T1 | Implement heuristic surface selector: regex + AST heuristics to tag endpoint handlers, auth functions, and AI-modified regions (// AI-generated comments, recent git-blame dates) | 2.0 | 4.8 | 8.0 | 4.80 | Not Started |
| 2.M4.T2 | Implement dependency extractor: parse import statements and package.json / go.mod / pom.xml / requirements.txt into a flat dependency list | 1.0 | 2.4 | 4.0 | 2.40 | Not Started |
| 2.M4.T3 | Implement NVD CVE cache: fetch NVD JSON feed weekly, store locally as SQLite, expose query-by-package-name API | 2.0 | 4.8 | 8.0 | 4.80 | Not Started |
| 2.M4.T4 | Wire CVE cross-reference: for each dependency in extracted list, query local CVE cache; auto-flag exact matches as BLOCK-tier findings before LLM | 1.0 | 2.4 | 4.0 | 2.40 | Not Started |
| 2.M4.T5 | Write unit tests for surface selector (verify endpoint/auth/AI-region tagging on synthetic files) and CVE lookup (mock SQLite fixture) | 1.0 | 2.4 | 4.0 | 2.40 | Not Started |

---

### Milestone 2.M5 — Path B Tier 2: UniXcoder Classifier Gate

| Field | Value |
|---|---|
| ID | `2.M5` |
| Name | Path B Tier 2 — UniXcoder Classifier Gate |
| Type | MILESTONE |
| Start | 2026-07-10 |
| End | 2026-07-13 |
| PERT O | 6.0 |
| PERT ML | 16.0 |
| PERT P | 28.0 |
| PERT E | 16.3 |
| Status | Not Started |
| Notes | UniXcoder-Base-Nine, ~125M params, F1=94.73% on BigVul. Runs locally on CPU, milliseconds per function, zero API cost. Only ~15-25% of surfaces escalate to Tier 3. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 2.M5.T1 | Download and validate UniXcoder-Base-Nine ONNX export; write Python inference wrapper callable from Go via subprocess or gRPC | 1.5 | 4.0 | 7.0 | 3.92 | Not Started |
| 2.M5.T2 | Implement classifier gate logic: confidence >= 0.85 → flag/dismiss directly; 0.55-0.84 → escalate to Tier 3; < 0.55 → dismiss | 1.0 | 2.8 | 5.0 | 2.80 | Not Started |
| 2.M5.T3 | Integrate classifier gate into Path B pipeline after Tier 1 surface selection; pass only uncertain surfaces to Tier 3 | 0.5 | 2.0 | 4.0 | 1.92 | Not Started |
| 2.M5.T4 | Write unit tests for classifier gate routing logic using mock inference responses covering all three confidence bands | 0.5 | 2.0 | 4.0 | 1.92 | Not Started |
| 2.M5.T5 | Benchmark classifier latency on CPU for 50 code surfaces; document p50/p95 latency in performance notes | 0.5 | 2.0 | 4.0 | 1.92 | Not Started |

---

### Milestone 2.M6 — Path B Tier 3: Token Budget Controller + LLM Semantic Scan

| Field | Value |
|---|---|
| ID | `2.M6` |
| Name | Path B Tier 3 — Token Budget + LLM Semantic Scan |
| Type | MILESTONE |
| Start | 2026-07-14 |
| End | 2026-07-16 |
| PERT O | 8.0 |
| PERT ML | 18.0 |
| PERT P | 30.0 |
| PERT E | 18.3 |
| Status | Not Started |
| Notes | Hard token cap per scan. CFG-based chunking at function boundaries. Sensitive data (credentials/PII) routed to secure model only. LLM Semantic Scan never sees Path A results. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 2.M6.T1 | Implement Token Budget Controller: set hard token cap per scan (default 32k tokens); CFG-based chunker splits large surfaces at function boundaries | 2.0 | 4.8 | 8.0 | 4.80 | Not Started |
| 2.M6.T2 | Implement surface prioritizer: rank uncertain surfaces by (CVE base score × classifier uncertainty score) descending; truncate to budget | 1.0 | 2.4 | 4.0 | 2.40 | Not Started |
| 2.M6.T3 | Implement LLM Semantic Scan via Ollama: craft system prompt for IDOR / missing auth guard / business logic flaw detection; never include Path A results in context | 2.0 | 4.8 | 8.0 | 4.80 | Not Started |
| 2.M6.T4 | Parse LLM Semantic Scan response into []Finding with CWE ID, severity, affected lines, and explanation | 1.0 | 2.4 | 4.0 | 2.40 | Not Started |
| 2.M6.T5 | Write integration test for full Path B Tier 3 flow using a synthetic endpoint with a deliberate IDOR vulnerability; assert finding is returned | 1.0 | 2.4 | 4.0 | 2.40 | Not Started |

---

### Milestone 2.M7 — Dedup + Confidence Scoring

| Field | Value |
|---|---|
| ID | `2.M7` |
| Name | Dedup + Confidence Scoring |
| Type | MILESTONE |
| Start | 2026-07-17 |
| End | 2026-07-20 |
| PERT O | 6.0 |
| PERT ML | 14.0 |
| PERT P | 24.0 |
| PERT E | 14.3 |
| Status | Not Started |
| Notes | Triple-path fusion: AST edit distance + LLM semantic similarity + CWE pattern hash. 5 tiers: BLOCK >=0.92, HIGH 0.75-0.91, MEDIUM 0.60-0.74, LOW 0.30-0.59, SUPPRESSED <0.30. Dual-path confirmation → +15% score boost. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 2.M7.T1 | Implement AST edit distance deduplicator: compare code snippet AST hashes across Path A and Path B findings; group findings within edit distance threshold 2 | 1.5 | 3.6 | 6.0 | 3.60 | Not Started |
| 2.M7.T2 | Implement LLM semantic similarity deduplicator: embed finding explanations via local embedding model; cluster cosine similarity >= 0.85 as duplicates | 1.0 | 2.4 | 4.0 | 2.40 | Not Started |
| 2.M7.T3 | Implement CWE pattern hash deduplicator: same CWE + same file + overlapping line range → merge | 0.5 | 1.2 | 2.0 | 1.20 | Not Started |
| 2.M7.T4 | Implement confidence scoring engine: assign base score by tier; apply +15% boost for dual-path confirmation; suppress test-file and framework-safe findings | 1.0 | 2.4 | 4.0 | 2.40 | Not Started |
| 2.M7.T5 | Write unit tests for dedup and scoring: verify dual-path boost, SUPPRESSED findings filtered, correct tier assignment | 0.5 | 1.8 | 3.0 | 1.80 | Not Started |

---

### Milestone 2.M8 — HTML Report + Patch Suggestions

| Field | Value |
|---|---|
| ID | `2.M8` |
| Name | HTML Report + Patch Suggestions |
| Type | MILESTONE |
| Start | 2026-07-21 |
| End | 2026-07-23 |
| PERT O | 8.0 |
| PERT ML | 16.0 |
| PERT P | 28.0 |
| PERT E | 16.7 |
| Status | Not Started |
| Notes | Self-contained single-file HTML output (all CSS/JS inlined). Filterable findings table, confidence tier badge, expandable code diff, one-click patch copy. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 2.M8.T1 | Design HTML report template (Go html/template): severity summary bar, filterable findings table, expandable code diff per finding, confidence tier badge | 2.0 | 4.0 | 7.0 | 4.00 | Not Started |
| 2.M8.T2 | Implement report renderer: consume []Finding from dedup engine, embed all assets inline (CSS, JS) for fully self-contained single-file output | 1.5 | 3.0 | 5.0 | 3.00 | Not Started |
| 2.M8.T3 | Implement patch suggestion generator: for each finding, produce a unified Git diff patch with a minimal secure replacement using LLM or template rules | 2.0 | 4.0 | 7.0 | 4.00 | Not Started |
| 2.M8.T4 | Embed patch diffs into the HTML report as collapsible sections; add one-click copy-to-clipboard button per patch | 0.5 | 1.2 | 2.0 | 1.20 | Not Started |
| 2.M8.T5 | Write snapshot tests for the HTML renderer: render a fixture []Finding and assert key HTML elements are present (severity badge, CWE ID, patch block) | 1.0 | 2.4 | 4.0 | 2.40 | Not Started |

---

### Milestone 2.M9 — Integration Buffer + Demo Prep

| Field | Value |
|---|---|
| ID | `2.M9` |
| Name | Integration Buffer + Demo Prep |
| Type | MILESTONE |
| Start | 2026-07-24 |
| End | 2026-07-25 |
| PERT O | 6.0 |
| PERT ML | 12.0 |
| PERT P | 20.0 |
| PERT E | 12.3 |
| Status | Not Started |
| Notes | Run full end-to-end on real-world vulnerable-by-design repo. Fix top-3 integration bugs. Record terminal demo GIF/MP4. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 2.M9.T1 | Run full end-to-end scan on a real-world open-source project; triage any integration failures | 1.0 | 2.4 | 4.0 | 2.40 | Not Started |
| 2.M9.T2 | Fix top-3 integration bugs found during end-to-end run; re-run and confirm clean pass | 1.0 | 3.0 | 6.0 | 3.00 | Not Started |
| 2.M9.T3 | Prepare demo codebase: synthetic vulnerable project with 5+ seeded vulnerabilities covering Path A and Path B findings | 1.0 | 2.4 | 4.0 | 2.40 | Not Started |
| 2.M9.T4 | Record terminal demo: scan the demo codebase, show HTML report in browser, walk through one patch suggestion; export as GIF or MP4 | 0.5 | 1.2 | 2.0 | 1.20 | Not Started |
| 2.M9.T5 | Update README with installation steps, usage examples, architecture diagram, and known limitations | 0.5 | 1.2 | 2.0 | 1.20 | Not Started |

---

### Milestone 2.M10 — Presentation

| Field | Value |
|---|---|
| ID | `2.M10` |
| Name | Presentation |
| Type | MILESTONE |
| Start | 2026-07-28 |
| End | 2026-07-28 |
| PERT O | 2.0 |
| PERT ML | 4.0 |
| PERT P | 8.0 |
| PERT E | 4.3 |
| Status | Not Started |
| Notes | Slide deck: problem statement, architecture diagram, live demo, benchmark numbers, roadmap to Approach 3. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 2.M10.T1 | Build slide deck: problem statement, architecture diagram, live demo script, benchmark numbers (FP reduction rate, scan latency), roadmap to Approach 3 | 1.0 | 2.0 | 4.0 | 2.00 | Not Started |
| 2.M10.T2 | Dry-run presentation with tech lead; incorporate feedback; commit final slide deck to repository | 0.5 | 1.2 | 2.0 | 1.20 | Not Started |
| 2.M10.T3 | Deliver Approach 2 demo presentation to stakeholders | 0.5 | 1.2 | 2.0 | 1.20 | Not Started |

---

## Summary

| Metric | Value |
|---|---|
| Total milestones | 10 |
| Total tasks | 51 |
| Total PERT E | ~161 h |
| Available (5 weeks × 5 days × 6 h) | 150 h |
| Presentation date | 2026-07-28 |
