# Sheet 2 — Approach 1: Semgrep PoC

**Sheet name:** `Approach 1 - Semgrep PoC`
**Goal ID:** 1
**Goal name:** Approach 1 — Semgrep PoC
**Description:** Deliver a working Semgrep-based custom rule engine that detects AI coding agent-introduced vulnerability patterns in Python and Java codebases, producing a CLI demo and presentation narrative approved by the tech lead by 2026-06-20.
**Date range:** 2026-06-09 → 2026-06-20
**Total milestones:** 7 + 1 explicit buffer
**Total tasks:** 39
**Current state (2026-06-11):** M1 Complete, M2 In Progress

---

## Sheet Header Rows

| Row | Content | Style |
|---|---|---|
| 1 | `ZeroTrust.sh  ·  Approach 1 — Semgrep PoC` | 20pt bold white on `#1F3864`, height 50px |
| 2 | `Intern: Ton Minh Hoang  ·  VNG ZingPlay Studio  ·  Goal: Semgrep-based custom rule engine  ·  Deadline: 2026-06-20` | 11pt italic white on `#2E5FA3`, height 22px |
| 3 | *(spacer)* | height 6px |
| 4 | Column headers: ID / Name / Type / Start Date / End Date / PERT O / PERT ML / PERT P / PERT E / Actual Hrs / Status / Owner / Notes | 20pt bold white on `#2E5FA3`, height 50px |

---

## Data Entries

### Milestone 1.M1 — Research & Setup

| Field | Value |
|---|---|
| ID | `1.M1` |
| Name | Research & Setup |
| Type | MILESTONE |
| Start | 2026-06-09 |
| End | 2026-06-09 |
| PERT O | 2.3 |
| PERT ML | 4.7 |
| PERT P | 10.5 |
| PERT E | 5.25 |
| Status | **Complete** |
| Notes | Install Semgrep CLI; scaffold repo; write one toy rule end-to-end. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 1.M1.T1 | Install Semgrep CLI and verify installation | 0.3 | 0.5 | 1.5 | 0.55 | Complete |
| 1.M1.T2 | Read Semgrep operator docs and YAML rule syntax documentation | 1.0 | 2.0 | 4.5 | 2.08 | Complete |
| 1.M1.T3 | Write one end-to-end toy rule to confirm setup works | 0.5 | 1.5 | 3.5 | 1.67 | Complete |
| 1.M1.T4 | Scaffold repo structure: rules/, tests/, scripts/ directories with README stubs | 0.2 | 0.5 | 1.0 | 0.53 | Complete |

---

### Milestone 1.M2 — Python Custom Rules

| Field | Value |
|---|---|
| ID | `1.M2` |
| Name | Python Custom Rules |
| Type | MILESTONE |
| Start | 2026-06-10 |
| End | 2026-06-11 |
| PERT O | 4.2 |
| PERT ML | 9.4 |
| PERT P | 27.0 |
| PERT E | 11.98 |
| Status | **In Progress** |
| Notes | Write 10 Python rules PY-001 to PY-010 with bad.py / ok.py test pairs. Save hardest rules (bypass, f-string SQL) for last. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 1.M2.T1 | Write PY-001: pickle.loads() without type validation (insecure deserialization) | 0.3 | 0.8 | 2.0 | 0.88 | In Progress |
| 1.M2.T2 | Write PY-002: subprocess.run(shell=True) with dynamic input (OS command injection) | 0.3 | 0.8 | 2.0 | 0.88 | Not Started |
| 1.M2.T3 | Write PY-003: eval() / exec() on user-controlled input (code injection) | 0.3 | 0.7 | 1.5 | 0.75 | Not Started |
| 1.M2.T4 | Write PY-004: requests SSL verification bypass (verify=False) | 0.2 | 0.5 | 1.5 | 0.57 | Not Started |
| 1.M2.T5 | Write PY-005: Hardcoded credentials — password, api_key, token string literals | 0.3 | 0.8 | 2.0 | 0.88 | Not Started |
| 1.M2.T6 | Write PY-006: Hardcoded AI service API keys (sk-, sk-ant-, hf_ prefixes) | 0.3 | 0.7 | 2.0 | 0.80 | Not Started |
| 1.M2.T7 | Write PY-007: Path traversal with open() without sanitization | 0.3 | 0.8 | 2.5 | 0.97 | Not Started |
| 1.M2.T8 | Write PY-008: yaml.load() instead of yaml.safe_load() (unsafe YAML parsing) | 0.2 | 0.5 | 1.5 | 0.57 | Not Started |
| 1.M2.T9 | Write PY-009: SQL injection via f-string or % formatting (hardest — save for last) | 0.5 | 1.5 | 5.0 | 1.92 | Not Started |
| 1.M2.T10 | Write PY-010: Unsanitized user input injected into LLM system prompts (AI-specific, hardest) | 0.5 | 2.0 | 7.0 | 2.58 | Not Started |

---

### Milestone 1.M3 — Java Custom Rules

| Field | Value |
|---|---|
| ID | `1.M3` |
| Name | Java Custom Rules |
| Type | MILESTONE |
| Start | 2026-06-12 |
| End | 2026-06-13 |
| PERT O | 4.3 |
| PERT ML | 10.3 |
| PERT P | 29.5 |
| PERT E | 12.84 |
| Status | Not Started |
| Notes | Write 9 Java rules JV-001 to JV-009. Validate AST shapes with semgrep --dump-ast before authoring. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 1.M3.T1 | Run semgrep --dump-ast --lang java on sample file; confirm AST node shapes before writing any rule | 0.2 | 0.5 | 1.5 | 0.57 | Not Started |
| 1.M3.T2 | Write JV-001: Runtime.getRuntime().exec(userInput) — OS command injection | 0.4 | 1.0 | 3.0 | 1.23 | Not Started |
| 1.M3.T3 | Write JV-002: JDBC string concatenation SQL injection (Statement.execute + string concat) | 0.4 | 1.2 | 4.0 | 1.57 | Not Started |
| 1.M3.T4 | Write JV-003: ObjectInputStream.readObject() without class filtering (insecure deserialization) | 0.3 | 1.0 | 3.5 | 1.30 | Not Started |
| 1.M3.T5 | Write JV-004: Hardcoded credentials in Java source (String password, String apiKey literals) | 0.3 | 0.8 | 2.0 | 0.88 | Not Started |
| 1.M3.T6 | Write JV-005: Path traversal with new File(baseDir + userInput) without normalization | 0.3 | 1.0 | 3.0 | 1.22 | Not Started |
| 1.M3.T7 | Write JV-006: Empty X509TrustManager (TLS certificate bypass — checkServerTrusted no-op) | 0.4 | 1.2 | 4.0 | 1.57 | Not Started |
| 1.M3.T8 | Write JV-007: MD5 or SHA1 used for password hashing (weak crypto) | 0.2 | 0.6 | 2.0 | 0.70 | Not Started |
| 1.M3.T9 | Write JV-008: Sensitive data in log statements (logger.info with password/token variable) | 0.3 | 0.8 | 2.5 | 0.97 | Not Started |
| 1.M3.T10 | Write JV-009: AI-agent security bypass comment pattern (SECURITY_BYPASS / disabled for testing) | 0.5 | 1.5 | 6.0 | 2.08 | Not Started |

---

### Milestone 1.M4 — Test Codebase

| Field | Value |
|---|---|
| ID | `1.M4` |
| Name | Test Codebase |
| Type | MILESTONE |
| Start | 2026-06-16 |
| End | 2026-06-16 |
| PERT O | 2.4 |
| PERT ML | 5.7 |
| PERT P | 16.0 |
| PERT E | 6.75 |
| Status | Not Started |
| Notes | AI-generate fake Spring Boot REST API (10-15 files, 800-1200 LOC). Embed >=8 intentional vulnerabilities. Success: Semgrep detects >=6 of 8. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 1.M4.T1 | Prompt AI to generate Spring Boot REST API skeleton (controller/service/repository layers, Java 8, 10-15 files) | 0.3 | 0.8 | 2.0 | 0.88 | Not Started |
| 1.M4.T2 | Embed >=8 intentional vulnerabilities into the codebase (mapped to JV-001 to JV-009 rule targets, realistic CVE-pattern placement) | 0.5 | 1.5 | 4.0 | 1.75 | Not Started |
| 1.M4.T3 | Run semgrep --config rules/ against the test codebase; record raw findings JSON | 0.2 | 0.5 | 1.5 | 0.57 | Not Started |
| 1.M4.T4 | Triage findings: confirm true positives, document false positives, verify >=6 of 8 embedded vulnerabilities caught | 0.5 | 1.5 | 5.0 | 1.92 | Not Started |
| 1.M4.T5 | Run rule set against one clean open-source Java repo; count and document false positives to establish FP rate baseline | 0.3 | 1.0 | 3.5 | 1.30 | Not Started |

---

### Milestone 1.M5 — Demo Preparation

| Field | Value |
|---|---|
| ID | `1.M5` |
| Name | Demo Preparation |
| Type | MILESTONE |
| Start | 2026-06-17 |
| End | 2026-06-17 |
| PERT O | 1.9 |
| PERT ML | 4.6 |
| PERT P | 13.0 |
| PERT E | 5.40 |
| Status | Not Started |
| Notes | Write demo/run_demo.sh with pinned Semgrep version and hardcoded paths. Full dry-run in fresh terminal. Record 3-minute fallback video. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 1.M5.T1 | Write demo/run_demo.sh with pinned Semgrep version, hardcoded absolute paths, and annotated output | 0.3 | 1.0 | 3.0 | 1.22 | Not Started |
| 1.M5.T2 | Full dry-run in a fresh terminal (close and reopen shell, no venv activated, execute script cold) | 0.2 | 0.8 | 2.5 | 0.95 | Not Started |
| 1.M5.T3 | Fix any path, version, or environment issues discovered in dry-run | 0.2 | 1.0 | 4.0 | 1.37 | Not Started |
| 1.M5.T4 | Record 3-minute fallback screen recording of the full demo running successfully | 0.3 | 0.8 | 2.0 | 0.88 | Not Started |

---

### Milestone 1.M6 — Presentation Narrative

| Field | Value |
|---|---|
| ID | `1.M6` |
| Name | Presentation Narrative |
| Type | MILESTONE |
| Start | 2026-06-18 |
| End | 2026-06-18 |
| PERT O | 2.0 |
| PERT ML | 4.4 |
| PERT P | 12.0 |
| PERT E | 5.00 |
| Status | Not Started |
| Notes | Write pros/cons with >=2 real limitations stated honestly. Draft Approach 2 next-step argument. Add speaker notes per slide. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 1.M6.T1 | Draft Approach 1 pros/cons section — minimum 2 real limitations stated without apology (no semantic analysis, no interprocedural taint) | 0.5 | 1.5 | 4.0 | 1.75 | Not Started |
| 1.M6.T2 | Draft the Approach 2 next-step argument: why Path B (independent LLM semantic scan) follows naturally from Approach 1 limitations | 0.5 | 1.5 | 4.0 | 1.75 | Not Started |
| 1.M6.T3 | Add speaker notes to each presentation section; review for tech lead audience register (no fluff, no over-selling) | 0.3 | 1.0 | 3.0 | 1.22 | Not Started |

---

### Milestone 1.M7 — Jupyter Notebook (BONUS)

> **BONUS milestone** — started only if M4 is Complete by 2026-06-17 end of day. Hard abort if not started by 16:00 on 2026-06-19. Cut first if schedule slips.

| Field | Value |
|---|---|
| ID | `1.M7` |
| Name | Jupyter Notebook (Bonus) |
| Type | MILESTONE |
| Start | 2026-06-19 |
| End | 2026-06-19 |
| PERT O | 2.3 |
| PERT ML | 5.6 |
| PERT P | 16.0 |
| PERT E | 6.55 |
| Status | Not Started |
| Notes | [BONUS] Produce five core metrics with charts. Only start if M4 is complete by Jun 17 EOD. |

**Tasks:**

| Task ID | Name | O | ML | P | E | Status |
|---|---|---|---|---|---|---|
| 1.M7.T1 | Set up Jupyter notebook with Semgrep JSON output parser; load findings from M4 validation scan | 0.3 | 0.8 | 2.5 | 0.97 | Not Started |
| 1.M7.T2 | Compute and chart precision and recall per rule against the intentional-vulnerability test codebase | 0.5 | 1.5 | 4.0 | 1.75 | Not Started |
| 1.M7.T3 | Benchmark scan speed: measure lines/second on test codebase; compare against a cloud SAST round-trip baseline | 0.3 | 0.8 | 2.5 | 0.97 | Not Started |
| 1.M7.T4 | Compute AI-specific detection rate: proportion of AI-pattern rules (PY-010, JV-009) that fire correctly vs. community-rule detections | 0.3 | 1.0 | 3.0 | 1.22 | Not Started |
| 1.M7.T5 | Compute and chart false positive rate on clean codebase (data from M4.T5); add executive summary cell at notebook top | 0.3 | 1.0 | 3.5 | 1.30 | Not Started |

---

### Buffer Row — 1.BUFFER

| Field | Value |
|---|---|
| ID | `1.BUFFER` |
| Name | Explicit Buffer |
| Type | BUFFER |
| Start | 2026-06-09 |
| End | 2026-06-19 |
| PERT O | 5.0 |
| PERT ML | 5.0 |
| PERT P | 5.0 |
| PERT E | 5.0 |
| Status | Not Started |
| Notes | Reserved for: bypass rule debugging (M2/M3), Java AST grammar mismatch (M3), detection rate shortfall requiring rule tuning (M4), demo environment polish (M5). Absorbed into whichever milestone overruns first. |

---

## Summary

| Metric | Value |
|---|---|
| Core PERT E total (M1–M6 + Buffer) | 45.22 h |
| Bonus PERT E total (+ M7) | 51.77 h |
| Available capacity (8 days × 6 h) | 48 h |
| Core slack | ~2.8 h |
| Presentation date | 2026-06-20 |
