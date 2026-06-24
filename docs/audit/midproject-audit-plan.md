# ZeroTrust.sh — Mid-Project Code & Test Audit Plan

**Date**: 2026-06-23
**Auditor**: Coding agents operating under SWE Quality Contract + QA Quality Contract

---

## 1. Rationale

Multiple coding agents have been writing code concurrently across Layers 0–3. Spot checks show:

- Functions with no real purpose (wrappers around stdlib calls, vague names like `processData`)
- Oversized functions (>60 lines, nesting depth >4)
- Missing error wrapping, context propagation, edge-case tests
- Tests that assert `NoError` but never check output correctness — greenwasher tests
- Goroutines without lifecycle owners, deferred closes without error checks

The project deadlines (Aug 6) are tight. Quality debt compounds if left unaddressed. This audit catches violations early, before remaining Layer 3.1 and Layer 4 work builds on a weak foundation.

---

## 2. Scope

### 2.1 In Scope — Completed Packages (21 packages)

These are fully implemented per the delivery plan. Any quality violations here are real — not scaffolding.

```
cmd/zerotrust/
  internal/dedup/              ← gates 1–2 complete; gates 3–4 are future (flagged as known gap)
  internal/finding/
  internal/ingestion/
  internal/ingestion/diffindex/
  internal/ingestion/miv/
  internal/output/
  internal/output/web/
  internal/pattern/astgrep/
  internal/pattern/instrscan/
  internal/pattern/joern/
  internal/pattern/opengrep/
  internal/pattern/verifier/
  internal/report/
  internal/semantic/assembler/
  internal/semantic/budget/
  internal/semantic/classifier/
  internal/semantic/llmscan/
  internal/semantic/scs/
  internal/worker/
  pkg/ollama/
  pkg/sqlite/
```

All `*_test.go` files in these packages are also in scope.
All `worker/` Python files are in scope (the worker is used by completed layers).

### 2.2 Out of Scope — Pending Packages (genuine stubs, planned for future layers)

These contain intentional scaffolding or are entirely unimplemented. Violations here are expected — they will be remediated when their layer is built.

| Package | Layer | Status |
|---|---|---|
| `internal/semantic/targeting/` | ML3.1 — Heuristic Targeting + BOLAZ | Pending implementation |
| `internal/semantic/enrichment/` | ML3.1 — Trivy CVE enrichment | Pending implementation |
| `internal/semantic/summarizer/` | ML3.1 — Semantic summarizer | Pending implementation |
| `internal/patch/` | ML4.2 — Patch generation & validation | Pending implementation |
| `internal/output/web/ui/` (full report) | ML4.2 — Report tabs, filtering, suppressions | Pending implementation |
| `internal/dedup/` gates 3–4 | ML4.1 — Embedding + AST dedup | Pending (skeleton gates 1–2 exist in scope) |

---

## 3. Quality Scorecard

Every audited package receives a letter grade (A/B/C/D/F) per dimension. Packages scoring C or below are scheduled for mandatory remediation.

| Dimension | Weight | Source | Description |
|---|---|---|---|
| Error handling | 15% | SWE E1–E8 | Wrapping, sentinels, log-vs-return, no panics |
| Concurrency & context | 15% | SWE C1–C8 | errgroup, lifecycle ownership, cancellation, bounds |
| Function design | 15% | SWE F1–F7 | Size, naming, justification, nesting, proliferation |
| Test function design | 10% | QA TF1–TF6 | One scenario per test, size, hidden helpers, circular logic |
| Test completeness | 20% | QA all sections | Table-driven, edge cases, error paths, mocks, golden files |
| Package organization | 10% | SWE P1–P6 | Structure, deps, single responsibility per file |
| Documentation | 5% | SWE D1–D5 | Godoc, error sentinel docs, nolint reasons |
| Python standards | 10% | SWE Python T/E/O | Type hints, error handling, module layout |
| **Total** | **100%** | | |

**Letter thresholds**: A ≥90, B ≥75, C ≥60, D ≥40, F <40.

---

## 4. Phase 0 — Instrument & Baseline

**Goal**: Automated quality gates so the audit is data-driven, not manual.

**Effort**: 4–6h

**Parallelizable**: Yes (one agent for configs, one for baseline scripts)

### 4.1 Deploy Linter Configs

**Go** — `.golangci.yml` with at minimum:

| Linter | Purpose | SWE Contract Rule |
|---|---|---|
| `errcheck` | Catch bare error discards | Preamble (prohibition 1) |
| `wrapcheck` | Enforce `fmt.Errorf("...: %w", err)` | E1 |
| `contextcheck` | Enforce context as first param | C1 |
| `thelper` | Enforce `t.Helper()` in test helpers | QA Go T3 |
| `paralleltest` | Enforce `t.Parallel()` | QA Go T4 |
| `gocognit` | Cyclomatic complexity gate | F6 (nesting depth proxy) |
| `gofmt` / `goimports` | Formatting | — |
| `govet` | Shadowing, lostcancel | C3 |
| `staticcheck` | Various | — |

**Python** — `pyproject.toml` or `setup.cfg` with:

| Tool | Rule | SWE Contract Rule |
|---|---|---|
| `mypy --strict` | Type annotations on all functions | Python T1 |
| `ruff` | Bare except (E722), unused imports (F401), print (T201) | Python E3 |
| `pylint` | Too-many-arguments, too-many-locals, too-many-branches | F3 (parameter count) |

### 4.2 Run Baseline

```
# Go
golangci-lint run --config .golangci.yml ./cmd/... ./internal/... ./pkg/... 2>&1 | tee docs/audit/baseline-golangci-{DATE}.txt

# Python
mypy --strict worker/ 2>&1 | tee docs/audit/baseline-mypy-{DATE}.txt
ruff check worker/ 2>&1 | tee docs/audit/baseline-ruff-{DATE}.txt

# Race detector
go test -race ./cmd/... ./internal/... ./pkg/... 2>&1 | tee docs/audit/baseline-race-{DATE}.txt
```

### 4.3 Create Per-Package Scorecard Template

A markdown table per package with rows for each dimension. Example:

```markdown
## internal/pattern/verifier

| Dimension | Weight | Score | Grade |
|---|---|---|---|
| Error handling | 15% | 70 | C |
| Concurrency & context | 15% | 90 | A |
| Function design | 15% | 40 | D |
| Test function design | 10% | 50 | D |
| Test completeness | 20% | 65 | C |
| Package organization | 10% | 85 | B |
| Documentation | 5% | 60 | C |
| Python standards | 10% | — | N/A |
| **Weighted total** | **100%** | **66** | **C** |
```

---

## 5. Phase 1 — Critical Path Deep Audit

**Goal**: Audit packages on the hot path — code that if wrong produces false negatives (missed vulnerabilities). Highest business impact.

**Effort**: 10–14h

**Parallelizable**: Yes — one agent per 2–3 packages

### 5.1 Priority Order (by blast radius of bugs)

| Rank | Package | Why Critical |
|---|---|---|
| 1 | `internal/pattern/verifier/` | FP/FN gate for Path A; a broken verifier poisons all findings |
| 2 | `internal/worker/` | Goroutine lifecycle; NDJSON IPC; deadlock takes down the entire scan |
| 3 | `internal/ingestion/` (MIV + DI) | Hash failures skip LLM or re-scan everything |
| 4 | `internal/semantic/classifier/` + `router/` | Misclassification sends vulns to dismiss or safes to LLM (cost blowup) |
| 5 | `internal/semantic/llmscan/` | ReAct loop boundary conditions; token budget overflow |
| 6 | `internal/semantic/assembler/` | Call-chain depth-3 traversal; batch inference correctness |
| 7 | `internal/dedup/` | Cross-path boost logic; suppression sidecar |
| 8 | `pkg/ollama/` | MIV gate; context cancellation; all LLM calls flow through here |

### 5.2 Per-Package Checklist

#### Against SWE Contract

**Error Handling (E1–E8)**:
- [ ] Every `if err != nil` wraps with `fmt.Errorf("...: %w", err)`? (E1)
- [ ] No bare `errors.As` — all use `errors.AsType`? (E2)
- [ ] Sentinel errors defined with `errors.New`, not `fmt.Errorf`? (E4)
- [ ] Log or return, never both? (E5)
- [ ] Errors translated at package boundaries? (E6)
- [ ] No bare `//nolint:errcheck` without inline justification? (Preamble)
- [ ] No `defer resp.Body.Close()` without error check? (E8)
- [ ] No `panic()` in production paths? (E8)

**Concurrency & Context (C1–C8)**:
- [ ] Every I/O function accepts `ctx context.Context` as first param? (C1)
- [ ] No context stored in a struct? (C2)
- [ ] `defer cancel()` immediately after every `WithTimeout`/`WithCancel`? (C3)
- [ ] `errgroup.WithContext` for fan-out, never raw `sync.WaitGroup` for error-producing goroutines? (C4)
- [ ] Every `go` statement has a lifecycle owner and shutdown path? (C5)
- [ ] `g.SetLimit(N)` bounds every fan-out? (C6)
- [ ] Long-running loops check `ctx.Done()`? (C7)

**Function Design (F1–F7)**:
- [ ] Every function passes the Name Test (verb-noun, ≤5 words)? (F1)
- [ ] No `processData`/`handleStuff`/`run`/`execute` names? (F1)
- [ ] Every new function satisfies ≥1 criterion from F2? (F2)
- [ ] No function violates F3 prohibitions (boolean split, 5+ forwarded params, stdlib wrapper, test-only)? (F3)
- [ ] No functions that should be unified per F4? (F4)
- [ ] Every function ≤60 lines? (F5) — if 41–60, has `// >40 lines justified:` comment?
- [ ] No nesting depth >3? (F6)
- [ ] No file >600 lines or 5+ unrelated functions? (F7)

**Package Organization (P1–P6)**:
- [ ] `main.go` ≤50 lines? (P1)
- [ ] No `pkg/` directory for code that could be in `internal/`? (P2)
- [ ] No cyclic imports? (P4)
- [ ] One file = one responsibility? (P5)
- [ ] Dependencies justified, no deprecated libraries? (P6)

**Documentation (D1–D5)**:
- [ ] Every exported identifier has godoc? (D1)
- [ ] Package-level godoc or `doc.go` present? (D2)
- [ ] Error sentinel docs state when they're returned? (D3)
- [ ] Test functions have scenario comments? (D4)
- [ ] `//nolint` includes reason? (D5)

#### Against QA Contract

- [ ] Tests use table-driven pattern with `t.Run` subtests? (Go T1)
- [ ] Test helpers call `t.Helper()`? (Go T3)
- [ ] Independent tests use `t.Parallel()`? (Go T4)
- [ ] Tests cover error paths AND success paths equally? (Go T5)
- [ ] Edge cases tested: nil, empty, boundary, overflow, timeout, cancellation, concurrent? (Go T6)
- [ ] Tests use `t.Cleanup()` not `defer` for parallel subtests? (Go T7)
- [ ] No test asserts `NoError` without checking output correctness? (rejected patterns)
- [ ] Mocks verify expected calls (not just return values)? (Go T9)
- [ ] One test function = one scenario? (TF1)
- [ ] Test function ≤40 lines? (TF2)
- [ ] Test helpers do ONE thing, not hidden tests? (TF3)
- [ ] No circular test logic (testing via same code path as production)? (TF4)
- [ ] Test hooks documented and promoted to interface by 3rd user? (TF5)
- [ ] No `testutil/` grab-bag package? (TF6)

---

## 6. Phase 1a — Function Proliferation Scan

**Goal**: Dedicated sweep for meaningless, duplicated, or poorly-sized functions across all 21 in-scope packages.

**Effort**: 4h

**Parallelizable**: Yes — automated scripts run in parallel, manual review is serial

### 6.1 Automated Scan (Script-Based)

All results output to `docs/audit/function-proliferation-{DATE}.csv`.

**Scan 1 — Orphan Detector**

Extract all exported functions. For each, check how many packages within the module import it. Flag any exported function imported by 0 packages (besides its own package's tests).

```bash
rg "^func [A-Z]" -g '*.go' --no-filename | grep -o 'func [A-Z][a-zA-Z]*' | sort -u
# cross-reference with go list -deps ./...
```

Expected triggers: exported helpers that should be unexported, dead code.

**Scan 2 — Tiny Function Detector**

Flag functions with body ≤4 lines and a single call site within the same package.

```
☐ internal/worker/worker.go:45 — func reset()  (3 lines, 1 call site)
  → violates F2 (no justification) + F3.1 (body ≤3 lines)
```

Expected triggers: stdlib wrappers, micro-extractions that should be inline.

**Scan 3 — Boolean Split Detector**

Flag functions accepting a `bool` parameter where the body branches on that parameter.

```go
func process(ctx context.Context, admin bool) error {
    if admin { return adminProcess(ctx) }
    return userProcess(ctx)
}
```

Expected triggers: functions that should be two named functions per F3.6.

**Scan 4 — Passthrough Detector**

Flag functions whose body is a single function call forwarding ≥3 parameters unchanged.

```go
func SaveUser(ctx, db, id, name string) error {
    return saveUserInternal(ctx, db, id, name)
}
```

Expected triggers: useless indirection per F3.3.

**Scan 5 — Size Violator**

Every function measured against F5 size table. Flag:

- 1–7 lines: check if satisfies F2 (if not → inline candidate)
- 41–60 lines: check for justification comment
- >60 lines: blocker

```bash
awk '
  /^func / { if(NR>last+1) print last+1"-"NR-1" lines: "name; }'
```

**Scan 6 — Nesting Violator**

Flag functions with 4+ levels of indentation.

**Scan 7 — Duplicate Body Detector**

Levenshtein or token-distance between all function bodies. Flag pairs with >70% similarity.

Expected triggers: copy-pasted validation logic, parallel implementations that should be unified per F4.2.

**Scan 8 — Name Violator**

Flag functions with vague names: `process`, `handle`, `run`, `execute`, `doWork`, `perform`, `stuff`, `thing`, `data`, `info`.

```bash
rg "^func .*(process|handle|run|execute|doWork|perform).*\(" -g '*.go'
```

Expected triggers: rename candidates per F1.

### 6.2 Stub Tagging in Completed Packages

Because some functions in "done" packages may still have TODO stubs (forgotten tasks or dead code), the scans also tag:

- `// TODO` or `// FIXME` or `// HACK` anywhere in function body
- `panic(".*not implemented.*")` or `return nil, nil` with no real logic

These are tagged `STUB` in the CSV output — they are NOT excluded (they're in completed packages, so they're violations). They get added to the remediation queue but with lower priority than active code.

### 6.3 Manual Review Sample

After automated scans, manually review 2 packages with the worst automated scores (selected by number of violations per LOC). Read every function in those packages and apply F1–F7 judgment calls that automated scanning cannot catch:

- "Is this function name less clear than the code it wraps?" (F3.2)
- "Do these two functions share a common abstraction?" (F4)
- "Is this function truly a distinct unit of change?" (F2.4)

### 6.4 Output

File: `docs/audit/function-proliferation-{DATE}.md`

```markdown
# Function Proliferation Scan — 2026-06-23

## Summary
- Total functions scanned: 847
- Violations found: 134
- Stubs in completed packages: 12
- Orphan exported functions: 8
- >60 line functions: 3 (blocker)
- Boolean-split functions: 7

## Per-Package Breakdown
| Package | Functions | Violations | Stubs | Grade |
|---|---|---|---|---|
| verifier | 14 | 2 | 0 | B |
| worker | 33 | 8 | 1 | D |
| ...

## Top Violators (Fix First)
1. internal/worker/worker.go:319 — handleDeath() 72 lines (F5 blocker)
2. internal/pattern/joern/joern.go:238 — go func() without lifecycle owner (C5)
3. ...
```

---

## 7. Phase 2 — Python Worker Audit

**Goal**: Verify the ML worker code against Python-specific contract rules.

**Effort**: 6–8h

**Parallelizable**: Yes — can run concurrently with Phases 1/1a

### 7.1 Scope

All files in `worker/`:
- `worker/main.py`
- `worker/handlers/*.py` (classify, llm_verify, llm_scan, summarize)
- `worker/models/*.py` (unixcoder, xgrammar)
- `worker/schemas/*.py` (verdict)
- `worker/tests/*.py` (test_classify, test_llm_verify)

### 7.2 Checklist

**Type Safety (Python T1–T6)**:
- [ ] Every function signature has type annotations
- [ ] `X | None` over `Optional[X]`
- [ ] `TypedDict` used for dictionary shapes, not `dict[str, Any]`
- [ ] `dataclass` for internal data, Pydantic for boundary data
- [ ] No bare `Any` without justification
- [ ] `# type: ignore[code]` with specific error codes

**Error Handling (Python E1–E4)**:
- [ ] No bare `except:`
- [ ] Specific exception types raised, not generic `Exception`
- [ ] `logging` with structured fields, no `print`
- [ ] NDJSON protocol errors produce structured JSON error responses

**Function Design (F1–F7)**:
- [ ] Same rules as Go — applied to every Python function
- [ ] Especially: name test, size boundaries, nesting depth, boolean splits

**Tests (QA Python section + TF1–TF6)**:
- [ ] `pytest.fixture` used for setup
- [ ] `@pytest.mark.parametrize` for multi-case tests
- [ ] Mocks use `spec=` to catch API drift
- [ ] Integration tests gated with `@pytest.mark.integration`
- [ ] One scenario per test function
- [ ] No hidden-test helpers
- [ ] No circular test logic

---

## 8. Phase 3 — Test Suite Quality Audit

**Goal**: Evaluate actual test quality, not just test presence. Identify greenwasher tests.

**Effort**: 8–10h

**Parallelizable**: Yes — sub-phase 3a is automated, 3b–3d are manual sampling

### 8.1 Sub-Phase 3a — Structural Audit (Automated)

Run these queries across all `*_test.go` files in scope:

| Check | Command | Flag |
|---|---|---|
| No assertions | Test function with zero `assert.*` or `require.*` calls | Greenwasher candidate |
| `NoError` only | Test that calls `assert.NoError` but never checks output | Greenwasher candidate |
| No table-driven | Test function with 3+ cases but no `t.Run` | Structure failure |
| No `t.Parallel()` | Independent test running solo | Performance miss |
| No `t.Helper()` | Helper function (accepts `*testing.T`) without `t.Helper()` | Line reporting loss |
| `defer` in parent | `defer` used in parent function of parallel subtests | Cleanup race |
| >25 lines | Test function exceeding 25 lines | Size warning per TF2 |
| >40 lines | Test function exceeding 40 lines | Size blocker per TF2 |
| No `goleak` | Package missing `goleak.VerifyTestMain` | Goroutine leak risk |
| No edge cases | No nil/empty/boundary/timeout test | Coverage gap |

### 8.2 Sub-Phase 3b — Semantic Audit (Manual Sampling)

Select 5 test files from the critical path packages (verifier, worker, classifier, dedup, ollama). For each test function, answer:

1. **Would this test fail if the code were wrong?** — If no, mark as greenwasher.
2. **Does the test name complete "it should ___"?** — If no, mark as naming failure (TF1).
3. **Does the test compute expected via production code?** — If yes, mark as circular logic (TF4).
4. **Does the test helper bundle multiple assertions?** — If yes, mark as hidden test (TF3).

Each test is classified as: ✅ Good / ⚠️ Weak / ❌ Greenwasher.

### 8.3 Sub-Phase 3c — Edge Case Gap Analysis

For each audited package, check coverage of:

| Edge Case | Check |
|---|---|
| Nil input | `ParseConfig(nil)`, `Scan("")`, `Process(nil)` |
| Empty input | Empty slice, empty string, empty map |
| Boundary | `len == 0`, `len == max`, exact threshold |
| Context cancellation | `ctx, cancel := context.WithCancel(ctx); cancel()` |
| Context timeout | `context.WithTimeout(ctx, 1*time.Nanosecond)` |
| Concurrent access | 10 goroutines calling the same function |
| Overflow | `math.MaxInt64 + 1`, large file paths |
| Negative / zero | `count = -1`, `port = 0` |
| Race detection | `go test -race` must pass |

Create gap matrix: rows = packages, columns = edge case types. Mark present/absent.

### 8.4 Sub-Phase 3d — Integration/E2E Audit

- [ ] Build tags correct: `//go:build integration` / `e2e`
- [ ] Integration tests clean up subprocesses (Joern, Ollama test servers)
- [ ] No leaked goroutines — confirm with `goleak.VerifyTestMain` presence
- [ ] Golden files have `.gitignore`? No timestamps/line numbers in assertions?

---

## 9. Phase 4 — Remediation Sprints

**Goal**: Fix violations found in Phases 1–3, prioritized by blast radius.

**Effort**: 20–28h

**Parallelizable**: Yes — 4 concurrent streams, each works independently

### 9.1 Triage Tiers

| Tier | Criteria | Action | Target |
|---|---|---|---|
| **P0 — BLOCKER** | Bug causes false negative/positive in findings | Fix immediately, write regression test | <24h |
| **P1 — HIGH** | Bug causes crash, hang, data corruption, or contract prohibition violation | Fix before next Layer work | <48h |
| **P2 — MEDIUM** | Contract violation with no immediate bug (missing godoc, no `t.Parallel()`, no error wrapping) | Schedule in current sprint | This week |
| **P3 — LOW** | Style / naming / consistency only | Batch at end of sprint | Before L4 delivery |
| **P4 — STUB** | TODO in completed package (forgotten task or dead code) | Investigate: either implement or remove | This week |

### 9.2 P0/P1 Violations (Must Fix Immediately)

| Source | Violation | Package Owner |
|---|---|---|
| F5 | Function >60 lines | Decompose |
| F4.6 | Orphan exported function | Unexport or inline |
| C5 | Goroutine without lifecycle owner | Add shutdown path |
| C3 | Missing `defer cancel()` | Add |
| Preamble | Bare `_, _ =` error discard | Assign or justify |
| E8 | `panic()` in production path | Convert to error |
| F3.6 | Boolean-split function | Split into two |
| F3.3 | Passthrough with 5+ forwarded params | Inline or use struct |
| TF2 | Test >40 lines | Decompose |
| TF4 | Circular test logic | Replace with known-answer |

### 9.3 P2 Violations (Schedule This Sprint)

| Source | Violation |
|---|---|
| F5 | Function 41–60 lines without justification comment |
| F2 | 1–7 line function, single call site, no F2 justification |
| F6 | Nesting depth >3 |
| F4 | Duplicate function bodies (≥70% similar) |
| F1 | Vague function name |
| E1 | Error not wrapped with context |
| E5 | Function both logs AND returns error |
| Go T1 | Tests not using table-driven pattern |
| Go T4 | Missing `t.Parallel()` |
| Go T6 | Missing edge case tests |
| TF1 | Test function testing multiple scenarios |
| TF3 | Hidden-test helper |

### 9.4 Parallel Remediation Streams

| Stream | Focus | Agent Skills Needed |
|---|---|---|
| **A** — Function size & structure | F5/F6/F7 violations — decompose big functions, reduce nesting, split files | Go refactoring |
| **B** — Function proliferation | F2/F3/F4 violations — inline tiny functions, split boolean-splits, unify duplicates, rename bad names | Go refactoring |
| **C** — Test quality | TF1–TF6 + table-driven + edge cases + greenwasher elimination | Test design |
| **D** — Error handling & concurrency | E1–E8, C1–C8 violations — wrap errors, add context, fix goroutine lifecycles | Go systems |
| **E** — Python worker | Type hints, error handling, test quality | Python + pytest |

### 9.5 Remediation Workflow

1. Create `docs/audit/` report per stream with file:line references
2. Fix P0/P1 by editing files directly
3. P2: batch into PRs organized by concern (e.g., "error wrapping audit fixes", "test helper cleanup")
4. After each fix batch, re-run linter baseline to verify improvement
5. Re-score the package scorecard

---

## 10. Phase 5 — Governance Gates

**Goal**: Prevent quality regression as remaining layers (ML3.1, ML4) are built.

**Effort**: 4–6h

### 10.1 CI Integration

Add to CI pipeline:
- `golangci-lint run --config .golangci.yml` (fail on new issues)
- `mypy --strict worker/` (fail on new type errors)
- `ruff check worker/` (fail on new style violations)
- `go test -race ./...` (fail on race violations)
- `go vet ./...` (fail on suspicious constructs)

### 10.2 Agent Startup Checklist

Create `ai/SESSION_START.md`:

```markdown
# Session Start Checklist

Before writing ANY code in this session:

1. Read `ai/quality_contracts/swe_contract.md`
2. Read `ai/quality_contracts/qa_contract.md`
3. Confirm which package(s) and task ID you're working on
4. Check `docs/audit/stub_inventory.md` if working on a planned stub
5. Run `make lint-audit` to check current state of the package

Before submitting ANY PR:

1. Every new function satisfies ≥1 criterion from F2
2. No function violates F3 (boolean split, passthrough, etc.)
3. No function exceeds 60 lines
4. Nesting depth ≤3
5. Every error is wrapped with context
6. Every goroutine has a lifecycle owner
7. Every test uses table-driven pattern with subtests
8. Test covers error paths AND edge cases
9. `go test -race ./...` passes
10. If uncertain about quality → STOP → notify the user

**Non-compliance procedure**:
- 1st offense in PR: reviewer marks, agent fixes before merge
- 2nd offense in same PR: entire PR rejected, must be re-scoped
- Repeated offenses across PRs: agent commit access revoked, all changes require manual review
```

### 10.3 Pre-Commit Hooks (Optional)

Makefile target:
```makefile
.PHONY: lint-audit
lint-audit:
    golangci-lint run --config .golangci.yml ./...
    mypy --strict worker/
    ruff check worker/
    go vet ./...
    go test -race -short ./...
```

### 10.4 Quality Regression Budget

During remaining Layer work, allocate 20% of each task's estimate to quality:
- If ML3.1 BOLAZ is 12h → 9.6h implementation + 2.4h for contract-conformant tests and lint-clean code
- Invoiced upfront, not as a last-minute addition
- If the quality work exceeds the 20% budget, the agent must stop and report — not compromise

---

## 11. Dedup Edge Case

`internal/dedup/` is in the "done" list but only gates 1–2 exist per the implementation plan. Gates 3–4 (embedding similarity, AST edit distance) are ML4 tasks.

**Audit treatment**:
- Existing gates 1–2 code is in scope — audit for quality, not completeness
- Missing gates 3–4 are NOT a violation — they're planned scaffolding
- The gap is documented in `docs/audit/stub_inventory.md` with reference to ML4.1.T1–T2
- When ML4 is built, the new gates must pass all contract checks

---

## 12. Timeline & Parallelization

| Phase | Effort | Agents | Wall-Clock | Depends On |
|---|---|---|---|---|
| P0 — Instrument | 4–6h | 1 | 4–6h | Nothing |
| P1 — Critical audit | 10–14h | 2–3 | 5–7h | P0 (configs) |
| P1a — Proliferation scan | 4h | 1 | 4h | P0 (scripts) |
| P2 — Python audit | 6–8h | 1 | 6–8h | P0 |
| P3 — Test audit | 8–10h | 2 | 4–5h | P1 (to know which packages to sample) |
| P4 — Remediation | 20–28h | 4 | 5–7h | P1 + P1a + P2 + P3 |
| P5 — Governance | 4–6h | 1 | 4–6h | P4 (to incorporate lessons) |
| **Total** | **56–76h** | **Max 4 concurrent** | **~3–4 calendar days** | |

### Dependency Graph

```
P0 ──┬── P1 ──┬── P3 ──┐
     │        │         │
     ├── P1a ─┤         ├── P4 ── P5
     │                 │
     └── P2 ──────────┘
```

P1, P1a, and P2 can run in parallel after P0. P3 needs P1's findings to know which test files to sample. P4 needs all four, then starts. P5 closes.

---

## 13. Deliverables

| Artifact | Location | Contents |
|---|---|---|
| Linter baseline | `docs/audit/baseline-*.txt` | Violation counts per linter |
| Package scorecards | `docs/audit/scorecards/*.md` | Grade per package per dimension |
| Proliferation scan | `docs/audit/function-proliferation-{DATE}.csv` | Every violation with file:line |
| Critical audit reports | `docs/audit/critical-{package}-{DATE}.md` | Per-package findings with code references |
| Test quality audit | `docs/audit/test-quality-{DATE}.md` | Greenwasher hitlist, edge case gap matrix |
| Remediation PRs | N/A (direct file edits) | Fix batches organized by concern |
| Stub inventory | `docs/audit/stub_inventory.md` | Planned stubs with task IDs and deadlines |
| Governance config | `.golangci.yml`, `pyproject.toml`, `ai/SESSION_START.md` | Permanent quality gates |

---

## 14. Contingency

| Risk | Likelihood | Mitigation |
|---|---|---|
| Too many violations to remediate in budget | Medium | Focus on P0/P1 only; defer P2/P3 to post-L4 or drop |
| False positives from automated scans | Medium | Manual review sample in Phase 1a.2 provides calibration |
| Stub code mistaken for violation | Low | Excluded by package list; `STUB` tag for anything missed |
| Audit introduces more bugs than it fixes | Low | Each fix is a focused edit with its own diff; `go test -race` must pass |
| Deadline pressure — audit takes too long | Medium | Hard time-box: 4 days max → if not done, drop P3/P4 and only fix P0/P1 |
