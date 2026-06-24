# ZeroTrust.sh — TODO

> L0 ✅ · L1 ✅ · L2 ✅ · L3 ✅ · ML4.1 ✅ · ML4.2 ✅ (all complete as of Jun 24, ~6 weeks early)
> Full plan: `docs/planning/implementation-plan.md`

---

## Layer 4 — Dedup Complete + Report + Final Integration

> Plan window: Jul 28 – Aug 6 · Budget: ~50h work + 13h buffer · **Hard deadline: Aug 6**
>
> Checkpoint: `zerotrust scan ./test-codebase` runs the full pipeline (Path A + Path B), deduplicates, scores, generates a self-contained HTML report with patch suggestions. Repo clean, README present.

---

### ML4.1 — Dedup Complete + SSVC-Inspired Confidence Scoring ✅ Done Jun 24

- [x] **T1** — Gate 3: MiniLM-L6-v2 embedding similarity (`worker/handlers/embed.py`; `worker.Embed()`; cosine similarity in Go; threshold 0.95)
- [x] **T2** — Gate 4: AST token edit distance (`worker/handlers/ast_edit.py`; tree-sitter-languages optional + regex fallback; `worker.ASTEditSimilarity()`; threshold 0.85)
- [x] **T3** — SSVC dimension sourcing (`internal/dedup/ssvc.go`; CISA KEV bundle cached `~/.zerotrust/kev.json` 24h TTL; EPSS via FIRST API; 20-entry CWE static maps; NVD deferred to buffer)
- [x] **T4** — Score → label + CVE CVSS floor + SSVC boosts + Path A MEDIUM floor (`applyBoostAndScore`)
- [x] **T5** — Cross-path +15pp boost; BLOCK not boosted (`f.Confidence < 0.92` guard)
- [x] **T6** — Framework-safe suppression + `.zerotrust-suppressions.yaml` sidecar (`internal/dedup/sidecar.go`; 8 framework globs; ID/path/CWE matching; `dedup.NewWithRoot(cfg.Target)`)
- [x] **T7** — `poe_context` population from Path B LLM Scan (`llmscan.buildPoeContext()` from `TaintFlow`+`AuthGuard`+`LogicFlaw`)

**27 dedup tests green · `make test` clean.**

---

### ML4.2 — HTML Report + Patch Suggestions ✅ Done Jun 24

> `internal/report/` · `internal/report/patch.go` · `internal/report/template.html`

- [x] **T1** — Complete HTML report:
  - `html/template` + `embed`; SSVC-inspired severity labels with colour coding.
  - Filtering by severity / file / detection path (Path A / Path B / cross-path).
  - Search across finding titles and file paths.
  - Expandable findings: **Evidence** (matched code) · **SSVC** (scoring) · **PoE Context** · **Patch** (unified diff).
  - All free-text fields via contextual escaping — no `template.HTML()`.
  - Scope notice bar; `diffLines` template func for server-side diff rendering.

- [x] **T2** — XSS mitigations:
  - CSP: `default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'`.
  - XSS tests cover `justification`, `path`, and `matched_code` fields; `TestRenderContainsCSPHeader` added.

- [x] **T3** — Patch generation (`internal/report/patch.go`):
  - `GeneratePatch(ctx, client, finding)` — zero-shot unified diff via Ollama.
  - CVE+CVSS injected as few-shot prefix for BLOCK/HIGH findings with a CVE.
  - `extractDiff` handles fenced ` ```diff ` blocks and bare `---` output.

- [x] **T4** — Patch validation:
  - `ValidatePatch(patch)` uses `go-gitdiff`; returns `(status, scope, err)`.
  - `Finding.PatchStatus = "malformed"` when `gitdiff.Parse` errors (catches off-by-one hunk headers).
  - 4 tests: single-hunk OK, multi-hunk, multi-file, garbage input.

- [x] **T5** — Patch scope labels:
  - `single_hunk` / `multi_hunk` / `multi_file` computed from file + hunk counts in `ValidatePatch`.
  - `Finding.PatchScope` set; PatchEval reliability note rendered in Patch tab (~22% / ~12% / 0–7.7%).

- [x] **T6** — Suppression sidecar UI action:
  - Per-finding **ACK** button in report UI; toggles to ✓ when clicked.
  - Sticky bar at bottom shows count + **Download .zerotrust-suppressions.yaml** button.
  - JS Blob download generates YAML in `dedup.SidecarEntry` format, directly compatible with `LoadSidecar`.

**All report tests green · `go vet` clean · `make test` passes.**

---

### ML4.3 — End-to-End Integration + Final Delivery (8h)

- [ ] **T1** — Full pipeline run (3h):
  - `zerotrust scan ./tests/integration/spring-boot-app` with `--native` flag.
  - Path A + Path B findings both present in output.
  - Dedup merges cross-path duplicates correctly.
  - SSVC scoring applied; HTML report generated at `--report zerotrust-report.html`.
  - All 5 severity labels reachable; no silent drops.

- [ ] **T2** — Precision/recall vs G1 baseline (2h):
  - Run Path A only vs Path A+B on the Spring Boot test codebase.
  - Document improvement to `docs/benchmarks/final_eval.md`.

- [ ] **T3** — Performance benchmark (1.5h):
  - Wall-clock time on 5K LOC synthetic codebase (cold + warm scan).
  - Peak RSS memory. Log to `docs/benchmarks/performance.md`.

- [ ] **T4** — Final delivery (1.5h):
  - `CLAUDE.md` accurate; README present with quickstart.
  - `make build` · `make test` · `make demo` all pass clean.
  - `git status` clean; no uncommitted changes.

**Done when**: all four tasks above pass; `make test` green end-to-end.

---

> **Drop sequence** (execute only if Layer 4 falls behind schedule):
> 1. Gate 4 AST edit distance (T2) — saves 2h; 3-gate dedup still correct *(already done)*
> 2. SSVC live APIs → CVSS-only scoring (T3 partial) — saves 8h; document in report *(already done; NVD in buffer)*
> 3. Patch suggestions (ML4.2 T3–T6) — saves 12.5h; report shows findings only, no diffs *(already done — moot)*
