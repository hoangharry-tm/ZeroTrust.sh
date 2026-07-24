# ZeroTrust.sh — AI Codebase Security Scanner

Local, privacy-preserving CLI SAST vulnerability scanner. Performs full-codebase source security analysis across logic, semantic, and structural flaws. Single native Go binary — no Docker orchestration. **The database is the product**: scored findings are persisted to Postgres; there is no HTML/JSON report and no CLI progress renderer. An analyst queries the `findings`/`scan_runs` tables directly. A proper client UI is deferred until detection accuracy justifies the investment.

## Architecture

- **Orchestration & CLI (Go):** single binary, `cmd/zerotrust/` — parallel Deterministic/Reasoning dispatch, Dedup, Postgres persistence.
- **CPG engine:** `internal/cpg_engine/` wraps Joern (HTTP JSON API, subprocess or externally managed). Exposes a small `Graph` interface; the Joern DSL is generated from `.scala`/`.scala.tmpl` files under `internal/cpg_engine/queries/` via `go:embed` + `text/template` — never hand-built Go string concatenation. CPG graph reads can be backed by Postgres (`pkg/postgres`) once ingested, bypassing repeat Joern HTTP round-trips.
- **Deterministic (fast, rule-based):** OpenGrep + ast-grep pattern matching, Joern CPG taint analysis, LLM Verifier filters false positives.
- **Reasoning (semantic):** Heuristic Targeting (CPG-based surface selection + Trivy CVE enrichment + IDOR detection) → Contracts/DCC (structural safe/violation/inconclusive verdict, keyed primarily on the CPG's own cross-language taint-sanitizer signal, not source-text keywords; genuinely ambiguous cases get one scoped LLM yes/no question, default-to-violation on any failure) → Triage (lightweight LLM filter on what Contracts couldn't resolve) → Analysis (full LLM reasoning with SCL/CFP/AIP evidence injection, few-shot examples, self-consistency check on high-confidence findings, and a bounded CPG tool-calling loop — see below). One prompt strategy — no per-model tiers.
- **Tool/function calling (`pkg/llm`):** `Options.Tools`/`Message.ToolCalls` — both Ollama and OpenAI backends support it natively (own wire-shape conversions, not a lossy shared format). Used by Contracts' scoped escalation and Analysis's bounded investigation loop.
- **"Lite agentic" Analysis (`internal/semantic/analysis`):** when `Scanner.WithGraph` is set, each surface's LLM call may take up to `maxToolCalls` (4) tool round-trips against read-only CPG queries (`get_callers`/`get_callees`/`get_neighbours_at_depth`/`query_nodes_by_file`) before committing to a verdict, then one final tools-disabled call forces an answer if the cap is hit. Hard-capped and fully logged by design — the point is bounded, auditable investigation depth, not an open-ended ReAct loop.
- **LLM layer:** provider-agnostic (`pkg/llm`) — Ollama (default, local) or OpenAI-compatible API (`--llm-provider openai`). Adding a provider is a ~30-line file in `pkg/llm` plus one line in `llm.New`'s switch. `llm.New` wraps every provider with retry/backoff (`pkg/llm/retry.go`, ≤3 attempts, exponential + jitter) so a transient backend hiccup doesn't fail whatever finding/surface triggered it — never retries `ErrModelBlocked` or context cancellation. No circuit breaker: a scan is a single short-lived process, so there's no future request left for a breaker to protect once the retry budget's exhausted.
- **Ingestion:** Model Integrity Verifier (cosign/Sigstore) + Differential Indexer (Postgres content-hash cache) for incremental scans.
- **Dedup + SSVC scoring**, findings persisted to Postgres (`pkg/postgres`) — `--patch` still generates patch suggestions (`internal/patch`), stored as columns on the finding row rather than embedded in a report.

There is no Python worker anymore — it was fully removed (dead code, disconnected from the pipeline). CodeT5+/XGrammar/LangGraph are not part of this codebase; the classifier tier is a pure-Go heuristic (`taintGateClassify` in `internal/pipeline/reasoning.go`).

## Project Structure

```
cmd/zerotrust/            CLI entrypoint, flag parsing (flags.go), scan orchestration (main.go)
internal/
  config/                 Calibration Config (thresholds, batch sizes) — loaded from calibration.json
  cpg_engine/              Joern CPG engine: Graph interface + Client + query builders
    queries/               *.scala / *.scala.tmpl — the actual Joern DSL, one query per file
  pipeline/                Wires ingestion → Deterministic/Reasoning → dedup → Postgres persistence; module/scope partitioning
  ingestion/               miv/ (Model Integrity Verifier) · diffindex/ (Differential Indexer)
  scanner/                 gitleaks, osv, opengrep/
  semantic/                targeting/ · enrichment/ · contracts/ · crypto/ · triage/ · analysis/
  dedup/                   Dedup + SSVC confidence scoring
  report/                  HTML report + patch generation — unwired, not deleted (see "Deprecated" below)
  patch/                   Patch suggestion generation and validation — still active via --patch
  poe/                     Opt-in (--verify-poc) grey-box sandboxed PoC verification (Java/Python/JS-TS/Go)
  finding/                 Finding struct, shared across the whole pipeline
  output/                  CLI renderers (minimal / tree / TUI) — unwired, not deleted (see "Deprecated" below)
pkg/
  llm/                     Provider-agnostic LLM interface (Ollama, OpenAI)
  postgres/                Findings/scan-state store + CPG graph cache (GORM for CRUD tables, raw pgx pool for CPG bulk ingest)
docs/                      architecture.md · research-papers.md · engineering/ · rules/ · design/
godocs/                    Generated Go API reference (gomarkdoc) — regenerate via `go generate ./...`
site/                      Project website (GitHub Pages)
```

## CLI surface

`zerotrust scan [directory]` — no `--mode`, no `--offline`, no `--llm-mode`, no `--token-cap`, no `--native`/Docker flags. These existed at various points and were deliberately removed:
- Scan scope is fixed (no tiered mode) — every scan covers working modules + depth-2 neighbours.
- LLM calls always attempt network access; there is no "offline mode" toggle, since the LLM stage may legitimately be a hosted API now (`--llm-provider openai`).
- Prompting is a single best-effort strategy (see Reasoning above) — no small/mid/frontier tiers.
- There is no token budget cap or "Token Budget Controller" — it was already disabled/dead code before removal; nothing in the pipeline caps or suppresses findings for cost reasons.
- Docker orchestration was removed entirely from the Go binary. Users who want a container build/run one themselves.
- `--report`/`--json-report` no longer exist — see "Deprecated" below. `--db-url` (or `$DATABASE_URL`) is required instead.

See `--help` on the binary for the current, authoritative flag list — this file describes intent and architecture, not a flag reference that can drift.

## Deprecated: report generation & CLI renderer

`internal/report` (HTML), the JSON report path, and `internal/output`'s CLI renderer are unwired from the pipeline — the packages still exist (not deleted) but `cmd/zerotrust/main.go` no longer calls into them. A scan's only output now is rows in Postgres (`pkg/postgres`) plus structured logging (`build/zerotrust.log`, and stderr under `--verbose`). This was a deliberate call, not an oversight: a client UI is planned once detection accuracy is good enough to justify building one, and until then the database itself is the interface. If you're touching pipeline output, don't silently re-wire these — that's a decision for whoever builds the UI, not something to restore piecemeal.

## Known gaps (accepted, not blocking)

- **Sandbox PoC verification is grey-box, not build-from-source.** `internal/poe/` (opt-in via `--verify-poc --poe-artifact <path>`) packages a caller-supplied, already-built artifact (jar/bundled JS/Python script/native binary) into a minimal runtime image, boots it in a sandboxed Docker container (plain bridge network, not `--internal` — an internal network breaks host port-publishing on Docker Desktop; see `docs/architecture.md` for the confirmed trade-off), fires an LLM-crafted HTTP request at the route reaching the finding's sink, and grades the response. Covers Java, Python (Flask/FastAPI), JavaScript/TypeScript (Express), and Go (net/http/Gin/chi) route conventions. No artifact-freshness check exists yet — a stale artifact (not actually built from the scanned revision) will silently produce misleading results; this is a deliberate, documented follow-up, not solved today. Projects needing an external DB/service to boot fall back to `finding.PoEInconclusive`. Eligibility (minimum severity, supported languages) is declarative config (`poe_min_severity`/`poe_supported_languages` in `calibration.json`), not a hardcoded gate. See `docs/architecture.md` for the full design and the "no confidence downgrade on a failed/inconclusive attempt" rule.
- **Custom-library blind spot.** Taint source/sink detection is taxonomy-based (`internal/cpg_engine/taint.go`); a codebase using unrecognized custom wrappers around safe/unsafe APIs won't be caught by the deterministic layer and falls to LLM judgment. Fundamental to this class of tool, not something a rewrite fixes.
- **Scala query correctness is only verified at the string level in unit tests.** `internal/cpg_engine/joern_integration_test.go` (build-tagged `integration`) confirms Joern starts and responds, but no longer builds a real CPG or runs a real taint query (the Spring Boot fixture those tests depended on isn't checked into the repo) — run a manual end-to-end scan after touching anything under `queries/` or `internal/cpg_engine/http.go`'s stdout parsing, since unit tests alone missed a real parsing bug there (see `docs/architecture.md`'s `parseStdout` note).
- **CWE label imprecision on LLM-confirmed findings.** Observed during a real end-to-end smoke test: an obvious SQL injection (raw string concatenation into a `sqlite3` query) was correctly detected and confirmed exploitable, but labeled `CWE-918` (SSRF) instead of `CWE-89` (SQL injection) — Contracts' `Rulebook` matched the surface to the wrong CWE anchor before Analysis ever got a chance to reason about the code. This is a semantic-layer precision issue (rulebook anchor matching), not a plumbing bug — the finding itself was correctly surfaced, scored, and persisted. Not yet root-caused.
- **Dedup gates 3 and 4 are no-op stubs.** `internal/dedup/gates.go`'s `gate3` (embedding cosine similarity) and `gate4` (AST token edit distance) both immediately return their input unchanged — they were designed to call the Python worker, which was fully removed (see "no Python worker" above), and never got a Go replacement (`pkg/embedding`, `pkg/astdiff` don't exist yet). Only gate1 (exact key) and gate2 (code fingerprint) actually dedupe today. Practical effect: near-duplicate findings that differ in exact matched-code text or line number won't be merged — the same underlying issue can appear as multiple separate findings instead of one. Not blocking (no incorrect verdicts, just under-merging), but worth knowing before assuming dedup counts reflect true unique-issue counts.

## Token Optimization & Navigation Guidelines

- **Native Navigation:** Use native grep and line-range reading (`offset`/`limit`) instead of loading whole files.
- **Large Logs:** Pipe extensive terminal/command outputs through `mcp__headroom__headroom_compress` when context optimization is required.
