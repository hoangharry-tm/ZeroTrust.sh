# Design: ZeroTrust.sh Tech Lead Presentation Notebook

**Date:** 2026-06-08
**Output file:** `admin/product_analysis/notebooks/01_technical_deep_dive.ipynb`
**Delivery:** Live Jupyter run during tech lead meeting
**Depth:** Technical deep dive + approval-focused

---

## Approach

Single notebook with linked ToC and section anchors (Approach B). No file-switching mid-meeting. Final cell is an explicit approval ask.

---

## Cell Map (26 cells)

### Section 0 — Setup (cells 1–3)
- `[MD]` Title card: project name, presenter, date, meeting context
- `[MD]` Linked table of contents covering all 8 sections
- `[CODE]` Imports: `plotly.graph_objects`, `plotly.express`, `IPython.display`

### Section 1 — Problem Statement (cells 4–6)
- `[MD]` Section header
- `[MD]` AI agent adoption trend + 3 threat vectors (slopsquatting, prompt injection, security control bypass) with concrete examples
- `[CODE]` Plotly table: threat vector × existing tool coverage gap matrix

### Section 2 — Market Gap & Competitors (cells 7–9)
- `[MD]` Section header
- `[CODE]` Plotly heatmap: 9 tools × 6 capability columns from `comparison_matrix.md`; ZeroTrust.sh row highlighted
- `[MD]` 2-sentence gap summary

### Section 3 — Core Value Proposition (cells 10–11)
- `[MD]` Section header + one-sentence differentiator
- `[CODE]` Plotly table: 3-approach comparison matrix; Approach 2 row highlighted

### Section 4 — Architecture Walkthrough / Approach 2 (cells 12–15)
- `[MD]` Section header
- `[MD]` Mermaid diagram: File Input → AST Filter → LLM Verifier → HTML Report
- `[MD]` Stage 1 detail: Tree-sitter CST, YAML rule engine
- `[MD]` Stage 2 detail: Ollama HTTP API, qwen2.5-coder:7b, hardware config table

### Section 5 — Tech Stack Decisions (cells 16–18)
- `[MD]` Section header
- `[MD]` Go over Rust rationale (DX, official Ollama SDK, 2-month window, Rust rewrite post-MVP)
- `[CODE]` Plotly table: tech stack per component

### Section 6 — MVP Scope & Assumptions (cells 19–20)
- `[MD]` Section header
- `[CODE]` Plotly table: 12-row assumptions register, color-coded by status (red/amber/green); A-01, A-02, A-03 highlighted

### Section 7 — Risks (cells 21–23)
- `[MD]` Section header
- `[CODE]` Plotly scatter: risk matrix (x=Likelihood, y=Impact, bubble labels=risk IDs); R-04, R-02, R-10 prominent
- `[MD]` Callout block: R-04 (High/High, unresolved), R-02 (VRAM), R-10 (false negative liability)

### Section 8 — Decision Required (cells 24–26)
- `[MD]` Section header
- `[MD]` 3 approaches side-by-side (1 paragraph each) + explicit recommendation: Approach 2
- `[MD]` Open questions for tech lead + approval ask

---

## Constraints

- All data hardcoded from source docs — no external file reads (safe for live demo)
- Dark-themed Plotly throughout (`plotly_dark` template)
- Mermaid rendered via `IPython.display.HTML` with cdn script tag
- Source docs: `specs/proposals/README.md`, `approach_2_hybrid_llm.md`, `research/competitor_teardown/comparison_matrix.md`, `decisions/assumptions.md`, `decisions/risk_registry.md`
