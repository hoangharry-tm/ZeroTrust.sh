# 01: Approaches to Problem Statements & Proposal Defense

## Presentation order

1. **Problem statement** → `CLAUDE.md`
   Synthesize: the AI agent adoption trend, the 3 core threat vectors (slopsquatting, prompt injection, security control bypass), and why existing tools miss them.

2. **Market gap & competitors** → `research/competitor_teardown/comparison_matrix.md` + `teardowns/semgrep.md`, `snyk.md`, `coderabbit.md`, `trufflehog.md`
   Synthesize: the 9-tool × 23-feature matrix — focus on the "local execution" and "AI-specific threat" columns where all competitors show gaps.

3. **Core value proposition** → `specs/proposals/README.md`
   Synthesize: the one-sentence differentiator (local-only + AI-threat-aware + agent-loop native) and the 16-column comparison matrix showing why Approach 2 is recommended.

4. **Architecture walkthrough** → `specs/proposals/README.md` + `specs/proposals/approach_2_hybrid_llm.md`
   Synthesize: the **two-path parallel design** — Path A (fast AST/Semgrep rules) runs in parallel with Path B (independent LLM semantic scan of high-risk surfaces). Neither gates the other. Both feed a shared deduplication layer. Emphasize: this is NOT a sequential pipeline — a vulnerability missed by Path A is still visible to Path B. Include the architecture diagram from CLAUDE.md.

5. **Tech stack decisions & rationale** → `specs/proposals/tech_stack_analysis.md`
   Synthesize: Go over Rust rationale (DX, official Ollama SDK, 2-month window), Tree-sitter grammar coverage for MVP languages, Ollama/qwen2.5-coder:7b model selection.

6. **MVP scope & assumptions** → `decisions/assumptions.md`
   Synthesize: the 12 assumptions register — highlight which are Unvalidated (A-01 privacy tradeoff, A-02 hardware, A-03 LLM accuracy) as open questions for the tech lead.

7. **Risks & mitigations** → `decisions/risk_registry.md`
   Synthesize: lead with R-04 (safety gate bypass unresolved, High/High), R-02 (VRAM ceiling, Medium/Critical), R-10 (false negative liability, Medium/Critical) — these are the 3 the tech lead must weigh in on.
