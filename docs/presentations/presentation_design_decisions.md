# ZeroTrust.sh — Week 1 Presentation: Design Decisions Log

**Session date:** 2026-06-12
**Figma file:** ZeroTrust.sh — Week 1 Internship Presentation
**Presenter:** Tôn Minh Hoàng · VNG ZingPlay Studio

---

## Phase 0 — Research Findings

### R1: Milestone Data Extracted

| Goal | Plain English Name | Target | Status |
|---|---|---|---|
| G1 | Detection PoC | 2026-06-27 | In Progress |
| G2 | Intelligent Engine (Path A: CPG + Taint + LLM Verifier) | 2026-07-18 | Not Started |
| G3 | Agentic System (Path B: Three-Tier Cost Funnel) | 2026-08-01 | Not Started |
| G4 | Integration, Report & Demo | 2026-08-06 | Not Started |

**G1 key deliverables used in slides:**
- AI-specific Semgrep/ast-grep rules (MCP config injection, agent instruction file injection)
- Single cross-platform Go CLI binary
- Model Integrity Verifier (SHA256 at startup)
- Differential Indexer (80–95% repeat-scan cost reduction)

**G2 key deliverables:**
- Joern CPG pipeline (shared with Path B)
- Multi-language taint flow detection (10+ CWE classes)
- Python worker IPC boundary (NDJSON — reused by G3)
- LLM Verifier with XGrammar-constrained output (≥88% FP reduction target)

**G3 key deliverables:**
- CPG-based heuristic targeting (~5% of surfaces selected)
- CodeT5+ classifier gate (75–85% surfaces without LLM call)
- Threat Feature Extractor (LLM sees structured summaries, never raw code)
- Bounded ReAct loop (max 3 steps)

**G4 key deliverables:**
- Dedup + SSVC 5-tier scoring (BLOCK/HIGH/MEDIUM/LOW/SUPPRESSED)
- Self-contained HTML report with filter/sort controls and unified diff patches
- End-to-end demo on Python, Go, and Java vulnerable codebases

### R2: Design Research Findings

**Typography recommendation source:** Figma font pairings resource + TypeSmith + Steph Corrigan Design + TypeType 2025 reports

**Color palette source:** B2B SaaS color trends (Tentackles 2026) + minimalist palette research (media.io) + Notion/Linear visual reference

**Roadmap slide principles source:** Slideworks consultant-grade roadmap design research + Visme roadmap examples + PitchWorx 2025 presentation trends

### R3: Evidence Points Used in Slides

| Stat | Source | Used on Slide |
|---|---|---|
| 90% of devs use AI coding tools (2025) | DORA 2025 | Slide 02 |
| GitHub Copilot: 20M users, 90% Fortune 100 | TechCrunch Jul 2025 | Slide 02 |
| 45% of AI-generated code has security flaws | Veracode 2025 GenAI Report | Slide 03 |
| AI code has 2.74× more vulnerabilities than human code | Veracode 2025 | Slide 03 |
| 1 in 5 AI-suggested packages doesn't exist (576K samples) | FOSSA / Trend Micro | Slide 03 |
| CVE-2025-54135 (CVSS 8.6) — RCE via MCP config | Tenable / Security Online | Slide 03 |
| AI security market: $34B (2025) → $213B (2034) | Fortune Business Insights | Slide 09 |
| Developer trust in AI output: 70% → 33% (2023→2025) | Uvik 2025 | Context only |

---

## Phase 1 — Design System

### 1.1 Color Palette

| Role | Hex | Name | Rationale |
|---|---|---|---|
| Background primary | `#F7F4EF` | Warm Parchment | Off-white with warm undertone — eliminates harshness on projection, signals premium intent |
| Background secondary | `#EDE8DF` | Linen | Deeper warm neutral for cards, panels, code containers — depth without introducing color |
| Text primary | `#1C1917` | Warm Charcoal | Near-black with brown undertone; WCAG AA compliant on both backgrounds |
| Text secondary | `#78716C` | Stone | Warm mid-gray for captions, labels, de-emphasized copy; maintains palette temperature |
| Accent | `#C2410C` | Ember Orange | Deep burnished orange-red; earns security-tool alert connotation without being alarming. **One element per slide maximum.** |
| Signal (optional) | `#0C4A6E` | Ink Blue | Deep navy for pass/confirmed states in diagrams only; ≤10% slide surface |

**Usage ratio:** ~70% Parchment+Linen · ~25% Charcoal+Stone · ~5% Ember Orange

**Decision rationale:** Warm minimalism avoids cold enterprise blue-gray (reads as "sterile vendor deck") and punchy startup red-black (reads as "alarming, not professional"). The parchment base signals deliberate design intent; the ember accent earns the security-risk semantic association without triggering alert fatigue.

### 1.2 Typography Scale

| Level | Font | Weight | Size | Usage Rule |
|---|---|---|---|---|
| Display | Inter | ExtraBold 800 | 64–80px | ≤4 words, hero moments only |
| Headline | Inter | SemiBold 600 | 36–44px | Slide titles, section labels — one idea per line |
| Body | Figtree | Regular 400 / Medium 500 for emphasis | 18–24px | Supporting copy, bullets, data labels |
| Code accent | JetBrains Mono | Regular 400 | 16px | Technical strings: file paths, CVE IDs, SHA hashes, CLI commands |

**Pairing rationale:** Inter (geometric, precision-engineered for screens) reads as the tool's technical credibility. Figtree (humanist rounded terminals, 2022 Google Fonts release) reads as approachable and warm. The contrast between authority (headline) and warmth (body) mirrors the product's dual identity: rigorous security tool, designed for working developers. All three fonts are Google Fonts native in Figma — no import required.

**Decision: single-family display + headline (Inter).** Using one family at two weights for the top two tiers signals restraint and discipline — appropriate for a security tool brand. A second display face would introduce decorative complexity that fights the "precision instrument" message.

### 1.3 Layout Grid

- **Frame size:** 1920 × 1080 px (16:9)
- **Margins:** 96px all four sides
- **Column grid:** 12 columns · 32px gutter
- **Content zones:**
  - Header zone: 0–120px (section tag, slide label in Figtree 14px Stone)
  - Main content zone: 120–936px (primary visual + copy)
  - Footer zone: 936–1080px (slide counter `01 / 10`, presenter name)

**Decision: 96px margins (5% of frame width).** This is larger than standard presentation templates (typically 64px). The extra margin enforces the "breathing room is content" principle — on a projected surface, oversized margins read as confidence, not waste.

### 1.4 Spacing Tokens

| Token | Value | Applied to |
|---|---|---|
| xs | 8px | Icon-to-label gaps, inline spacing |
| sm | 16px | Headline-to-body gap |
| md | 32px | Between content blocks on the same slide |
| lg | 64px | Major section separation, visual breathing room |

### 1.5 Recurring Visual Motifs

**Motif 1 — Ember Orange left-edge rule (4px vertical line)**
Present on every content slide (not the cover or end slide). Anchors the left edge of the content column and conditions the eye to associate Ember Orange with "signal worth reading" before it appears at full intensity on key data points. Structural purpose: provides a consistent entry point for the eye scanning left-to-right.

**Motif 2 — Slide counter glyph**
Bottom-right corner: `01 / 10` in Figtree Regular 14px Stone. Typographic furniture — invisible to the audience at reading distance, present for the presenter's orientation. Creates a quiet rhythm across all frames without introducing design noise.

---

## Phase 2 — Slide Architecture

**Total slides:** 10
**Narrative arc:** SCQA (Situation → Complication → implied Question → Answer/Resolution)

| Slide | Title | Section | Purpose |
|---|---|---|---|
| 01 | Cover | A — Introduction | Make the director want to hear this |
| 02 | The Situation | B — Problem setup | Establish the scale of AI adoption |
| 03 | The Problem | B — Problem core | Surface the vulnerability gap |
| 04 | The Gap | C — Landscape | Show where no competitor sits |
| 05 | How It Works | C/D bridge | Brief architecture — 2 paths, local, no upload |
| 06 | Development Roadmap | D — Roadmap | Visual timeline: 3 phases with dates |
| 07 | Phase 1: Detection PoC | E — Milestone Briefs | What's happening right now |
| 08 | Phases 2 & 3 | E — Milestone Briefs | What comes next (credible, not exhaustive) |
| 09 | Vision | F — Conclusion | The outcome, the market, the promise |
| 10 | End | — | Clean close, contact info |

### Creative decisions by slide

**Slide 01 (Cover):** Tagline chosen: *"AI writes code. We audit it."* — 6 words, no jargon, immediately states the relationship between the problem and the tool. Rejected alternatives were either too long or required domain knowledge to parse.

**Slide 02 (Situation):** Two-column layout with large typographic numbers (Ember Orange). Deliberate choice: lead with scale, not with risk. The director first understands *how many* developers are affected before hearing that the code they're shipping has problems.

**Slide 03 (Problem):** Centered composition with one dominant stat (45%). Slopsquatting and config file injection are listed as specific threat classes — not generic "AI risks" — because naming concrete CVEs (CVE-2025-54135, CVSS 8.6) is the difference between "interesting concern" and "recognized attack surface with real CVEs."

**Slide 04 (Gap):** 2×2 positioning matrix chosen over comparison table. Decision rationale: a table with 5 competitors and 6 features has 30 data points competing for 8 seconds of attention. A 2×2 with one visible empty quadrant communicates the market gap in 3 seconds. The empty space *is* the message.

**Slide 05 (How It Works):** Three-column card layout for the three key capabilities. Kept deliberately light — the audience is directors, not engineers. The technical depth (CPG, XGrammar) is omitted; only the outcome properties (local, no LLM call for 75–85% of surfaces, no upload) are surfaced.

**Slide 06 (Roadmap):** Horizontal timeline with filled (active) vs. outlined (planned) phase blocks. Plain English phase names used throughout — "Detection PoC", "Intelligent Engine", "Agentic System" — not "Approach 1/2/3." Ember Orange fills Phase 1 block only (the "now" visual anchor).

**Slide 07 (Detection PoC):** Only slide with a short bullet list (4 items max). The 4 deliverables selected are the ones with the strongest directorial-relevance: novel attack surface covered (config injection), local execution proof (no upload), tamper-resistant model (supply chain protection), and efficiency claim (80–95% cost reduction). Technical deliverables with no executive analogue (canonical finding schema, IPC boundary) are omitted.

**Slide 08 (Phases 2 & 3):** Two side-by-side cards. Decision: one slide covers both future phases rather than two separate slides. Directors care about the current phase; future phases need to feel *credible*, not exhaustive. Three deliverables per card is the maximum that communicates competence without overwhelming.

**Slide 09 (Vision):** Typography-forward, single composition, maximum whitespace. The CLI command (`zerotrust scan ./my-project`) is typeset in JetBrains Mono Ember Orange — a deliberate genre signal that says "this is a real tool, not a concept." The promise statement ("By August 2026...") is placed last — it earns its position by following the market data, not preceding it.

**Slide 10 (End):** Mirror of the cover — same visual grammar, same font hierarchy. Visual bookend that signals completion without requiring a "Thank you" title. GitHub URL included as a signal of open-source commitment.

---

## Phase 3 — Figma Execution Log

**Completed: 2026-06-12**

- [x] `figma:figma-use` skill invoked before any Figma call
- [x] File created: "ZeroTrust.sh — Week 1 Internship Presentation" — key: `mZRqA21ycHSGRjHfE6y6Tq`
- [x] `_Design System` page: 6 color styles, 5 text styles, visual swatches + type samples
- [x] `Presentation` page: all 10 frames built and named in sequence
- [x] Visual hierarchy audit completed — all 10 slides passed all 3 questions
- [x] Delivery check completed

**Figma file URL:** https://www.figma.com/design/mZRqA21ycHSGRjHfE6y6Tq

**Build order:**
- Call 1: Pages + design system (color/text styles)
- Call 2: Slides 01, 10 (Group A — cover + end)
- Call 3: Slides 02, 03 (Group B — situation + problem)
- Call 4: Slides 04, 05 (Group B/C — landscape + how it works)
- Call 5: Slides 06, 07, 08 (Group C — roadmap + milestone briefs)
- Call 6: Slide 09 (Group D — vision)
- Call 7: _Design System page visual content

---

## Phase 4 — Delivery Check

**Completed: 2026-06-12 — ALL CHECKS PASSED**

**Content completeness:**
- [x] Project name and tagline on cover ("ZeroTrust.sh" + "AI writes code. We audit it.")
- [x] Problem analysis grounded in real evidence (45% Veracode, 1-in-5 slopsquatting, CVE-2025-54135 CVSS 8.6)
- [x] Landscape slide shows competitor gap — 2×2 matrix, ZeroTrust.sh alone in bottom-right quadrant
- [x] Roadmap shows all 3 phases with target dates (Jun 27 / Jul 18 / Aug 6)
- [x] Milestone briefs cover what's being built and when (slides 07 + 08)
- [x] Conclusion communicates product vision AND market opportunity ($34B→$213B, three unique positions)

**Design quality:**
- [x] All slides use only Phase 1 palette colors
- [x] All text uses only the 3 type scale levels (Display/Headline/Body + Code accent)
- [x] No slide has more than 4 bullet points (slide 07 has exactly 4)
- [x] All content slides (02–09) have the Ember Orange left-edge rule motif
- [x] Roadmap slide decodable without technical background — phase names use plain English
- [x] Vision slide (09) is visually distinct — JetBrains Mono CLI command as hero, maximum whitespace

**Figma file hygiene:**
- [x] All frames named correctly: 01 — Cover … 10 — End
- [x] `_Design System` page exists with color styles, text styles, swatches, type scale
- [x] No detached instances or broken components (no component instances used — all primitives)
- [x] File named "ZeroTrust.sh — Week 1 Internship Presentation"
