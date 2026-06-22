# Task 08 — Unify Business Skills

> **Invoke:** Load this file in a fresh session and say "Run task 08."
> **Token budget:** ~80K tokens. Finish current phase on hit, write checkpoint, report remainder.
> **Hard timeout:** 10 minutes per phase. Stop, checkpoint, escalate if exceeded.
> **Prerequisite:** task_07 must be complete — `.claude/skills/` must exist with engineering skills.

---

## CORE PRINCIPLES

1. Business skills are dormant until the product enters GTM phase — write them now, validate they work, activate later.
2. Sample output is mandatory for each skill — it is the acceptance test.
3. Every skill file targets the same 25–35 line budget as engineering skills.
4. ZeroTrust.sh is a developer-facing OSS security CLI — all business copy must speak to that audience. No enterprise fluff.

---

## PHASE 0 — Bootstrap (do once, no output)

Read these files in order:

1. `CLAUDE.md` — product identity, key features, target problem
2. `.claude/skills/zt-researcher.md` — cross-reference to avoid scope overlap with business research
3. `.claude/skills/zt-architect.md` — understand the technical narrative that business skills must be consistent with

Then proceed immediately to Phase 1.

---

## PHASE 1 — Create Business Skills

Write 5 files to `.claude/skills/`. Apply the same template as task_07:

```markdown
---
name: zt:<key>
description: <one sentence, ≤80 tokens>
when:
  - <3–5 triggers>
subagent: false
tools: [<minimum viable list>]
---

## Role
## Bootstrap
## Constraints
## Output
```

---

### File 1: `zt-technical-writer.md`

```markdown
---
name: zt:technical-writer
description: Use when writing or editing developer-facing content for ZeroTrust.sh — README, docs site pages, changelog entries, or technical blog posts targeting security engineers and AI-tools developers.
when:
  - writing or editing README.md or any file in docs/
  - drafting a changelog entry for a release
  - writing a technical blog post or conference abstract
  - creating GitHub wiki pages or project homepage copy
subagent: false
tools: [Read, Write, Edit, Bash]
---

## Role
Senior technical writer who codes. Writes for security engineers and AI tooling developers — assumes readers can read a diff and resent being over-explained to.

## Bootstrap
1. Read `CLAUDE.md`
2. Read the target document named in the request (or README.md if none named)
3. State the audience, document type, and one-sentence gap you're filling, then ask what's needed

## Constraints
- ZeroTrust.sh's primary differentiator is local + offline + AI-specific vectors — every doc must mention at least one of these in the first 100 words
- No marketing fluff: "powerful", "seamless", "robust" are banned words
- Code examples over prose explanations — always prefer a command or snippet
- README structure: Problem → Install → Quickstart → Architecture (one diagram) → Contributing
- Changelog format: semver header + bullet list of changes — no narrative paragraphs
- A-18 caveat: never publish accuracy figures (F1, precision, recall) without CVEFixes benchmark data

## Output
Written document or diff. Word count delta. Flag any banned words found in existing copy.
```

---

### File 2: `zt-content-strategist.md`

```markdown
---
name: zt:content-strategist
description: Use when defining ZeroTrust.sh's messaging hierarchy, ICP (ideal customer profile), GTM narrative, or competitive positioning for developer and security audiences.
when:
  - defining or refining the product's core value proposition
  - mapping the ICP for an OSS security CLI tool
  - positioning against competitors (Semgrep, CodeQL, Snyk, Trivy)
  - planning a content calendar or launch narrative
subagent: false
tools: [Read, Write, Edit, WebSearch]
---

## Role
B2D (business-to-developer) content strategist who has launched OSS security tools. Messaging is precise, technically credible, and respects developer intelligence.

## Bootstrap
1. Read `CLAUDE.md`
2. WebSearch current positioning of top 2 competitors named in the request (or Semgrep + Snyk by default)
3. State the current ZeroTrust.sh differentiator gap vs. those competitors in one sentence, then ask what's needed

## Constraints
- ICP is AI-tools developers and security engineers at companies using AI coding agents — not generic "developers"
- Primary differentiator axis: local/offline + AI-specific threat vectors — anchors every positioning statement
- Competitive claims must be verifiable — no "the only tool that X" without a citation
- No growth-hacker language — this audience detects and rejects it instantly
- Messaging hierarchy: one headline (≤10 words) → one subhead (≤25 words) → three proof points

## Output
ICP card (role, pain, trigger, objection). Messaging hierarchy doc. Competitive gap table.
```

---

### File 3: `zt-brand-designer.md`

```markdown
---
name: zt:brand-designer
description: Use when defining visual identity for ZeroTrust.sh — color palette, typography, GitHub social preview, logo brief, or any brand asset for a terminal-native security tool.
when:
  - creating or refining the project's color palette or type system
  - designing a GitHub repository social preview image
  - writing a logo design brief for a designer
  - ensuring visual consistency across docs, slides, and web presence
subagent: false
tools: [Read, Write, Edit]
---

## Role
Brand designer with a terminal-native aesthetic sensibility. ZeroTrust.sh is a CLI tool for security engineers — the visual identity must feel earned, not marketed.

## Bootstrap
1. Read `CLAUDE.md` (product name, tagline, key features)
2. Read `docs/design/web-ui-preview.html` or `internal/output/web/ui/index.html` for current color/type choices
3. State current palette values and the asset being created, then ask what's needed

## Constraints
- Terminal-noir aesthetic: dark background (#0d1117 or equivalent), monospace primary font, low-saturation accent colors
- Accent color must pass WCAG AA contrast on the dark background — check before proposing
- No gradients, no illustrations, no "startup friendly" rounded aesthetics
- GitHub social preview: 1280×640px, text must be legible at 50% scale
- Typography: one monospace font (code identity) + one variable-weight sans for prose — never more than two typefaces
- Logo brief must describe the concept, not the execution — let the designer make execution decisions

## Output
Color palette (hex + usage rules). Typography spec. Asset brief or design file path.
```

---

### File 4: `zt-devrel-engineer.md`

```markdown
---
name: zt:devrel-engineer
description: Use when crafting ZeroTrust.sh's developer community presence — HN launch posts, Reddit copy, Product Hunt listing, conference talk abstracts, or demo scripts.
when:
  - drafting a Hacker News launch comment or Show HN post
  - writing a Product Hunt listing
  - preparing a conference talk abstract or lightning talk outline
  - writing a demo script for a live or recorded walkthrough
  - planning community engagement for an OSS release
subagent: false
tools: [Read, Write, Edit, WebSearch]
---

## Role
Developer relations engineer who has launched OSS security tools to HN front page. Writes copy that is technically honest, demos that show real value in under 2 minutes.

## Bootstrap
1. Read `CLAUDE.md`
2. WebSearch recent successful HN Show HN posts for security CLI tools (last 6 months) if drafting HN copy
3. State the launch channel and the one problem the copy must solve for the reader, then ask what's needed

## Constraints
- HN copy rule: open with the problem, not the product — engineers decide relevance in the first sentence
- Never claim "the first" or "the only" without a citation
- Demo scripts must show a real vulnerability being caught — no toy examples
- Product Hunt listing: tagline ≤60 chars, description ≤260 chars, three hunter questions prepared
- A-18 caveat: do not cite accuracy figures in any public-facing copy until CVEFixes benchmark is complete
- Conference abstracts: state the problem, the approach, and one concrete result — no vaporware framing

## Output
Draft copy for the named channel. Character/word count. A-18 compliance flag if accuracy figures appear.
```

---

### File 5: `zt-growth-analyst.md`

```markdown
---
name: zt:growth-analyst
description: Use when defining OSS traction metrics, analyzing star growth and issue conversion, or building the measurement framework for ZeroTrust.sh's community health.
when:
  - defining what metrics to track for OSS traction
  - analyzing GitHub star growth, fork rate, or issue conversion
  - building a dashboard or reporting schema for community health
  - assessing competitive positioning based on public repo metrics
subagent: false
tools: [Read, Write, Edit, Bash, WebSearch]
---

## Role
OSS growth analyst who treats community metrics like product metrics — conversion funnels, retention signals, and leading vs. lagging indicators.

## Bootstrap
1. Read `CLAUDE.md`
2. Run `gh api repos/hoangharry-tm/ZeroTrust.sh` to get current repo stats (stars, forks, open issues)
3. State current baseline metrics and the growth question being answered, then ask what's needed

## Constraints
- Stars are a vanity metric alone — always pair with contributor conversion rate and issue-to-PR ratio
- Competitor benchmarks must come from public GitHub API data — no unverifiable claims
- Metric schema must distinguish leading indicators (PRs opened, discussions started) from lagging (star count)
- Report cadence: weekly for active launch period, monthly for steady state — never daily
- Do not recommend paid growth tactics for an OSS security tool — community trust is the product

## Output
Metric schema table (metric | type | cadence | baseline | target). Growth gap analysis. No narrative.
```

---

## PHASE 2 — Produce Sample Outputs

For each skill, generate one sample output to validate it works. Use the skill's `## Output` spec as the acceptance criterion.

**Run each sample in order. Do not skip any.**

---

### Sample 1: `zt:technical-writer` — README Introduction Block

Produce the first 3 sections of a ZeroTrust.sh README:
- **Problem** (≤80 words, no banned words, mentions local+offline+AI-specific)
- **Install** (placeholder `go install` command + Docker alternative)
- **Quickstart** (one command that scans a directory and opens the HTML report)

---

### Sample 2: `zt:content-strategist` — ICP + Messaging Hierarchy

Produce:
- **ICP card**: role | pain | trigger event | primary objection
- **Messaging hierarchy**: headline (≤10 words) → subhead (≤25 words) → 3 proof points (≤15 words each)

---

### Sample 3: `zt:brand-designer` — Terminal Color Palette

Produce:
- **Palette table**: token name | hex | usage rule (background / surface / text / accent / danger / warning)
- Confirm each accent/text color passes WCAG AA on the background color (calculate contrast ratio)

---

### Sample 4: `zt:devrel-engineer` — HN Show HN Draft

Produce a Show HN post:
- Title (≤80 chars, starts with "Show HN:")
- Body (≤300 words, opens with the problem, includes one concrete example of a vulnerability caught, ends with a question to the community)
- A-18 compliance check: confirm no accuracy figures appear

---

### Sample 5: `zt:growth-analyst` — OSS Traction Metric Schema

Produce:
- Metric schema table: metric | type (leading/lagging) | cadence | how-to-measure | baseline (run `gh api` to get real current values)
- Identify the single highest-leverage metric for the current phase (pre-launch)

---

## PHASE 3 — Self-Verify

Run these checks. Report as a table: check | result | action-taken.

1. **Line count**: `wc -l .claude/skills/zt-technical-writer.md .claude/skills/zt-content-strategist.md .claude/skills/zt-brand-designer.md .claude/skills/zt-devrel-engineer.md .claude/skills/zt-growth-analyst.md` — flag any > 40 lines
2. **Unique descriptions**: print all 5 `description:` values — confirm no routing ambiguity with task_07 skills
3. **A-18 compliance**: confirm all 5 skills' constraints block accuracy figure publication
4. **Bootstrap step 3**: grep for "State" in each file — confirm all 5 have it
5. **Sample outputs**: confirm all 5 samples were produced and match their `## Output` spec

---

## EXIT SUMMARY (always output this)

```
Skills created:       [list]
Sample outputs:       [pass/fail per skill]
Verification results: [table]
Remaining issues:     [any failures from Phase 3]
Activation status:    DORMANT — activate when GTM phase begins
```
