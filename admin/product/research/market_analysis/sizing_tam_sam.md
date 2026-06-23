# Market Sizing Methodology — ZeroTrust.sh

> **Document type:** Research & analysis only. No product decisions are made here.  
> **Compiled:** June 2026  
> **Critical disclaimer:** This is a bottom-up estimate based on publicly available data assembled through desk research. These figures are hypotheses constructed from secondary data sources and should not be treated as validated revenue projections. All inputs should be re-verified before use in fundraising, business planning, or investor materials. Estimates marked as "(estimate)" or "(unverified)" are particularly uncertain.

---

## Table of Contents

1. [Sizing Approach](#1-sizing-approach)
2. [Input Data: Global Developer Population](#2-input-data-global-developer-population)
3. [Input Data: AI Tool Adoption Rates](#3-input-data-ai-tool-adoption-rates)
4. [Input Data: Security Tooling Spend](#4-input-data-security-tooling-spend)
5. [Total Addressable Market (TAM)](#5-total-addressable-market-tam)
6. [Serviceable Addressable Market (SAM)](#6-serviceable-addressable-market-sam)
7. [Serviceable Obtainable Market (SOM)](#7-serviceable-obtainable-market-som)
8. [Comparable OSS Security Tool Adoption Benchmarks](#8-comparable-oss-security-tool-adoption-benchmarks)
9. [Sensitivity Analysis](#9-sensitivity-analysis)
10. [Key Assumptions and Risks](#10-key-assumptions-and-risks)

---

## 1. Sizing Approach

This analysis uses a **bottom-up segmentation approach**:

```
TAM = Total developers using AI coding tools × average security tooling spend per developer per year
SAM = TAM × fraction with privacy/data-sovereignty requirements
SOM = SAM × realistic Year 1–3 market capture rate (benchmarked against comparable OSS tools)
```

Three scenarios are modeled: conservative, base, and optimistic. The base case uses median estimates; conservative and optimistic cases use lower/upper bounds on the key input variables.

All monetary figures are in USD unless otherwise noted.

---

## 2. Input Data: Global Developer Population

### Published Figures (June 2026)

| Source | Estimate | Methodology | Date |
|--------|----------|-------------|------|
| SlashData Global Developer Population Report 2025 | 47.2 million total developers | Includes GitHub, Stack Overflow users + employment stats (US, EU) | 2025 |
| Evans Data Corp Worldwide Developer Population | ~27–29 million professional developers | Professional developers only; narrower methodology | 2024–2026 |
| GitHub Octoverse 2025 | 180 million+ GitHub accounts | Includes all GitHub users; not all are active developers | 2025 |
| Stack Overflow Developer Survey 2025 | ~65,000 survey respondents (sample) | Self-selected sample; primary data for developer demographics | 2025 |

**Working figure for this analysis:** 47 million total developers (SlashData 2025) as the broadest credible estimate. The Evans Data figure (~27M professional developers) is used as the conservative lower bound.

Note: The discrepancy between sources (27M vs. 47M) reflects methodological differences, not errors. Evans Data counts full-time professional developers; SlashData includes hobbyists, students, and part-time developers who actively write code.

(Source: [SlashData 2025](https://www.slashdata.co/post/global-developer-population-trends-2025-how-many-developers-are-there), [Evans Data](https://evansdata.com/press/viewRelease.php?pressID=365))

---

## 3. Input Data: AI Tool Adoption Rates

### Survey Data Convergence

| Source | Metric | Value | Date |
|--------|--------|-------|------|
| Stack Overflow Developer Survey 2025 | Developers using or planning to use AI tools | 84% | 2025 |
| JetBrains State of Developer Ecosystem 2025 | Developers regularly using AI tools | 85% | 2025 |
| JetBrains (January 2026 update) | Developers using at least one AI tool at work | 90% | Jan 2026 |
| Vibe Coding Statistics 2026 | Developers using AI-powered coding tools daily | 72% | 2026 |

**Working figure:** 84% of developers use AI coding tools (Stack Overflow 2025 — largest sample size; most methodologically transparent).

**Developers actively using AI agents for substantial code generation** (a stricter criterion relevant to ZeroTrust.sh's threat model):
- JetBrains 2025: 62% rely on at least one AI coding assistant as their primary tool
- GitHub Copilot: 4.7 million paid subscribers as of January 2026; 20 million all-time users
- Cursor: 7 million+ MAU as of 2026; 1 million DAU

**Working figure for "active AI code generation" users:** 62% of total developers (JetBrains) as base case.

---

## 4. Input Data: Security Tooling Spend

### Application Security Market Size

| Source | Market Size | Year | CAGR |
|--------|-------------|------|------|
| Mordor Intelligence | $13.61B (2025) → $14.83B (2026) | 2025 | ~9% |
| ResearchNester | $14.12B (2025) → $43.08B (2035) | 2025 | ~12% |
| Straits Research | $13.87B (2025) → $47.38B (2033) | 2025 | 16.6% |
| MarketsandMarkets (SAST/DAST only) | $1.83B (2025) → $7.6B (2031) | 2025 | 26.7% |

**Working figure:** Application security market = ~$14B in 2025. SAST/DAST subsegment = ~$1.83B in 2025.

### Per-Developer Security Spend (Derived Estimate)

Direct per-developer security spend data from Gartner/IDC was not accessible via public sources. The following is a derived estimate:

```
SAST market (2025) = $1.83B
Professional developer population = 27–47M
Implied per-developer SAST spend = $1.83B ÷ 35M (midpoint) ≈ $52/developer/year
```

Validation checks:
- Semgrep Pro: $35/contributor/month = $420/dev/year (paying users only; many use free tier)
- Snyk Team: $25/dev/month = $300/dev/year (paid tier)
- SonarQube Community: $0 (free tier dominant)
- Blended average across paying and non-paying developers likely in $20–60/dev/year range

**Working figure for per-developer security tooling spend:** $40/developer/year (conservative), $60/developer/year (base), $100/developer/year (optimistic). These are rough estimates; Gartner/IDC primary data would improve this significantly.

---

## 5. Total Addressable Market (TAM)

**Definition:** The total global market for a security scanner targeting developers who use AI coding tools.

### TAM Calculation

```
TAM = (Total developers × AI tool adoption rate) × per-developer security spend
```

| Scenario | Developer Base | AI Adoption | Per-Dev Spend | TAM |
|----------|---------------|-------------|---------------|-----|
| Conservative | 27M (Evans Data) | 62% | $40/year | ~$670M |
| Base | 47M (SlashData) | 84% | $60/year | ~$2.4B |
| Optimistic | 47M (SlashData) | 90% | $100/year | ~$4.2B |

**Base case TAM: ~$2.4 billion annually**

Note: This TAM represents the full addressable market for a tool that could serve every AI-coding-tool-using developer globally. It does not account for the specific niche positioning of ZeroTrust.sh (local/offline focus); that narrowing is captured in SAM.

**Alternative top-down validation:**
- Total application security market: ~$14B (2025)
- SAST/static analysis subsegment: ~$1.83B (2025)
- AI-augmented developer tools are ~62–84% of developers
- AI-specific SAST as a sub-sub-segment is *smaller* than the total SAST market
- TAM ceiling from this perspective: $1.83B × (fraction that applies to AI-specific tooling) — likely $200M–$800M at this stage of market formation

The two approaches bracket a range of approximately **$500M–$2.4B** for the TAM. The bottom-up approach ($2.4B) is more generous; the top-down approach ($200M–$800M) is more conservative for the specific AI-code-security niche.

---

## 6. Serviceable Addressable Market (SAM)

**Definition:** The subset of TAM that ZeroTrust.sh can realistically serve given its architectural constraints and initial positioning (local/offline, AI-specific threat detection).

### SAM Narrowing Factors

**Factor 1: Developers with data sovereignty / privacy requirements**

This is the defining constraint. ZeroTrust.sh's local-only architecture is a requirement for some organizations and a preference for others.

Published data on data sovereignty requirements:
- EU GDPR: ~500M EU citizens; EU-based companies with GDPR obligations include a large fraction of European developers
- Financial services developers: ~10–15% of enterprise developer population subject to FINRA, PCI DSS, SOX (estimate)
- Healthcare developers: ~8–12% of enterprise developers subject to HIPAA (estimate; no direct source found for developer-specific figure)
- Defense contractors (CMMC): ~5% of US enterprise developers (estimate)
- EU-regulated enterprise (GDPR strict interpretation): significant fraction of EU market

A conservative estimate: 20–30% of enterprise developers have policy requirements that create a *preference or requirement* for local tooling. (This is an estimate derived from the regulatory landscape; no direct survey data was found.)

**Factor 2: Developers concerned about AI-generated code security**

Stack Overflow 2025: Trust in AI-generated code at 33% (down from 43% in 2024). This represents the fraction that is actively concerned — but "concern" does not equal "budget" or "action."

Among the 84% of developers using AI tools, the subset that (a) uses AI tools *and* (b) is actively concerned enough to add a security scanning step to their workflow is smaller. No direct data was found; a reasonable estimate is 15–25% of AI tool users, based on the security maturity proxy (only ~20% of developers in small/mid-size companies have dedicated security tooling beyond npm audit/Dependabot, per community estimates).

### SAM Calculation

```
SAM = TAM × (fraction with privacy requirements OR active security concern)
```

Using an inclusive OR:
- Privacy requirement (enterprise): ~25% of enterprise developers
- Active security concern (all developers): ~20% of AI tool users
- Overlap is significant; combined unique fraction ≈ 25–35% of TAM

| Scenario | TAM | SAM Fraction | SAM |
|----------|-----|-------------|-----|
| Conservative | $670M | 20% | ~$134M |
| Base | $2.4B | 27% | ~$648M |
| Optimistic | $4.2B | 35% | ~$1.47B |

**Base case SAM: ~$650M annually**

Note: This SAM includes both paying and non-paying users. An open-source model would convert a small fraction of this population to revenue-generating customers. This is further addressed in SOM.

---

## 7. Serviceable Obtainable Market (SOM)

**Definition:** The portion of SAM that ZeroTrust.sh could realistically capture in Years 1–3, given its stage, resources, and competitive dynamics.

### SOM Benchmarking Approach

Rather than applying an arbitrary percentage to SAM, this section benchmarks against comparable open-source security tools at Year 1–3 of their adoption curves.

(See Section 8 for detailed benchmark data.)

### Year 1–3 SOM Estimates

**Year 1 (if released as open-source):**
- Comparable tools (TruffleHog, Bandit): reach 1,000–5,000 GitHub stars in first year with strong HN/community seeding
- GitHub stars are a proxy for reach, not revenue. Conversion to paying users at 0.5–2% is typical for developer tools (estimate)
- Assuming 5,000 active users, 1% conversion to $10/month plan = $500/month = $6,000/year
- Conservative Year 1 revenue: $0–$50K (primary value is adoption, not revenue)

**Year 2 (post-community seeding, team plan tier launched):**
- Comparable tools: 5,000–15,000 stars, beginning enterprise inbound
- Assuming 20 small teams paying $500/year = $10,000 ARR + 2 enterprise pilots at $10,000/year = $30,000 ARR
- Base Year 2 revenue: $10,000–$100,000 ARR

**Year 3 (maturity in niche):**
- Comparable tools: 10,000–25,000+ stars; established community
- Semgrep at Year 3 equivalent had raised $20M+ Series A; revenue undisclosed but substantial
- Assuming 50 team customers at $3,000/year + 3 enterprise customers at $30,000/year = $240,000 ARR
- Base Year 3 revenue: $100,000–$500,000 ARR

**SOM (addressable paying market, Year 3):**
- From SAM of ~$650M, capturing 0.05–0.1% = $325K–$650K ARR at Year 3
- This is consistent with the benchmark data from comparable tools

| Year | Conservative | Base | Optimistic |
|------|-------------|------|------------|
| Year 1 | $0 | $10,000 ARR | $50,000 ARR |
| Year 2 | $20,000 ARR | $100,000 ARR | $300,000 ARR |
| Year 3 | $100,000 ARR | $400,000 ARR | $1,000,000 ARR |

**Caveat:** These figures assume an open-source community model with a commercial tier. An enterprise-first model would have different revenue timing (slower initial, higher per-customer) and requires different assumptions.

---

## 8. Comparable OSS Security Tool Adoption Benchmarks

### TruffleHog

- Year 1: Released as open-source Go binary targeting a specific niche (Git secret scanning)
- Growth path: viral HN/security community adoption; strong because it was genuinely differentiated (live verification)
- Current state: 25,700+ GitHub stars, 250,000+ daily scans
- Monetization: Truffle Security Co. commercial offerings alongside OSS (exact revenue not disclosed)
- Key lesson: Differentiated-from-day-one OSS tools in security can grow to 25K+ stars without enterprise marketing budgets

### Semgrep

- Year 1 (as r2c): Open-source AST scanner; targeted by Dropbox security team
- Series A: $13M in 2020
- Series D: $100M in February 2025
- ARR: $33.6M estimated (2025)
- GitHub stars: 14,300+
- Key lesson: Open-source security tooling can build to $30M+ ARR over ~5 years with the right community-first approach

### Bandit (Python Security Linter)

- Fully open-source (Apache-2.0); maintained by PyCQA community
- 7,900+ GitHub stars; 59,500+ repositories use it
- No commercial layer; no revenue
- Key lesson: A narrowly-scoped, language-specific tool can achieve meaningful adoption without monetization — but does not build a business

### Gitleaks (Secret Scanning)

- OSS alternative to TruffleHog; MIT license
- ~17,000+ GitHub stars
- Commercial entity (Gitleaks LLC) sells Pro tier: $5/developer/month
- Key lesson: Secret-scanning niche supports commercial models on top of OSS core

### Summary of OSS Security Tool Benchmarks

| Tool | GitHub Stars | Years to 10K Stars (estimate) | Commercial Model |
|------|-------------|-------------------------------|-----------------|
| TruffleHog | ~25,700 | ~2–3 years | Yes (Truffle Security Co.) |
| Semgrep | ~14,300 | ~2 years | Yes (Semgrep, Inc.; $100M+ raised) |
| Bandit | ~7,900 | ~4 years | No |
| Gitleaks | ~17,000 | ~3 years | Yes (Pro tier) |
| ast-grep | ~12,000 | ~2 years | Uncertain |

**Observation:** Security CLI tools targeting developers can reach 10,000+ GitHub stars within 2–3 years if they address a real gap with a genuinely differentiated approach. Commercial viability has been demonstrated by multiple tools in this space. Revenue scale varies widely based on whether the tool pursues enterprise sales or relies on community-driven adoption alone.

---

## 9. Sensitivity Analysis

The TAM, SAM, and SOM estimates are sensitive to the following key variables:

| Variable | Conservative | Base | Optimistic | Impact on Base TAM |
|----------|-------------|------|------------|-------------------|
| Total developer population | 27M (Evans) | 47M (SlashData) | 180M (GitHub accounts) | 2× swing between conservative and base |
| AI adoption rate | 62% (JetBrains daily users) | 84% (Stack Overflow) | 90% (Jan 2026 JetBrains) | ±16% swing around base |
| Per-developer security spend | $40/year | $60/year | $100/year | 2.5× swing between conservative and optimistic |
| Privacy/sovereignty fraction | 15% | 27% | 40% | 2.7× swing on SAM |
| OSS-to-paid conversion | 0.1% | 0.5% | 2% | 20× swing on SOM |

**The OSS-to-paid conversion rate is the most critical and uncertain variable for revenue.**  
Comparable data:
- Developer tool OSS-to-paid conversion is typically 0.5–2% for individual developers
- Team/enterprise conversion from OSS adoption is typically 2–5% of organizations that adopt the tool (not individuals)
- No direct public data was found for ZeroTrust.sh's specific positioning

---

## 10. Key Assumptions and Risks

**Assumptions underlying this analysis:**

1. Global developer population is 47 million (SlashData 2025)
2. 84% of developers use or plan to use AI coding tools (Stack Overflow 2025)
3. Per-developer SAST spend is ~$60/year blended across paying and non-paying users (derived estimate — not verified)
4. 27% of AI-tool-using developers have privacy requirements or active security concerns sufficient to seek a local-only scanner (estimate — not directly surveyed)
5. ZeroTrust.sh operates an open-source model with a commercial team/enterprise tier

**Key risks to the model:**

- **Risk R1:** Major AI coding tool vendors (GitHub, Anthropic, Cursor) bundle security scanning into their tools, reducing the addressable market
- **Risk R2:** Established vendors (Semgrep, Snyk) ship AI-specific threat detection before ZeroTrust.sh gains traction
- **Risk R3:** Local LLM inference quality does not reach parity with cloud tools, limiting value proposition
- **Risk R4:** Developer population estimates are from different methodologies; the "true" population is uncertain
- **Risk R5:** "Concern about AI-generated code security" does not translate to willingness to add a new tool to the workflow

**This document should be updated when:**
- Primary user interviews are conducted (see personas.md)
- Gartner/IDC per-developer security spend data is obtained
- Comparable tool adoption velocity data for Year 1–2 is validated
- ZeroTrust.sh has pilot users providing direct feedback on conversion willingness

---

*End of document.*
