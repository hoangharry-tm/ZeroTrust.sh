# Competitor Feature Comparison Matrix — ZeroTrust.sh

> **Document type:** Research & analysis only. No product decisions are made here.  
> **Compiled:** June 2026  

---

## Table of Contents

1. [Methodology](#1-methodology)
2. [Feature Comparison Matrix](#2-feature-comparison-matrix)
3. [Key Differentiators](#3-key-differentiators)
4. [Scoring Rationale Notes](#4-scoring-rationale-notes)

---

## 1. Methodology

Features were evaluated using the following sources, in priority order:

1. **Official documentation** — each vendor's public docs, FAQ, and product pages as of June 2026
2. **Published benchmarks and third-party reviews** — AppSecSanta, G2, Gartner Peer Insights, independent blog posts
3. **GitHub repository inspection** — for open-source tools: README, features list, issue tracker, release notes
4. **Pricing pages** — official vendor pricing pages or published tier comparisons
5. **Hands-on community reports** — r/netsec, security conference presentations, developer forum threads

Where a feature was ambiguous or unverified, the rating uses ⚠️ (partial/limited) with a note rather than a definitive ✅ or ❌. GitHub star counts are pulled from public repository data as of June 2026; all figures should be treated as approximate.

**Symbol key:**
- ✅ — fully supported, documented
- ❌ — not supported
- ⚠️ — partial, limited, or conditional support
- N/A — not applicable to this tool's scope
- *Italic text* — specific value or condition

---

## 2. Competitive Landscape — Two Distinct Categories

ZeroTrust.sh operates in a **different lane** from automated pentest/security validation tools. The distinction is fundamental, not a matter of degree:

| Dimension | SAST / Source Code Audit tools (ZeroTrust.sh's lane) | Automated Pentest / Security Validation tools |
|---|---|---|
| **What they test** | Source code (static files) | Running / deployed applications |
| **When in SDLC** | Pre-deployment — while developer is coding | Post-deployment — after application is live |
| **Primary user** | The developer who wrote the code | Security team, pentesters, compliance auditors |
| **Requires deployment** | No | Yes — application must be running |
| **Speed expectation** | Seconds to minutes (fits coding loop) | Hours to days (periodic engagement) |
| **Cost model** | Developer tool ($0–$15/month) | Security service ($6,000–$250,000/engagement or /year) |
| **What it catches** | Vulnerabilities introduced in code before they're deployed | Vulnerabilities exploitable in a live system |

**Why automated pentest tools (Strix AI, XBOW, PentestGPT, RidgeGen) are not ZeroTrust.sh competitors:**
- They all require a running application — ZeroTrust.sh requires only source code
- They serve security teams — ZeroTrust.sh serves the individual developer
- They are used periodically — ZeroTrust.sh is designed to run after every AI agent session
- They test traditional vulnerability classes — ZeroTrust.sh specifically targets AI-agent-introduced patterns

See Section 2b for the automated pentest tool comparison.

---

## 2a. SAST / Source Code Security Tools (Direct Comparison)

| Feature | ZeroTrust.sh *(proposed)* | Semgrep OSS | Semgrep Pro | Snyk Code | SonarQube Community | CodeRabbit | TruffleHog | Bandit | ast-grep |
|---------|--------------------------|------------|------------|-----------|-------------------|-----------|-----------|--------|---------|
| **EXECUTION & PRIVACY** | | | | | | | | | |
| Fully local execution | ✅ (design goal) | ✅ | ⚠️ (dashboard is cloud) | ⚠️ (Local Engine add-on) | ✅ (self-hosted) | ❌ | ✅ | ✅ | ✅ |
| Source code stays on-device | ✅ (design goal) | ✅ | ⚠️ (findings sent to cloud) | ⚠️ (code uploaded; deleted post-scan) | ✅ (self-hosted) | ❌ (repo cloned to cloud) | ✅ | ✅ | ✅ |
| Single binary distribution | ✅ (design goal) | ⚠️ (pip/brew/Docker) | ❌ (platform) | ❌ (platform + CLI) | ❌ (Docker/WAR) | ❌ (SaaS) | ✅ (Go binary) | ⚠️ (pip install) | ✅ (Go binary) |
| No API key required | ✅ (design goal) | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ |
| Offline capable | ✅ (design goal) | ✅ | ❌ | ❌ | ⚠️ (self-hosted, requires initial setup) | ❌ | ✅ | ✅ | ✅ |
| **AI-SPECIFIC THREAT DETECTION** | | | | | | | | | |
| AI-specific threat detection | ✅ (design goal) | ❌ | ❌ | ⚠️ (slopsquatting blog only; no dedicated tooling confirmed) | ❌ | ❌ | ❌ | ❌ | ❌ |
| Package hallucination detection | ✅ (design goal) | ❌ | ❌ | ⚠️ (SCA checks known packages; not hallucinated ones) | ❌ | ❌ | ❌ | ❌ | ❌ |
| Prompt injection detection (in code) | ✅ (design goal) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Safety gate bypass detection | ✅ (design goal) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **ANALYSIS ENGINE** | | | | | | | | | |
| Semantic analysis (beyond pattern matching) | ✅ (LLM stage, design goal) | ❌ | ⚠️ (interprocedural dataflow, not LLM) | ✅ (DeepCode AI engine) | ⚠️ (symbolic analysis) | ✅ (LLM-powered) | ❌ | ❌ | ❌ |
| LLM-powered review | ✅ (local GGUF model, design goal) | ❌ | ⚠️ (Semgrep Assistant — cloud only) | ✅ (cloud) | ❌ | ✅ (cloud) | ❌ | ❌ | ❌ |
| Auto-generated patch suggestions | ✅ (design goal) | ❌ | ⚠️ (Semgrep Assistant) | ✅ (Snyk Code Fix) | ❌ | ✅ (one-click fix) | ❌ | ❌ | ❌ |
| Taint analysis / data-flow | ⚠️ (LLM semantic; no dedicated taint engine) | ⚠️ (taint mode, limited) | ✅ (interprocedural taint) | ✅ (DeepCode dataflow) | ⚠️ (limited) | ❌ | N/A | ❌ | ❌ |
| **LANGUAGE & RULE SUPPORT** | | | | | | | | | |
| Multi-language support | ✅ (design goal; scope TBD) | ✅ *30+ languages* | ✅ *30+ languages* | ✅ *25+ languages* | ✅ *27+ languages* | ✅ *all (LLM-based)* | N/A | ❌ *Python only* | ✅ *20+ languages* |
| YAML/custom rule format | ✅ (planned) | ✅ | ✅ | ❌ | ❌ | ❌ | ⚠️ (custom detectors via YAML) | ❌ (Python plugin API) | ✅ (YAML rules) |
| **INTEGRATION** | | | | | | | | | |
| CI/CD integration | ✅ (design goal: pre-commit, GitHub Actions) | ✅ *(GH Actions, GitLab, Jenkins, CircleCI)* | ✅ *(same + managed policies)* | ✅ *(GitHub, GitLab, Bitbucket, Jenkins, etc.)* | ✅ *(Jenkins, GitHub, Azure DevOps, etc.)* | ✅ *(GitHub, GitLab, Bitbucket)* | ✅ *(GitHub Actions, GitLab CI)* | ✅ *(any CI via CLI)* | ✅ *(any CI via CLI)* |
| IDE plugin available | ❌ (not in scope initially) | ✅ *(VS Code, IntelliJ)* | ✅ *(VS Code, IntelliJ)* | ✅ *(VS Code, IntelliJ, Eclipse, etc.)* | ✅ *(SonarLint)* | ✅ *(VS Code, JetBrains — via IDE)* | ❌ | ❌ | ⚠️ *(VS Code only, experimental)* |
| **OUTPUT** | | | | | | | | | |
| Interactive HTML report | ✅ (design goal) | ❌ | ⚠️ (dashboard, not standalone HTML) | ❌ (web dashboard) | ⚠️ (web UI when self-hosted) | ❌ (GitHub/GitLab PR comments) | ❌ (JSON/text output) | ❌ (text/JSON output) | ❌ (text/JSON output) |
| **SCOPE** | | | | | | | | | |
| Supply chain scanning | ⚠️ (package hallucination detection only; not SCA) | ❌ | ✅ (Semgrep Pro SCA) | ✅ (Snyk Open Source) | ❌ | ❌ | ❌ | ❌ | ❌ |
| Secret scanning | ❌ (out of scope; TruffleHog recommended) | ❌ | ⚠️ (Secrets product, separate) | ⚠️ (Snyk Secrets, separate product) | ❌ | ⚠️ (secret detection as add-on) | ✅ *800+ credential types* | ❌ | ❌ |
| **BUSINESS** | | | | | | | | | |
| License type | TBD | LGPL-2.1 (engine) | Commercial | Commercial | LGPL-3.0 | Commercial | AGPL-3.0 | Apache-2.0 | MIT |
| Pricing model | TBD (analysis in progress) | Free | $35/contributor/month (Team) | $25/dev/month (Team) | Free (Community Build) | $24/dev/month (Pro) | Free | Free | Free |
| GitHub stars (approx., June 2026) | N/A (not yet released) | ~14,300 | N/A (same repo) | ~3,800 (CLI) | ~10,200 | ~1,400 (GitHub app listing) | ~25,700 | ~7,900 | ~12,000+ |

---

## 2b. Automated Pentest / Security Validation Agents (Different Lane — Not Direct Competitors)

> These tools test **running applications**, not source code. They are used by security teams, not individual developers. They require deployed infrastructure. Their cost model ($6,000–$250,000/year) assumes infrequent use. Listed here for completeness and positioning clarity — ZeroTrust.sh does not compete with them; they solve a different problem at a different point in the SDLC.

| Feature | Strix AI | XBOW | PentestGPT | RidgeGen (RidgeBot) |
|---|---|---|---|---|
| **What it tests** | Running web apps (HTTP proxy + browser + terminal) | Running web applications | Running applications / CTF challenges | IT/OT/API infrastructure |
| **Primary user** | Developers + security teams | Security teams, compliance auditors | Pentesters (human-guided) | Enterprise security teams |
| **Source code required** | No — tests live endpoints | No — tests deployed app | No — network/app scanning | No — tests live infrastructure |
| **Local execution** | ✅ (open-source, runs locally) | ❌ (cloud service) | ✅ (runs locally, uses cloud LLM) | ❌ (enterprise SaaS/on-prem) |
| **AI-specific threat detection** | ❌ (tests traditional vuln classes) | ❌ (tests traditional vuln classes) | ❌ (general pentest framework) | ❌ (IT/OT/AI infra validation) |
| **Slopsquatting detection** | ❌ | ❌ | ❌ | ❌ |
| **Prompt injection in source code** | ❌ | ❌ | ❌ | ❌ |
| **Safety gate bypass in code** | ❌ | ❌ | ❌ | ❌ |
| **Pre-deployment (no running app)** | ❌ — needs running app | ❌ — needs running app | ❌ — needs running app | ❌ — needs running infra |
| **Developer workflow integration** | ⚠️ (CI/CD for deployed apps) | ❌ (engagement model) | ❌ (human pentest assist) | ❌ (enterprise security audit) |
| **Proof-of-Concept / PoE generation** | ✅ (validates live exploits) | ✅ (pentest report) | ⚠️ (human-guided) | ✅ (88% DEFCON 2025 benchmark) |
| **Pricing** | Free (open-source) | $6,000+/engagement | Free (OSS research tool) | Enterprise (undisclosed) |
| **License** | Open-source | Commercial SaaS | MIT (research) | Commercial |

**Key insight:** Strix AI is the closest in concept (open-source, PoE generation, developer-accessible) but fundamentally requires a running application and tests traditional vuln classes. It does not address the developer's question: *"What did the AI agent introduce into my source code before I deployed it?"*

---

## 3. Key Differentiators

ZeroTrust.sh occupies a position that no existing shipped tool satisfies. The unique combination is:

**Differentiator 1: The only pre-deployment developer tool specifically targeting AI-agent-introduced vulnerabilities**

- No SAST tool (Semgrep, Snyk, CodeRabbit) has dedicated detection for slopsquatting, prompt injection in code, or safety gate bypass — confirmed ❌ across all 8 tools in the matrix above
- No automated pentest tool (Strix, XBOW, PentestGPT, RidgeGen) targets these patterns either — they test running apps against traditional vulnerability classes
- ZeroTrust.sh answers the question no existing tool answers: *"What did the AI coding agent introduce into my source code?"*

**Differentiator 2: Two-path local analysis (Pattern detection + Logic/semantic detection) without code egress**

- All tools with LLM-powered semantic analysis (CodeRabbit, Snyk Code, Semgrep Assistant) are cloud-based — source code leaves the machine
- All fully local tools (Semgrep OSS, Bandit, ast-grep) use pattern matching only — no logic-level vulnerability detection
- ZeroTrust.sh is the only tool combining: local execution + Path A (fast AST rules) + Path B (independent LLM semantic scan of high-risk surfaces) in a single developer workflow tool

**Differentiator 3: Developer-workflow native, not security-team native**

- ZeroTrust.sh runs after every AI agent session on the developer's own machine — not as a periodic engagement, not requiring a security team, not requiring a deployed application
- Target user: the developer themselves, in their local terminal, 30 seconds after Cursor finishes writing code
- This workflow position is unoccupied: SAST tools run in CI/CD (post-commit), pentest tools run post-deployment, code review tools run at PR time. ZeroTrust.sh runs at the moment of maximum leverage — when the code was just written and before it's committed

**Differentiator 4: Self-contained PoE output (Approach 3) designed for developer/manager consumption**

- Automated pentest tools produce security team reports (technical, compliance-oriented)
- ZeroTrust.sh Approach 3 produces a two-layer PoE: technical trace for the developer who needs to fix it, executive summary for the manager who needs to decide whether to block the release
- No existing local tool produces this output format

**Caveat:** These differentiators are based on the proposed design, not a shipped product. The most immediately deliverable and defensible differentiator is Differentiator 1 — the AI-specific Semgrep ruleset (Approach 1) can be shipped in 2 weeks and has no equivalent in any existing tool.

---

## 4. Scoring Rationale Notes

**Semgrep OSS:** The LGPL-2.1 engine is purely local and open source. Its taint analysis in "taint mode" is limited to single-file by default in OSS; interprocedural taint requires Pro. The community rules registry has 2,800+ rules, but none specifically target AI-generated code threat vectors as of June 2026. Stars: 14,300+ (Source: [github.com/semgrep/semgrep](https://github.com/semgrep/semgrep))

**Snyk Code:** Uploads source code for analysis; has a "Local Engine" for enterprise customers that avoids full cloud egress, but this is an add-on that receives slower updates. The DeepCode AI engine provides genuine semantic analysis beyond pattern matching. The patent-pending AI Fix Suggestions generate patches. Stars for Snyk CLI: ~3,800 (Source: [github.com/snyk/cli](https://github.com/snyk/cli))

**SonarQube Community:** Self-hosted, so code never leaves the organization's infrastructure. However, it requires maintaining a server instance (Docker/WAR), not a single binary. Community Build is free under LGPL-3.0. Used by 7 million+ developers. Stars: ~10,200 (Source: [github.com/SonarSource/sonarqube](https://github.com/SonarSource/sonarqube))

**CodeRabbit:** Cloud-only; clones repositories per review in isolated containers. Source code is not retained after review. The tool uses multiple cloud LLMs plus 40+ SAST/linter tools. Review turnaround is measured in minutes post-PR creation — not suitable as a pre-commit or inline agent-loop tool. Over 2 million repositories connected.

**TruffleHog:** Best-in-class for secret scanning with live verification. Not a SAST tool — does not analyze code for vulnerability patterns, only credentials/secrets. Fully local, single binary. Stars: 25,700+ (Source: [github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog))

**Bandit:** Python-only. AST-based, fast, well-maintained (Apache-2.0, PyCQA). No LLM component. Stars: ~7,900; used by 59,500+ repositories. (Source: [github.com/PyCQA/bandit](https://github.com/PyCQA/bandit))

**ast-grep:** Language-agnostic structural search and linting tool. Supports YAML-format rules similar to Semgrep but with a different implementation. Fast; no semantic analysis. Stars: ~12,000+ (approximate, as of June 2026).

---

*End of document.*
