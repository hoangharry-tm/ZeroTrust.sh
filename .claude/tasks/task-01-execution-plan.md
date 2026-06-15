# Task 01 — Generate Execution Plan: ZeroTrust.sh Approach 1 (Semgrep PoC)

> **Purpose of this file**: Invoke this in a fresh Claude Code session to research,
> plan, estimate, and produce a Microsoft Word execution plan document for tech lead
> approval. Use a team of specialized subagents. Do NOT skip subagent consultations.

---

## MISSION

Produce a single Microsoft Word file at:

```
docs/planning/execution-plan-approach-1.docx
```

The document is an implementation timeline for **Approach 1 (Semgrep PoC)** of the
ZeroTrust.sh project — to be reviewed and approved by a technical lead before full
implementation begins. It must be concise, professionally structured, scientifically
estimated, and include a buffer for unexpected events.

---

## FULL CONTEXT — READ ALL OF THIS BEFORE DOING ANYTHING

### 1. What ZeroTrust.sh is

ZeroTrust.sh is a local, privacy-first CLI security scanner targeting codebases
produced by AI coding agents (Cursor, Cline, Aider, Copilot Workspace). Its value
proposition: source code never leaves the machine, and it specifically detects
AI-agent-introduced vulnerability patterns that traditional SAST tools miss.

Full product spec: `CLAUDE.md` (project root).

### 2. The Three-Phase Product Roadmap (Context)

The tech lead approved a phased development strategy:

ZeroTrust.sh uses a **two-path parallel design** across all three approaches:
- **Path A** — Pattern detection: fast AST/rule-based scanning for vulnerabilities with a syntactic signature
- **Path B** — Semantic/logic detection: LLM-based scanning of high-risk surfaces for vulnerabilities invisible to patterns (IDOR, missing auth, business logic flaws, AI-agent trust escalation)

Neither path gates the other. Both run in parallel against the same codebase and feed a shared deduplication layer.

| Phase | Name | What it builds |
|---|---|---|
| **Approach 1** | Semgrep PoC | **Path A only.** Custom Semgrep YAML rules to detect AI-agent vulnerability patterns. Pure static, no LLM, no Path B. |
| Approach 2 | Hybrid AST + Local LLM | **Path A expanded + Path B introduced.** Go/Tree-sitter core with broader rules; local Ollama LLM verifies Path A findings AND independently scans endpoint/auth surfaces for logic flaws (Path B). Patch generation. |
| Approach 3 | Agentic Scanner | **Path A + Path B fully realized.** Path A expands to taint-aware tools (CodeQL/Joern). Path B: LangGraph multi-agent, call graph traversal, CVE cross-referencing, Docker sandbox exploit execution, two-layer PoE output. Requires 32B+ model. |

**This task covers Approach 1 only.**

### 3. Deliverables for the Tech Lead Presentation (Approach 1)

The following must exist and work on demo day:

1. **Semgrep custom rule set** — YAML rules targeting Python and Java first.
   Rules must detect vulnerability patterns commonly introduced by AI coding agents
   (defined in the Vulnerability Target List below).

2. **Fake Java test codebase** — An AI-generated Java application with intentional,
   realistic security issues that the Semgrep rules are designed to catch. The manager
   will also test these rules against their own code or AI-generated code; the rules
   must generalize, not just hit on the fake codebase.

3. **Semgrep detection demo** — Semgrep scans the fake Java codebase using the
   custom rules and catches a meaningful portion of the issues (not 100% — PoC goal
   is to prove the concept scales and that signal is real).

4. **Presentation narrative** — A section on pros and cons of the Semgrep-only
   approach: what it does well, where it fails, and why Approach 2 (LLM verifier)
   is the logical next step.

5. **Python Notebook (bonus but strongly desired)** — A Jupyter notebook
   demonstrating effectiveness metrics (precision, recall proxy, rule coverage) or
   showing that false positive rates are in an acceptable range.

### 4. Vulnerability Target List (what the Semgrep rules must detect)

These are the AI-agent-specific vulnerability patterns. Use this list to scope the
rule set. Not all need custom rules — some map to existing Semgrep community rules
that can be adopted and customized.

**Python targets:**
- `pickle.loads()` without type validation (insecure deserialization)
- `subprocess.run(..., shell=True)` with dynamic input (OS command injection)
- `eval()` / `exec()` on user-controlled input (code injection)
- `requests.get(url, verify=False)` or any SSL verification bypass
- Hardcoded credentials: `password = "..."`, `api_key = "sk-..."`, `token = "..."`
- SQL injection via f-string or % formatting: `f"SELECT ... WHERE id={user_id}"`
- Path traversal: `open(f"uploads/{filename}")` without sanitization
- `yaml.load()` instead of `yaml.safe_load()` (unsafe YAML parsing)
- Direct injection of unsanitized user input into LLM system prompts

**Java targets:**
- `Runtime.getRuntime().exec(userInput)` (OS command injection)
- `Statement.execute("SELECT ... " + id)` or any JDBC string concatenation (SQL injection)
- `new ObjectInputStream(input).readObject()` without class filtering (insecure deserialization)
- Hardcoded credentials in source: `String password = "secret"`, `String apiKey = "..."`
- Path traversal: `new File(baseDir + userInput)` without normalization
- Accepting all TLS certs: implementing `X509TrustManager` with empty `checkServerTrusted`
- `MessageDigest.getInstance("MD5")` or `"SHA1"` for password hashing (weak crypto)
- Sensitive data in logs: `logger.info("password: " + password)`
- AI-agent-specific control bypass: `// SECURITY_BYPASS: disabled for testing` patterns
  in comments immediately preceding a security check that was removed or weakened

### 5. Developer Profile (Hoang — the person executing this plan)

- **Role**: Intern, VNG ZingPlay Studio
- **Internship window**: ~2 months total, starting from early June 2026
- **Current phase**: Analysis → now moving to PoC implementation (Approach 1)
- **Experience with Semgrep**: Zero prior experience. Fast learner, comfortable using
  AI tools to accelerate learning. Willing to put in overtime hours to learn.
- **Tooling available**: Claude Code (this CLI), macOS, Python, Java JDK, Semgrep CLI,
  Jupyter, standard brew-installed tools (pandoc, etc.)
- **Available time**: 6–8 hours per day (primary focus project)
- **Hard deadline**: 1–2 weeks from 2026-06-09 (use 2026-06-20 as the target date)
- **Communication language**: English for the document

### 6. Key Constraints for Estimation

- Learning curve is real: Semgrep YAML rule syntax takes ~1 full day to get productive.
- AI tools (Claude Code) compress learning time by ~40–60% vs unassisted research.
- Writing effective pattern-matching rules for AI-specific vulnerabilities requires
  iterative testing — budget for multiple refinement cycles.
- The fake Java codebase must be realistic enough to generalize, not just a trivial
  snippet file. AI generation is used but requires careful prompting.
- Python Notebook is a bonus — if time is tight, it gets cut first.
- Buffer must account for: rule edge cases, Semgrep version quirks, Windows/macOS
  path issues, and one potential sick day or blocked day.

---

## SUBAGENT TEAM — MANDATORY

You must spawn the following specialized subagents **before writing a single word of
the plan**. Use `Agent` tool with `subagent_type: "claude"` for each. Run them in
**parallel** where their inputs are independent.

Do NOT write the plan based on your own judgment alone. The plan's credibility depends
on these expert consultations.

---

### Agent A — PM Consultant (Project Management Expert)

**Role**: Senior project manager with 10+ years in software delivery. Knows estimation
theory (PERT, story points, cone of uncertainty), risk registers, buffer strategy, and
how to present implementation plans to skeptical technical leads.

**Prompt to send**:

```
You are a senior software project manager with deep expertise in estimation theory
and implementation planning for security tooling.

I need to build a Semgrep PoC for AI coding agent vulnerability detection.
The developer (junior intern) has ZERO prior Semgrep experience but is a fast learner
with access to AI coding assistants (Claude Code). They have 6–8 focused hours per day
and a hard deadline of 2026-06-20 (approximately 9 working days from today, 2026-06-09).

The deliverables are:
1. Semgrep custom YAML rules for ~10 Python vulnerability patterns and ~9 Java patterns
2. An AI-generated fake Java codebase with intentional security issues
3. A working demo where Semgrep detects a meaningful portion of those issues
4. A prepared presentation narrative (pros/cons of the approach)
5. (Bonus) A Python Jupyter Notebook with effectiveness metrics

Using PERT estimation (Optimistic / Most Likely / Pessimistic):
- Research and Semgrep learning phase
- Python rule development phase
- Java rule development phase
- Test codebase generation and validation phase
- Demo preparation and refinement phase
- Presentation narrative writing phase
- Bonus Notebook phase (if time allows)
- Buffer

For each phase, provide:
- Subtask list (granular)
- O / ML / P estimates in hours
- PERT expected value E = (O + 4×ML + P) / 6
- Variance σ² = ((P-O)/6)²

Then give:
- Total expected hours and standard deviation
- Whether this fits in 9 working days at 7 hrs/day
- Go/No-go recommendation on the bonus notebook
- Recommended buffer size as a % and which phases absorb it
- Top 3 risks to the timeline and mitigation for each

Present your analysis clearly in structured markdown.
```

---

### Agent B — Semgrep & SAST Technical Advisor

**Role**: Security engineer who has written production Semgrep rules and understands
the practical effort, pitfalls, and realistic detection rates of YAML-based SAST.

**Prompt to send**:

```
You are a security engineer with hands-on experience writing custom Semgrep rules
in production environments and deploying SAST pipelines.

I need expert advice on the following PoC:
Goal: Write custom Semgrep YAML rules to detect AI coding agent-introduced vulnerabilities
in Python and Java codebases. Target timeline: ~9 working days, developer has zero
prior Semgrep experience.

Target vulnerability patterns (Python):
- pickle.loads() without validation
- subprocess.run(shell=True) with dynamic input
- eval()/exec() on user input
- requests SSL verification bypass (verify=False)
- Hardcoded credentials (password, api_key, token literals)
- SQL injection via f-string concatenation
- Path traversal with open()
- yaml.load() instead of yaml.safe_load()
- Unsanitized user input in LLM system prompts

Target vulnerability patterns (Java):
- Runtime.exec() with user input
- JDBC string concatenation SQL injection
- Insecure ObjectInputStream deserialization
- Hardcoded credentials in source
- Path traversal with new File()
- Empty X509TrustManager (TLS bypass)
- MD5/SHA1 for password hashing
- Sensitive data in log statements
- Comment patterns indicating AI-agent security bypass

Please advise on:
1. Which patterns map to existing Semgrep community rules (semgrep-rules registry) that
   can be adopted and customized vs. written from scratch? Estimate ratio.
2. For a zero-experience developer using AI assistance, what is a realistic rule count
   to aim for in this timeline that demonstrates "the concept works"?
3. What is a realistic precision/recall expectation for these rules against intentionally
   vulnerable code? What should I NOT promise the tech lead?
4. What are the top 3 technical pitfalls that will slow down a Semgrep beginner the most?
5. What does a "well-structured" Semgrep ruleset repo look like for a PoC presentation?
   (directory structure, metadata, test files)
6. For the fake Java test codebase: what makes an AI-generated codebase convincing
   enough for a security PoC demo? What should it contain?
7. For the Python Notebook: what 3–5 metrics would most impress a technical lead when
   evaluating Semgrep rule effectiveness?

Respond in structured markdown, be direct about limitations and realistic expectations.
```

---

### Agent C — Technical Writer (Word Document Structure)

**Role**: Technical writer experienced in producing implementation plan documents for
engineering and security teams at tech companies.

**Prompt to send**:

```
You are a technical writer specializing in implementation plans and engineering
proposals for software security products.

I need to produce a Microsoft Word execution plan document to present to a tech lead
for approval of a 2-week PoC implementation. The product is a Semgrep-based custom
rule engine for detecting AI coding agent vulnerabilities.

Audience: A technical lead at a Vietnamese game studio (VNG ZingPlay Studio) who
understands software engineering, security tooling, and SAST concepts. Wants brevity
and clarity. Not interested in fluff or over-selling.

Please design the exact document structure (sections, subsections, and 1-sentence
description of what each contains). The document should:
- Fit on approximately 3–5 pages when rendered
- Lead with the objective and scope, not background
- Present the milestone timeline visually (suggest how to represent a 2-week schedule
  clearly in Word without Gantt chart software)
- Clearly separate "committed deliverables" from "bonus deliverables"
- Show the estimation methodology (that it was derived scientifically, not guessed)
- Include a risk + mitigation table
- End with a clear ask: "Please approve this plan so implementation can begin on [date]"

Output: The exact section structure with headers, sub-headers, and a one-line note
on what content belongs in each section. Also specify: font, heading sizes, and
page margins to use for a clean professional look.
```

---

## ORCHESTRATION PROCESS

After collecting all three subagent reports, follow these steps in order:

### Step 1 — Synthesize the Findings

Read all three reports. For each of the following, write a 2–3 sentence synthesis:
- Confirmed milestone structure (from A + B combined)
- Final task list per milestone (reconcile A's PM view with B's technical view)
- Final time estimates (use A's PERT numbers, adjusted by B's technical reality check)
- Document structure (from C, verified against what A and B recommend including)

If Agent A and Agent B disagree on estimates, trust Agent B's technical complexity
assessment and apply Agent A's buffer methodology to it.

### Step 2 — Resolve the Notebook Decision

Based on Agent A's go/no-go recommendation on the bonus Notebook:
- If go: include it as a "stretch goal" milestone with its own estimated hours
- If no-go: include it in the document as "Out of Scope for v1, planned for Approach 2"

### Step 3 — Write the Document Content

Using Agent C's structure, write the full content for each section of the Word document.
Be direct and concise. No filler. No marketing language. This is an internal engineering
document, not a pitch deck.

Critical content rules:
- Time estimates MUST show the PERT formula (O + 4×ML + P) / 6 for at least one
  representative milestone, to demonstrate the estimation is scientific
- The risk table MUST have at least 4 rows
- Committed vs. bonus deliverables MUST be clearly separated
- Every milestone MUST have a start date, end date (relative: Day X–Y), and success
  criterion (what does "done" look like?)
- Buffer MUST be named explicitly, not hidden inside task estimates
- The pros/cons section MUST be honest: name at least 2 real limitations of the
  Semgrep-only approach without apologizing for them

### Step 4 — Generate the Word File

Check if pandoc is available:

```bash
which pandoc
```

If pandoc is available:
1. Write the full document content to `docs/planning/execution-plan-approach-1.md` as a
   well-formatted markdown file (use `#`, `##`, `###`, tables, and horizontal rules)
2. Run:
   ```bash
   pandoc docs/planning/execution-plan-approach-1.md \
     -o docs/planning/execution-plan-approach-1.docx \
     --reference-doc=.claude/tasks/reference.docx 2>/dev/null || \
   pandoc docs/planning/execution-plan-approach-1.md \
     -o docs/planning/execution-plan-approach-1.docx
   ```
3. Verify the `.docx` file exists and is non-zero bytes

If pandoc is NOT available:
1. Install it: `brew install pandoc`
2. Retry the pandoc command above
3. If brew is also unavailable, use `python3 -c "import docx"` to check for python-docx,
   then use python-docx to generate the file programmatically (write a Python script
   `docs/generate_doc.py` and run it)

Do NOT output the plan as a raw markdown file and call it done. The `.docx` file is
the required deliverable. The `.md` file is an intermediate artifact — keep it as a
human-readable companion.

### Step 5 — Final Check

Before declaring the task complete, verify:
- [ ] `docs/planning/execution-plan-approach-1.docx` exists and is non-zero bytes
- [ ] The document contains all required sections per Agent C's structure
- [ ] All milestones have start date, end date, success criterion
- [ ] PERT formula appears at least once
- [ ] Risk table has at least 4 rows
- [ ] Committed vs. bonus deliverables are clearly labeled
- [ ] Buffer is explicitly named
- [ ] Pros AND cons of Semgrep-only approach are stated honestly
- [ ] The final line of the document is a clear approval ask with a specific start date

If any check fails, fix it before reporting completion.

---

## OUTPUT REQUIREMENTS (Word Document)

**File location**: `docs/planning/execution-plan-approach-1.docx`
**Companion markdown**: `docs/planning/execution-plan-approach-1.md`
**Target length**: 3–5 pages (aim for 4)
**Tone**: Professional, direct, no fluff
**Audience**: Technical lead who will read this in < 5 minutes

### Required Sections

1. **Objective and Scope** — What Approach 1 is, what it is not, and why it matters
2. **Deliverables** — Two-column table: Committed vs. Bonus
3. **Milestone Plan** — Milestone table with Day range, tasks, hours, success criteria
4. **Estimation Methodology** — Brief explanation of PERT; one worked example
5. **Risk Register** — Table with 4+ rows: Risk | Likelihood | Impact | Mitigation
6. **Pros and Cons of Approach 1** — Honest two-column table
7. **Approval Request** — One paragraph, clear ask, proposed start date

---

## IMPORTANT REMINDERS

- Do NOT write the plan from scratch without the subagent consultations. The whole
  point is expert-backed credibility.
- Run all three agents in parallel (independent inputs) before synthesizing.
- The final deliverable is a `.docx` file, not a markdown output in chat.
- If any tool fails, diagnose and fix rather than skipping or substituting.
- Keep all intermediate work files in `docs/` so Hoang can inspect them.
