# Task 06 — Rules Auditor & Engineer: Uniqueness, Quality & Gap Coverage

> **Invoke:** Load this file in a fresh session and say "Run task 06."
> **Token budget:** ~120K tokens total across all phases. If you hit this, finish the current
> phase, write a checkpoint, and report what remains. Do NOT silently exceed it.
> **Hard timeout:** 15 minutes wall-clock per phase. If a phase takes longer, stop, checkpoint, escalate.

---

## CORE PRINCIPLES (read before acting)

**Efficiency rules:**
1. Never read a file you already know the content of from context. Reuse, don't re-read.
2. Output tables, not prose. Every deliverable must fit in 3 columns × 20 rows or less.
3. If you detect yourself going in circles (same file read >2 times), stop and take the **aggressive path** (cut scope, not quality).
4. When in doubt between "dig deeper" and "move on", **always move on**. The task has hard phase gates — unfinished work is reported in the exit summary, not silently half-done.

**Decision trees for common forks:**

```
If rule overlaps with community rule:
  → Is our version strictly better? (more variants, taint-mode, lower FP?)
    → YES: document "why ours is better" table, keep as-is
    → NO: either eliminate the rule OR upgrade it to be better (pick one, don't agonize)

If rule has 0 bad/ or 0 ok/ tests:
  → Is it a GN rule that needs special file encoding? (Unicode chars, JSON schema)
    → YES: write at least the ok/ test, note that bad/ needs manual Unicode byte creation
    → NO: write both bad/ and ok/ immediately

If missing language coverage (JS/TS, Kotlin, C#, Ruby, PHP):
  → Does the vulnerability class have a clear AST pattern in this language?
    → YES: write an ast-grep rule (1 file, 1-3 patterns, done)
    → NO: skip this language for this class, note "requires Path B semantic analysis"
```

---

## MISSION

Audit and upgrade the ZeroTrust.sh rule set to ensure:
1. **Every rule is logically airtight** — no false negatives due to missing variants, no false positives due to over-broad patterns
2. **Every rule is unique** — if a community rule already covers a pattern well, either improve ours to be strictly better, or eliminate ours entirely
3. **Language coverage** — add JS/TS, Kotlin, C#, Ruby, PHP rules via ast-grep for the highest-signal vulnerability classes
4. **Test completeness** — every rule has ≥1 bad/ + ≥2 ok/ tests; 0 FP on ok/ set
5. **Selling points documented** — clear competitive differentiation vs Semgrep community rules

---

## PHASE 1 — AUDIT EXISTING RULES (max 25K tokens, 10 min)

Read every YAML file in `rules/` and produce a single unified audit table.

**Read order (stop after 25 files or 25K tokens, whichever comes first):**
1. `rules/python/` — all 10 files
2. `rules/java/` — all 9 files
3. `rules/generic/` — all 7 files
4. `rules/astgrep/` — all 4 files
5. `testdata/rules-tests/FINE_TUNING_LOG.md` (read once, understand the FP history)

**Output — Exact table format (same row for every rule):**

| Rule ID | CWE | Confidence | Lang | Variants Covered | Variants Missing | Tests: bad/ | Tests: ok/ | Test Status | FP Risk | Uniqueness vs Community |
|---|---|---|---|---|---|---|---|---|---|---|

**Column rules:**
- `Variants Covered`: list V1-V7+ from the file's comment header. If no header, write "NONE STATED".
- `Variants Missing`: look at the vulnerability class. Could there be aliased imports? f-string forms? reflection variants? List what's absent.
- `Test Status`: `PASS` (0 FP on ok, ≥1 TP per bad) | `PARTIAL` (some variants untested) | `FAIL` (FP on ok or 0 TP on bad) | `NOT TESTED`
- `FP Risk`: `LOW` (well-scoped patterns, good exclusions) | `MEDIUM` (broad regex or pattern) | `HIGH` (overly broad, likely fires on benign code)
- `Uniqueness vs Community`: `UNIQUE` (no community rule exists) | `BETTER` (community exists but our version is strictly stronger — explain in 1 sentence) | `OVERLAP` (similar quality — recommend to upgrade or eliminate) | `WEAKER` (community version is better — must eliminate or upgrade)

**After the table, write 2-3 sentences summarizing:**
- How many rules are UNIQUE vs BETTER vs OVERLAP vs WEAKER
- How many have incomplete tests
- Which rules need immediate attention (red flags only)

---

## PHASE 2 — COMMUNITY COMPARISON (max 20K tokens, 12 min)

Browse the Semgrep community rules registry live to find existing rules that overlap with ZeroTrust.sh rules. Compare each ZeroTrust rule against the closest community equivalent.

### 2.1 — Browse Community Registry (5 min, 4 fetches max)

Fetch these URLs in parallel (all at once, do not do them sequentially):

```
https://github.com/semgrep/semgrep-rules/tree/develop/python/lang/security
https://github.com/semgrep/semgrep-rules/tree/develop/java/lang/security
https://github.com/semgrep/semgrep-rules/tree/develop/ai
https://github.com/semgrep/semgrep-rules/tree/develop/generic
```

For each, find directories/files that overlap with our rules. For overlapping rules, open the YAML file and read its `patterns:`, `mode:`, `severity:`, `confidence:`, and `message:` fields.

**If a fetch fails** (timeout, 404, rate limit): log the failure and fall back to the pre-loaded data table below for that specific rule category.

**Fetch budget:** max 4 URL fetches. If you've fetched 4 and still have gaps, use the pre-loaded fallback data for the remainder. Do NOT exceed 4 fetches.

### 2.2 — Comparison Table

After fetching, produce:

| ZeroTrust Rule | Closest Community Rule | Community Quality | Our Quality | Verdict | Recommended Action |
|---|---|---|---|---|---|

**Fallback data (use ONLY if live fetch fails for that category):**

| Category | Community Rule | Quality |
|---|---|---|
| Python OpenAI | `python.lang.security.audit.audit-openai-chat-completion` — simple pattern, no taint | LOW — existence check only |
| Python Anthropic | `ai/python/detect-anthropic` — `import anthropic` detection | INFO/LOW — not a security rule |
| Python LangChain | `ai/python/detect-langchain` — `import langchain` detection | INFO/LOW — not a security rule |
| Python hardcoded creds | `python.lang.security.detected-hardcoded-password` regex | MEDIUM — ~30% FP |
| Python API keys | `python.lang.security.detected-aws-secret-key` — AWS only | LOW — no AI key patterns |
| Java SQL injection | `java.lang.security.audit.sqli.*` — taint-mode, Spring sources | HIGH — 5+ sub-rules |
| Java deserialization | `java.lang.security.audit.deserialization.untrusted-deserialization` | HIGH — 3 variants |
| Java creds | `java.lang.security.audit.hardcoded-credentials` multi-pattern | MEDIUM |
| Generic bidi | `generic.unicode.security.bidi.yml` | WARNING, LOW confidence |
| Generic secrets | `generic.secrets.*` gitleaks patterns | GOOD — secrets-focused |
| Java SSL/TLS | `java.lang.security.*` noop TrustManager rules | GOOD — standard coverage |

### 2.3 — Comparison Methodology

- If community rule uses simple pattern-match and ours uses taint mode → ours is BETTER
- If community rule has fewer variants → ours is BETTER (document how many more)
- If community rule has worse FP controls (no `pattern-not`, no exclusions) → ours is BETTER
- If community rule covers the same ground with similar quality → mark OVERLAP
- If community rule is clearly stronger → mark WEAKER (and recommend elimination)

### 2.4 — Summary Outputs

- A comma-separated list of rules to KEEP AS-IS (unique or better)
- A comma-separated list of rules to UPGRADE (overlap — specify the upgrade)
- A comma-separated list of rules to ELIMINATE (weaker — only if we truly add nothing)

---

## PHASE 3 — LANGUAGE GAP ANALYSIS (max 10K tokens, 5 min)

Identify exactly which languages and vulnerability classes are missing ast-grep rules.

**Output — Exact table:**

| Language | Missing Vulnerability | Priority | Why Important | ast-grep Feasibility |
|---|---|---|---|---|

**Priority scale:** `CRITICAL` (top-5 web language, common vuln) | `HIGH` (common language or vuln) | `MEDIUM` (niche) | `LOW` (rare overlap)

**Pre-loaded feasibility data (use these):**
- **JavaScript/TypeScript**: ast-grep supports JS/TS natively. OpenGrep also supports JS. Highest-priority gap.
- **Kotlin**: ast-grep supports Kotlin. Also supported by Semgrep community rules (limited).
- **C#**: ast-grep supports C#. Semgrep community has decent C# coverage.
- **Ruby**: ast-grep supports Ruby. Semgrep community has some Ruby rules.
- **PHP**: ast-grep supports PHP. Semgrep community has solid PHP rules.

**Must-cover vulnerability classes for each (pick top 3 per language):**
- Prompt injection / LLM SDK usage (follows same pattern as PY-001)
- Hardcoded API keys (`sk-`, `sk-ant-`, `hf_` patterns)
- SQL injection via string concatenation

**Decision rule:**
- If language + vuln has a clear AST pattern → write 1 ast-grep rule
- If vuln requires multi-file taint analysis → skip (defer to Path B)
- Write max 3 new ast-grep rules per language (enforced ceiling)
- Total new ast-grep rules across ALL languages: max 12

---

## PHASE 4 — WRITE NEW RULES (max 30K tokens, 20 min)

Execute the Phase 2 and Phase 3 recommendations. Write only what was flagged as needed.

**Rule priority order (write in this order, stop when budget runs out):**
1. Eliminate or upgrade OVERLAP/WEAKER rules from Phase 2
2. Add missing tests for rules with incomplete test coverage
3. Write new ast-grep rules for missing languages (max 12 total)
4. Fix any FP risks identified in Phase 1

**Upgrade methodology (when upgrading an overlapping rule):**
- Do NOT rewrite the whole file — surgically edit the existing one
- For each upgrade, the change must be justified by a specific community weakness:
  - "Added V4 (transitive wrapper) — community rule only covers V1 direct form"
  - "Added taint mode with Spring/Flask sources — community uses pattern-only"
  - "Added `pattern-not:` for env var exclusions — community has 30% FP due to missing this"
- If the upgrade would change <3 lines, just make the edit. If >10 lines, consider elimination instead.

**New ast-grep rule template (use exactly this):**

```yaml
id: AG-XXX-$LANGUAGE-$VULN-SLUG
language: $language
rule:
  kind: $ast_node_kind  # Use ast-grep playground to find this
  pattern: $PATTERN
  not:
    pattern: $SAFE_PATTERN
message: >
  [1-sentence detection] [1-sentence fix]
severity: ERROR  # Always ERROR for new rules — can downgrade later
files:
  - $INCLUDE_PATTERN  # e.g., "*.ts", "*.js", "*.kt"
```

**For each new rule, also produce:**
- 1 bad/ test file (testdata/rules-tests/bad/AG-XXX-v1-$variant.$ext)
- 1 ok/ test file (testdata/rules-tests/ok/AG-XXX-safe-$case.$ext)

**After writing, validate:**
```bash
# Validate YAML syntax (not full semantic validation, just syntax)
for f in rules/astgrep/AG-*-new-*.yaml; do
  echo "--- $f ---"
  python3 -c "import yaml; yaml.safe_load(open('$f'))" && echo "VALID" || echo "INVALID"
done
```

---

## PHASE 5 — TEST VALIDATION (max 20K tokens, 12 min)

Run the rules against the test corpus and verify results.

**Step 5.1 — Check ok/ for false positives:**
```bash
opengrep --config rules/ testdata/rules-tests/ok/ --json 2>/dev/null | \
  python3 -c "import sys,json; r=json.load(sys.stdin); print(f'FP count: {len(r.get(\"results\",[]))}'); [print(x['check_id'],x['path']) for x in r.get('results',[])]"
```
- If any FP exists, identify the rule and file. Tighten the rule (add `pattern-not`). Re-run.
- Max 3 tighten iterations per rule. If not fixed by iteration 3, document as `KNOWN LIMITATION` in the rule YAML header and move on.

**Step 5.2 — Check bad/ for true positives:**
```bash
opengrep --config rules/ testdata/rules-tests/bad/ --json 2>/dev/null | \
  python3 -c "import sys,json; r=json.load(sys.stdin); print(f'TP count: {len(r.get(\"results\",[]))}'); ids=set(x['check_id'] for x in r.get('results',[])); print(f'Unique rules firing: {len(ids)}'); print(f'Rules: {sorted(ids)}')"
```
- Cross-reference against expected rules. If a rule has 0 TP, check if it needs a variant added.

**Step 5.3 — Validate ast-grep rules:**
```bash
for f in rules/astgrep/*.yaml; do
  ast-grep scan --config "$f" testdata/rules-tests/ --json 2>/dev/null | \
    python3 -c "import sys,json; r=json.load(sys.stdin); print(f'$(basename $f): {len(r)} results')" 2>/dev/null || \
    echo "$(basename $f): ast-grep not available or parse error"
done
```

---

## PHASE 6 — SELLING POINTS DOCUMENT (max 10K tokens, 5 min)

Write a concise competitive differentiator table to `docs/rules/rules_selling_points.md`.

Create the directory if it doesn't exist.

**Output — Exact format in the file:**

```markdown
# ZeroTrust.sh Rules — Competitive Differentiation

## Coverage Summary
- Total rules: N
- UNIQUE (no community equivalent): N
- BETTER than community equivalent: N
- OVERLAP (intentionally kept for completeness): N
- Languages covered: Python, Java, [new languages]

## Rules With No Community Equivalent
| Rule | What It Detects | Why No Competitor Covers This |
|---|---|---|

## Rules That Are Strictly Better Than Community Versions
| Rule | Community Version | ZeroTrust.sh Version | Why Better |
|---|---|---|---|

## Rules Intentionally Overlapping (Kept for Completeness)
| Rule | Community Equivalent | Rationale |
|---|---|---|

## Language Coverage
| Language | Rules | Engine | Notes |
|---|---|---|---|

## Key Differentiators Summary (3 sentences max)
```

---

## CHECKPOINT & ESCALATION PROTOCOL

If ANY of these occur, stop the current phase and write a checkpoint:

- **Token exhaustion**: You have <5K tokens remaining in your budget. Write a `.checkpoint.md` file to `docs/audit/checkpoint_YYMMDD.md` with: completed phases, what was found, what remains, exact file paths changed.
- **Phase timeout**: A phase takes >1.5× its allocated time. Stop, report partial progress, and ask: "Should I continue this phase or skip to the next?" The answer is always "skip to next" unless overridden.
- **Detection loop**: You read the same file >2 times in a row. STOP. The answer is not in that file. Move to the next phase.
- **Semantic confusion**: If a rule's intent is unclear (e.g., "what does PY-005 actually detect?"), read only the rule's `message:` field and `pattern:` block. If still unclear after 1 read, assume the rule is well-intentioned but poorly documented — flag it as `DOCUMENTATION NEEDED` in the audit table and move on. Do NOT spend >60 seconds on any single rule's semantic interpretation.
- **Tool failure**: If `opengrep` or `ast-grep` are not installed or fail, note it in the checkpoint and proceed with syntactic validation only (YAML parse check).

---

## EXIT SUMMARY

After all phases complete (or at checkpoint), write this exact summary to the user:

```
## Task 06 — Completion Report

### Phases Completed
- [ ] Phase 1 — Audit: N rules audited, X UNIQUE, X BETTER, X OVERLAP, X WEAKER
- [ ] Phase 2 — Community Comparison: X rules to keep, X to upgrade, X to eliminate
- [ ] Phase 3 — Language Gap: X languages missing, X new rules recommended
- [ ] Phase 4 — Write: X rules upgraded, X eliminated, X new ast-grep rules written
- [ ] Phase 5 — Test: X% TP rate, X FPs found and fixed
- [ ] Phase 6 — Selling Points: docs/rules/rules_selling_points.md written

### Files Changed
- rules/python/:
- rules/java/:
- rules/generic/:
- rules/astgrep/:
- testdata/rules-tests/:
- docs/:

### Rules Eliminated (and why)
| Rule | Reason |
|---|---|

### Rules Upgraded (and what changed)
| Rule | Change | Why |
|---|---|---|

### New Rules Written
| Rule ID | Language | Vulnerability | Test Files |
|---|---|---|---|

### Remaining Gaps (not addressed, deferred)
| Gap | Reason | Deferred To |
|---|---|---|

### Action Items for Human
1. [Any manual test needed — e.g., "GN-003 still missing bad/ file — needs manual Unicode byte creation"]
2. [Any design decision needed — e.g., "Eliminating JV-003 overlaps with community — confirm?"]
```

---

## FINAL REMINDERS

- **Browse the web ONLY in Phase 2.3.** Max 4 fetches. If a fetch fails, use fallback data. Do NOT browse social media, blog posts, or documentation — only the `semgrep/semgrep-rules` GitHub tree pages and raw YAML files.
- **Do NOT rewrite rules that are working.** The goal is surgical improvement, not rebuild.
- **Do NOT add speculative rules.** Every new rule must trace to a real AI-agent vulnerability pattern.
- **Do NOT run `opengrep` across the entire project directory.** Scope it to `testdata/rules-tests/`.
- **If `ast-grep` is not installed**, note it in the exit summary and write ast-grep rules anyway (they validate on YAML parse).
- **When in doubt between two interpretations of a pattern, assume the narrower one** — fewer FPs is better than more TPs for a developer-facing tool.
