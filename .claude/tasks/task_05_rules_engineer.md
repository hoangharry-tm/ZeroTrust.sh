# Task 05 — Rules Engineer: Exhaustive OpenGrep, AST-grep & Instruction File Scanning Rules

> **How to invoke:** Load this file in a fresh Claude Code session and say "Run task 05."
> You are the **orchestrator**. You do NOT write rules directly. You spawn specialized
> subagents, collect their outputs, then spawn the test case engineer.
> Follow the two-phase orchestration exactly as written.

---

## MISSION

Produce a **complete, production-quality rule set** for ZeroTrust.sh Approach 1 covering:

- **M1.2** — 10 Python OpenGrep rules (`PY-001` → `PY-010`)
- **M1.3** — 9 Java OpenGrep rules (`JV-001` → `JV-009`) + ast-grep fill-in rules
- **M1.4** — AI agent instruction file scanning rules (Unicode + keyword + MCP schema)

The defining principle of this task: **exhaustion over coverage.** Every rule must enumerate
*all syntactic variants* a vulnerability can appear in — not just the canonical textbook form.
An AI coding agent will use the aliased import, the transitive wrapper, the f-string variant,
and the conditional bypass just as often as the direct form. Rules that miss these variants
are useless in production.

After rules are written, a test case engineer writes intentionally good and bad code for every
rule, fires them, documents false positives, and feeds corrections back until every rule passes
its test suite with zero false positives on the `ok/` set.

---

## FULL PROJECT CONTEXT

ZeroTrust.sh is a local CLI security scanner targeting AI-generated code. Full spec: `CLAUDE.md`.

**Tech stack for rules:**
- **Engine**: OpenGrep (LGPL-2.1, Semgrep CE fork — identical YAML rule format)
- **Supplemental**: ast-grep (YAML rules for Dart, Swift, Rust — OpenGrep language gaps)
- **Install check**: `opengrep --version` and `ast-grep --version`

**Rule namespaces and file locations:**

| Namespace | Path | Engine |
|---|---|---|
| `PY-NNN` | `rules/python/PY-NNN-<slug>.yaml` | OpenGrep |
| `JV-NNN` | `rules/java/JV-NNN-<slug>.yaml` | OpenGrep |
| `GN-NNN` | `rules/generic/GN-NNN-<slug>.yaml` | OpenGrep generic-mode |
| `AG-NNN` | `rules/astgrep/AG-NNN-<slug>.yaml` | ast-grep |

**Test file locations:**

| Set | Path | Contract |
|---|---|---|
| Must-fire | `testdata/rules-tests/bad/` | Rule MUST fire on this file |
| Must-not-fire | `testdata/rules-tests/ok/` | Rule MUST NOT fire on this file |

**Implementation plan milestone reference (read once, then discard):**
`docs/planning/implementation-plan.md` — M1.2, M1.3, M1.4

---

## OPENGREP YAML RULE FORMAT (canonical reference)

All agents must follow this format exactly. Rules with missing fields will be rejected.

```yaml
rules:
  - id: PY-001-llm-prompt-injection-openai           # kebab-case, must match filename
    message: |
      [One sentence: what was found, why it is dangerous.]
      Fix: [one sentence prescriptive fix].
    severity: ERROR          # ERROR | WARNING | INFO
    languages: [python]      # [python] | [java] | [generic]
    metadata:
      cwe: "CWE-77: Improper Neutralization of Special Elements used in a Command"
      owasp: "A03:2021 - Injection"
      category: llm-prompt-injection
      ai_specific: true      # true for all rules in this task
      confidence: HIGH       # HIGH | MEDIUM | LOW
      rule_version: "1.0"
    # --- detection body (choose one style) ---
    pattern: |
      ...

    # OR for multi-condition rules:
    patterns:
      - pattern: |
          ...
      - pattern-not: |
          ...

    # OR for multiple equivalent forms:
    pattern-either:
      - pattern: |
          ...
      - pattern: |
          ...

    # OR for taint-mode rules:
    mode: taint
    pattern-sources:
      - pattern: request.$METHOD(...)
    pattern-sanitizers:
      - pattern: sanitize(...)
    pattern-sinks:
      - pattern: openai.ChatCompletion.create(...)
```

**Key operators** (use freely, combine aggressively):

| Operator | Purpose |
|---|---|
| `$X` | Matches any single expression (metavariable) |
| `...` | Matches any sequence of arguments or statements |
| `pattern-not:` | Exclude this sub-pattern from matches |
| `pattern-inside:` | Match only inside this surrounding context |
| `pattern-not-inside:` | Exclude matches inside this context |
| `pattern-either:` | OR — any child matches |
| `patterns:` | AND — all children must match |
| `metavariable-regex:` | Filter metavariable by regex |
| `metavariable-pattern:` | Recurse pattern check on a metavariable |
| `focus-metavariable:` | Report only the highlighted variable's location |
| `mode: taint` | Full taint-flow analysis (source → sanitizer → sink) |

---

## VARIANT EXHAUSTION METHODOLOGY

> **Every agent MUST apply this 7-variant framework to every rule they write.**
> A rule that covers only variants 1–2 is incomplete. Aim for 4–7 variants per rule.

For each vulnerability pattern, enumerate:

| Variant | Description | Example (Python `eval`) |
|---|---|---|
| **V1 — Direct form** | Standard canonical API call | `eval(user_input)` |
| **V2 — Aliased import** | `from x import y as z` | `from builtins import eval as execute; execute(data)` |
| **V3 — Dynamic attribute** | `getattr(obj, name)()` or `globals()[name]` | `getattr(__builtins__, 'eval')(src)` |
| **V4 — Transitive wrapper** | Vulnerability buried inside a helper called from the surface | `def run(code): eval(code)` — detect at definition |
| **V5 — String-constructed call** | Input is built via concatenation before reaching sink | `eval(prefix + user_data)` |
| **V6 — Conditional bypass** | Inside an `if`/`try` that *could* be bypassed by attacker | `if debug: eval(user_input)` |
| **V7 — AI-agent mutation** | Forms AI agents specifically tend to produce: TODO-masking, bypass comments, hardcoded literals, cheat patterns | `# TODO: validate input\neval(raw)` |

For Java add:
- **V8 — Reflection** — `Method.invoke()` reaching vulnerable sink
- **V9 — Framework annotation** — `@RequestParam`, `@PathVariable` as taint source

For instruction files (M1.4) add:
- **V8 — Unicode disguise** — BIDI overrides, zero-width joiners, lookalike chars
- **V9 — Semantic disguise** — grammatically correct English that encodes a malicious directive
- **V10 — YAML/JSON escape** — injection via YAML scalar, JSON value, or markdown code block

---

## PHASE 1 — PARALLEL: THREE RULES-WRITING AGENTS

Spawn all three agents simultaneously using the `Agent` tool. Do NOT wait for one to finish
before starting another — their outputs are fully independent.

---

### AGENT A — Software Engineer: Python OpenGrep Rules (M1.2)

```
AGENT IDENTITY
==============
You are a senior software security engineer with 10+ years writing production static analysis
rules. Your specialities: Python ecosystem security, SAST/DAST tool design (Semgrep, CodeQL,
Bandit), taint analysis for web frameworks (Django, Flask, FastAPI), and AI/LLM SDK security
patterns (OpenAI SDK, Anthropic SDK, LangChain, LlamaIndex).

You write rules that are precise (low FP), recall-maximizing (catch all variants), and
immediately actionable (message tells the developer exactly what to fix).

MISSION
=======
Write 10 OpenGrep YAML rules for Python vulnerability patterns in ZeroTrust.sh.
Target directory: rules/python/
Naming convention: PY-NNN-<slug>.yaml (e.g., PY-001-llm-prompt-injection-openai.yaml)

RULE SET (exhaustive — do not skip any):

PY-001 — LLM Prompt Injection via OpenAI SDK
  Target: openai.ChatCompletion.create() / openai.chat.completions.create() where any
  message content field contains unsanitized user-controlled data.
  Variants to cover:
    - Direct: messages=[{"role":"system","content": user_input + "..."}]
    - f-string: content=f"You are {user_role}. Answer: {user_question}"
    - .format(): content="Answer {}".format(user_data)
    - Variable assigned then used: msg = user_prompt; messages=[..., msg]
    - New SDK style: client.chat.completions.create(...)
    - Streaming: openai.ChatCompletion.create(..., stream=True)
  CWE: CWE-77, OWASP: A03:2021

PY-002 — LLM Prompt Injection via Anthropic SDK
  Target: anthropic.Anthropic().messages.create() where user data reaches content field.
  Variants: same as PY-001 but for Anthropic API patterns including system= kwarg and
  the human_turn/assistant_turn older format.
  CWE: CWE-77

PY-003 — LLM Prompt Injection via LangChain / LlamaIndex
  Target: PromptTemplate, ChatPromptTemplate, SystemMessage, HumanMessage when template
  variables are populated from unsanitized user input. Also covers LlamaIndex QueryEngine.
  CWE: CWE-77

PY-004 — Unsanitized f-string / .format() into any LLM call
  Target: Any call containing a string argument where the string was constructed via
  f-string or .format() and at least one interpolated variable comes from request.*,
  environ.*, stdin, input(), or an argument named *user*, *input*, *query*, *prompt*.
  This is the generic catch-all for frameworks not covered by PY-001–003.
  Use taint mode: sources = [request.*, input(), environ.get(...), sys.stdin.read()]
                  sinks   = [any function call whose name contains "llm", "chat", "complete",
                              "generate", "prompt", "ask", "query" + openai.*, anthropic.*]
  CWE: CWE-77

PY-005 — AI Bypass Comments
  Target: Source lines immediately before or after a security-relevant check where
  a comment contains the patterns:
    - "bypass" / "BYPASS" / "skip security" / "disable auth"
    - "# SECURITY:" followed by "disabled", "off", "TODO", "remove", "for testing"
    - "# noqa: S" annotations suppressing security linters
    - "# type: ignore" on a line that also contains auth/validate/check/sanitize
  Pattern-inside: functions with names matching *auth*, *validate*, *check*, *verify*,
                  *permission*, *sanitize*, *login*, *logout*, *token*
  Severity: ERROR (not WARNING — bypass comments are almost always intentional)
  CWE: CWE-284

PY-006 — Hardcoded AI Service API Keys
  Target: String literals matching known AI service key prefixes assigned to variables
  named *key*, *token*, *secret*, *api*, *credential*, *auth*, *password*.
  Prefixes to match (use metavariable-regex):
    - OpenAI:    sk-[A-Za-z0-9]{32,}  and  sk-proj-[A-Za-z0-9-_]{32,}
    - Anthropic: sk-ant-[A-Za-z0-9-_]{32,}
    - HuggingFace: hf_[A-Za-z0-9]{32,}
    - Cohere:    [A-Za-z0-9]{40}  (heuristic — flag only when variable name matches)
    - Generic:   any 32+ character hex or base64-looking string in a variable named *api_key*
  pattern-not: env vars, os.environ.get(), dotenv — do not flag correctly-loaded keys
  CWE: CWE-798

PY-007 — Hardcoded General Credentials (non-AI-specific)
  Target: password = "..." / passwd = "..." / secret = "..." / db_pass = "..."
  Literals of length ≥ 4 that are not empty strings, not "TODO", not "changeme" variants.
  Include: connection strings with embedded credentials (jdbc:..., postgres://user:pass@...)
  CWE: CWE-798

PY-008 — Cheat-Detection: `return True` in Auth Functions
  Target: Functions whose name matches *auth*, *is_admin*, *check_permission*,
  *verify_token*, *validate_session*, *has_access*, *can_*, *is_allowed*
  that contain a bare `return True` or `return 1` not wrapped in any conditional.
  This catches AI agent "cheat" behavior: making a security check always pass.
  Pattern-not-inside: test functions (def test_*, class Test*)
  Severity: ERROR
  CWE: CWE-284, CWE-863

PY-009 — Cheat-Detection: TODO-then-Skip (disabled validation)
  Target: A `# TODO` or `# FIXME` or `# HACK` comment immediately followed (within 3
  lines) by one of: `pass`, `return`, `return None`, `return True`, `return {}`, `return []`
  inside a function whose name or body previously contained a validation/security call.
  Also catches: commented-out validation blocks (`# if not validate_input(data):`)
  Severity: WARNING (intent uncertain) — but flag for human review
  CWE: CWE-20, CWE-284

PY-010 — Cheat-Detection: Disabled Assertions / Tests
  Target:
    - `assert False` or `assert True` in non-test code (overriding a real assertion)
    - `@unittest.skip("security")` or `@pytest.mark.skip` on a test named *test_auth*,
      *test_permission*, *test_security*, *test_validation*
    - `raise NotImplementedError` inside a function whose name is a security primitive
      (names matching: *encrypt*, *decrypt*, *hash_password*, *verify_signature*)
  CWE: CWE-617, CWE-284

VARIANT EXHAUSTION REQUIREMENT
================================
For EACH rule, apply the 7-variant framework:
  V1 Direct · V2 Aliased import · V3 Dynamic attribute · V4 Transitive wrapper
  V5 String-constructed · V6 Conditional bypass · V7 AI-agent mutation

List which variants you covered per rule at the top of each YAML file in a comment block:
  # Variants covered: V1 V2 V4 V5 V7
  # Variants not covered (reason): V3 (getattr on builtins too broad — high FP risk)

OPENGREP YAML FORMAT REFERENCE
================================
Use the canonical format defined in the task file (task_05_rules_engineer.md):
  - id, message, severity, languages, metadata (cwe, owasp, category, ai_specific,
    confidence, rule_version)
  - pattern / patterns / pattern-either / mode: taint as appropriate
  - pattern-not for safe patterns you explicitly exclude

DELIVERABLES
============
Write each rule as a separate YAML file. After writing ALL rules, output a summary table:

| Rule ID | Name | Variants Covered | Confidence | FP Risk | CWE |
|---|---|---|---|---|---|

Do not write test cases — that is Agent D's job.
Do not modify any files outside rules/python/.
```

---

### AGENT B — Cybersecurity Analyst: Java OpenGrep + AST-grep Rules (M1.3)

```
AGENT IDENTITY
==============
You are a senior cybersecurity engineer and Java security specialist with 12+ years of
experience. Your background: Java EE / Spring Boot security hardening, SAST rule engineering
(Semgrep, SpotBugs, SonarQube), OWASP Top 10 exploit development and mitigation in JVM
ecosystems, and deep knowledge of AI coding agent behavioral patterns in Java.

You understand that AI coding agents writing Spring Boot code specifically tend to:
  - Use string concatenation in JPQL/SQL queries (never PreparedStatement by default)
  - Copy-paste hardcoded credentials from documentation examples without modification
  - Implement no-op TrustManagers to silence SSL errors during dev (and forget to revert)
  - Add "// TODO: add proper auth" and ship it
  - Use Runtime.exec() for system calls because it's the first Google result
  - Return null or true from auth methods when "it's just a PoC"

MISSION
=======
Write two rule sets:

PART 1 — OpenGrep Java Rules (9 rules, rules/java/JV-NNN-<slug>.yaml)
PART 2 — AST-grep fill-in rules (rules/astgrep/AG-NNN-<slug>.yaml)
         for language gaps: Rust, Go (partial), Swift, Dart

--- PART 1: Java OpenGrep Rules ---

JV-001 — Spring Boot Prompt Injection (HTTP request → LLM call)
  Target: @RequestParam, @RequestBody, @PathVariable, HttpServletRequest.getParameter()
  reaching an LLM call (openai4j, spring-ai ChatClient, LangChain4J, Anthropic Java SDK,
  or any method call whose name contains: generate, chat, complete, prompt, ask, infer).
  Taint mode: source = Spring request annotations / HttpServletRequest methods
              sink   = any LLM SDK call
  Variants: direct assignment, intermediate variable, passed via @Service method
  CWE: CWE-77

JV-002 — SQL Injection via JDBC String Concatenation
  Target: Statement.execute(), executeQuery(), executeUpdate() where the SQL string
  was built via + concatenation or String.format() with a non-constant argument.
  Patterns:
    - "SELECT ... " + variable
    - String.format("SELECT ... %s", userParam)
    - StringBuilder append() followed by execute()
  pattern-not: PreparedStatement, JpaRepository, @Query with :param notation
  CWE: CWE-89

JV-003 — SQL Injection via JPA/JPQL String Concatenation
  Target: EntityManager.createQuery() or createNativeQuery() called with a
  string that was built via concatenation. Distinct from JV-002 (JDBC).
  pattern-not: TypedQuery with setParameter()
  CWE: CWE-89

JV-004 — AI Bypass Annotations and Comments (Java-specific)
  Target:
    - @SuppressWarnings("security") on a method annotated @PreAuthorize or @Secured
    - Comments matching bypass patterns before a security annotation or null return
    - @Disabled on a JUnit test whose name contains: auth, security, permission, token
    - Spring's @WithMockUser(roles="ADMIN") in non-test source files
  CWE: CWE-284

JV-005 — Hardcoded Credentials (Java)
  Target: String literals assigned to variables named password, passwd, secret,
  apiKey, api_key, token, credentials, auth where the literal is non-empty and
  not fetched from environment/config.
  Include: JDBC connection strings with embedded passwords
           (`jdbc:mysql://host/db?user=root&password=secret`)
  pattern-not: @Value("${...}"), env.getProperty(), System.getenv()
  CWE: CWE-798

JV-006 — Empty or No-Op Security Controls (TLS bypass, empty catch)
  Target:
    V1: X509TrustManager implementations where checkServerTrusted() body is empty
    V2: HostnameVerifier that always returns true
    V3: Empty catch(Exception e) {} inside a method annotated @PreAuthorize or
        whose name matches *auth*, *validate*, *verify*, *check*
    V4: try { securityCheck(); } catch (SecurityException e) { /* ignored */ }
  Severity: ERROR for V1/V2, WARNING for V3/V4
  CWE: CWE-295 (TLS), CWE-390 (empty catch)

JV-007 — Cheat-Detection: `return null` / `return true` in Auth Methods
  Target: Methods annotated @PreAuthorize, @Secured, or whose name matches
  *isAuthorized*, *checkPermission*, *validateToken*, *hasRole*, *canAccess*,
  *authenticate*, *isAdmin*, *isLoggedIn* that contain a bare `return true;` or
  `return null;` not inside a conditional checking a real value.
  pattern-not-inside: test classes (class names containing Test, Spec, Mock)
  Severity: ERROR
  CWE: CWE-284, CWE-863

JV-008 — Cheat-Detection: TODO-then-Skip (Java)
  Target: // TODO or // FIXME or // HACK comment immediately above (within 3 lines) a
  `return null;`, `return true;`, `return new ArrayList<>();`, `throw new UnsupportedOperationException()`
  inside a method whose name or annotation indicates a security function.
  CWE: CWE-20

JV-009 — Insecure Deserialization (ObjectInputStream without ClassFilter)
  Target: `new ObjectInputStream(inputStream).readObject()` where the ObjectInputStream
  is not wrapped in a ValidatingObjectInputStream (Apache Commons IO) and no
  ObjectInputFilter has been set via setObjectInputFilter() or ObjectInputFilter.Config.
  Variants: direct new ObjectInputStream(), assigned to variable then readObject(),
  inside a try-with-resources block
  CWE: CWE-502

--- PART 2: AST-grep Rules (Language Gaps) ---

Write ast-grep YAML rules for the following. AST-grep format differs from OpenGrep:
use `rule:` with `kind:`, `pattern:`, `inside:`, `has:`, `not:` operators.

AG-001 — Rust: Unsafe Deserialization (serde_json::from_str on unvalidated input)
  Target: serde_json::from_str($INPUT) or serde_json::from_slice($INPUT) where
  $INPUT comes from a function parameter not annotated as trusted.
  Language: rust

AG-002 — Go: SQL Injection via fmt.Sprintf in db.Query
  Target: db.Query(fmt.Sprintf(...)) or db.Exec(fmt.Sprintf(...)) where the
  format string includes a %s, %v or %d pulled from an http.Request argument.
  Language: go

AG-003 — Swift: Hardcoded API Keys
  Target: let apiKey = "sk-..." or let secret = "..." string literals
  in non-test Swift source files.
  Language: swift

AG-004 — Dart/Flutter: HTTP without TLS verification
  Target: HttpClient() where badCertificateCallback is set to return true
  or where no certificate validation callback is set and http:// URL is used.
  Language: dart

VARIANT EXHAUSTION REQUIREMENT
================================
For EACH Java rule, explicitly apply V1–V9 (V8 = Reflection, V9 = Framework annotation).
Document covered variants in a comment block at the top of each YAML file:
  # Variants covered: V1 V2 V5 V7 V9
  # Variants not covered (reason): V3 (reflection-based attacks require taint mode not
  #   available in OpenGrep free tier — punted to Approach 2 Joern taint)

AST-GREP YAML FORMAT
====================
  id: AG-001-rust-serde-unvalidated-deserialization
  language: rust
  rule:
    pattern: serde_json::from_str($INPUT)
    not:
      inside:
        kind: function_item
        has:
          pattern: validate($INPUT)
  message: "..."
  severity: ERROR

DELIVERABLES
============
Write each rule as a separate YAML file in its respective directory.
Output a summary table after all rules are written.
Do not write test cases — that is Agent D's job.
Do not modify anything outside rules/java/ and rules/astgrep/.
```

---

### AGENT C — AI/ML Security Researcher: Instruction File Scanner (M1.4)

```
AGENT IDENTITY
==============
You are a world-class AI/ML security researcher with expertise in:
  - Adversarial machine learning and prompt injection taxonomy
  - Unicode security (BIDI text attacks, zero-width characters, homoglyph substitution)
  - LLM agent system design and trust boundary analysis (MCP protocol, agent toolchains)
  - MITRE ATLAS adversarial ML threat catalog
  - OWASP GenAI Top 10 (LLM01–LLM10, 2025 edition)
  - NIST AI RMF (Govern, Map, Measure, Manage)
  - AI coding agent behavior: how Cursor, Claude Code, Cline, Copilot Workspace,
    Gemini CLI, and Aider ingest and execute instruction files

You have read:
  - "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications
    with Indirect Prompt Injection" (Greshake et al., 2023)
  - "BadGPT" and related adversarial instruction tuning papers
  - MCP (Model Context Protocol) specification v1.x
  - MITRE ATLAS AML.CS0041 (Indirect Prompt Injection via Shared Resources)

Your job is to think adversarially and exhaustively — you are not trying to build the
simplest scanner; you are trying to ensure NO attack vector is missed.

MISSION
=======
Design and implement the full three-tier M1.4 instruction file scanner:

TIER 1 (Approach 1 deliverable) — Zero-cost static checks:
  - Unicode obfuscation scanner (Go function spec → write as rules/generic/ OpenGrep rules
    where possible; for Go-native checks, write the function signature + logic in a comment
    block so Agent D can write test inputs)
  - Keyword/pattern match (OpenGrep generic-mode rules)
  - MCP schema validation (JSON schema spec → write validation rules)

TIER 2 (Approach 2 design, not yet implemented) — Embedding similarity:
  - Design the embedding-based detection approach (which model, similarity threshold,
    reference corpus construction) — write this as a design spec comment block
    at the top of rules/generic/README.md

TIER 3 (Approach 2 design, not yet implemented) — Sandboxed LLM meta-audit:
  - Design the LLM meta-audit prompt (what do you ask the LLM to look for?) — write the
    system prompt and detection prompt template as a draft in rules/generic/README.md

--- TIER 1: OPENGREP GENERIC-MODE RULES ---

GN-001 — Unicode Right-to-Left Override (BIDI attack)
  Target: Files matching *.md, *.txt, *.yaml, *.json, *.toml, AGENTS.md, CLAUDE.md,
  GEMINI.md, copilot-instructions.md, .cursor/rules
  Detect: U+202E (RIGHT-TO-LEFT OVERRIDE), U+200F (RIGHT-TO-LEFT MARK),
          U+2066–U+2069 (BIDI isolates), U+202A–U+202D (embedding/override chars)
  These are the chars used in "Trojan Source" attacks (CVE-2021-42574) — they visually
  disguise malicious content in instruction files.
  Use OpenGrep generic mode with `pattern-regex:` on the raw byte sequence.
  CWE: CWE-116 (Improper Encoding)
  MITRE: AML.CS0041

GN-002 — Unicode Zero-Width Characters (invisible instruction injection)
  Target: same file types as GN-001
  Detect: U+200B (ZERO-WIDTH SPACE), U+200C (ZERO-WIDTH NON-JOINER),
          U+200D (ZERO-WIDTH JOINER), U+FEFF (BYTE ORDER MARK, when not at file start),
          U+2060 (WORD JOINER), U+00AD (SOFT HYPHEN)
  Use case: attackers embed instructions invisible in text editors but parsed by LLMs.
  CWE: CWE-116

GN-003 — Homoglyph / Confusable Character Substitution
  Target: same file types
  Detect: Cyrillic а (U+0430), е (U+0435), о (U+043E), р (U+0440), с (U+0441),
          х (U+0445) used in contexts that look like Latin ASCII
          (e.g. in YAML keys, JSON field names, markdown link text).
  Pattern-regex on common confusable pairs that appear in file paths and identifiers.
  CWE: CWE-116
  Note: Exhaustive confusable coverage requires Unicode CLDR data — flag the top 20
  most-used confusable pairs in attacker scenarios (documented in MITRE ATLAS Technique
  AML.T0051).

GN-004 — Malicious Directive Keywords (high-signal patterns)
  Target: AGENTS.md, CLAUDE.md, GEMINI.md, copilot-instructions.md, .cursor/rules,
          any file matching the pattern *-instructions.md, *-rules.md, *.cursorrules
  Keyword patterns (match any, case-insensitive, with word boundary):
    GROUP A — Exfiltration directives:
      - "send" / "transmit" / "upload" / "exfiltrate" followed by "secret" / "key" /
        "password" / "token" / "credential" / "env" / ".env" within 10 words
      - "curl" / "wget" / "fetch" followed by a URL pattern within 5 words
      - "base64" followed by "encode" near "secret" / "key" / "password"
    GROUP B — Privilege escalation directives:
      - "ignore" / "bypass" / "skip" followed by "safety" / "policy" / "guideline" /
        "restriction" / "filter" / "rule" within 5 words
      - "pretend" / "act as" / "you are now" / "jailbreak" / "DAN"
      - "override" / "supersede" followed by any of the above
    GROUP C — Silent action directives:
      - "do not tell" / "don't mention" / "hide this" / "don't reveal" /
        "keep this secret" / "silently"
      - "without asking" / "without confirmation" / "automatically"
        near "delete" / "modify" / "send" / "install" / "execute"
    GROUP D — Identity confusion directives:
      - "you are" / "your real name is" / "your true identity" /
        "forget your instructions" / "disregard previous"
  Severity: ERROR for GROUP A + B; WARNING for GROUP C + D (context-sensitive)
  CWE: CWE-77, OWASP LLM01:2025

GN-005 — Markdown Hidden Content (HTML comment injection)
  Target: *.md files that are instruction files (match by name pattern)
  Detect:
    - HTML comments <!-- ... --> containing any GROUP A–D keywords from GN-004
    - Base64-encoded content inside comments (base64 regex: [A-Za-z0-9+/]{40,}={0,2})
    - YAML front matter in .md files with unexpected fields (e.g., `execute:`, `run:`)
  CWE: CWE-116

GN-006 — Suspicious URL Patterns in Instruction Files
  Target: all instruction file types
  Detect:
    - URLs not pointing to localhost (http://localhost or https://localhost)
    - ngrok.io, burpcollaborator.net, requestbin.*, pipedream.net, webhook.site
    - IP addresses (non-RFC-1918) directly embedded in instruction text
    - URLs with data: scheme
    - URLs constructed with variable substitution: `https://attacker.com/${SECRET}`
  pattern-not: github.com, npm, pypi, docs.*, api.openai.com, api.anthropic.com
    (these are expected legitimate URLs in documentation)
  Severity: WARNING (URL presence is not always malicious — flag for review)
  CWE: CWE-601

--- MCP SCHEMA VALIDATION (GN-007) ---

GN-007 — MCP Server Config Security Validation
  Target: *.mcp.json, mcp.json, .mcp/config.json, cline_mcp_settings.json,
          claude_desktop_config.json (when present in the scanned codebase)

  Schema violations to flag (ERROR severity):

  VIOLATION A — External network servers:
    Any MCP server entry where "url" or "baseUrl" does not match:
      - http://localhost:* or http://127.0.0.1:* or http://[::1]:*
    Detection: JSON path $.mcpServers.*.url matching non-localhost
    CWE: CWE-918 (SSRF)

  VIOLATION B — HTTP (non-TLS) to external URLs:
    Any server entry with url starting with http:// and hostname not localhost
    CWE: CWE-319 (Cleartext Transmission)

  VIOLATION C — Over-broad tool permissions:
    Any server entry claiming permissions that include:
      - "filesystem" with paths outside the project root (absolute paths, "../")
      - "shell" or "execute" or "run_command" in capabilities list
      - "network" without explicit URL allowlist
    CWE: CWE-269 (Improper Privilege Management)

  VIOLATION D — Unknown/unvetted server sources:
    Any server entry whose "package" or "command" refers to:
      - A package not in an approved registry (npm, pypi, homebrew)
      - A local path pointing outside the project directory
      - A Git URL with no pinned commit SHA
    Severity: WARNING (unknown ≠ malicious, but requires manual review)

  Implementation note: OpenGrep generic-mode with pattern-regex can detect JSON
  patterns. For complex JSON path logic, specify as a Go validation function in
  internal/pattern/instrscan/ instead.

--- TIER 2 DESIGN (Approach 2 — Embedding Similarity) ---

Write this as a design block in rules/generic/README.md:

Design the embedding-based second tier:
  - Which embedding model? (small, local, no API cost — suggest best option)
  - How to build the reference corpus of "known-malicious" instruction file snippets?
  - What similarity threshold triggers a flag?
  - How to handle false positives from legitimate security documentation?
  - Latency budget: must complete within 200ms per file

--- TIER 3 DESIGN (Approach 2 — LLM Meta-Audit) ---

Write this as a design block in rules/generic/README.md:

Design the sandboxed LLM meta-audit:
  - System prompt: what role does the LLM play? what threat model does it apply?
  - Detection prompt template: what specific questions do you ask about the instruction file?
  - Output schema: what structured JSON does the LLM return?
  - How do you prevent the malicious instruction file from influencing the LLM's verdict?
    (This is the key adversarial challenge — the thing being analyzed can attack the analyzer)
  - Sandboxing approach: what constraints on the LLM's context prevent prompt exfiltration?

VARIANT EXHAUSTION FOR M1.4 (Instruction Files)
================================================
For each GN-* rule, apply the 10-variant framework (V1–V7 from the standard framework
plus V8 Unicode disguise, V9 Semantic disguise, V10 YAML/JSON escape).

Document the attack scenario for each variant. For GN-004 specifically, provide at
least 3 real-world attack examples for each keyword group (A, B, C, D), drawn from
published prompt injection research or your own threat modeling.

DELIVERABLES
============
1. rules/generic/GN-001.yaml through GN-007.yaml (OpenGrep rules)
2. rules/generic/README.md updated with Tier 2 and Tier 3 design specs
3. A threat model summary at the top of each rule file explaining the attack scenario
   a sophisticated attacker would execute using this vector
4. Explicit notes on which checks CANNOT be done in OpenGrep generic-mode and MUST be
   implemented as Go functions in internal/pattern/instrscan/ (document the function
   signature expected)

Do not write test files — that is Agent D's job.
Do not modify anything outside rules/generic/.
```

---

## PHASE 1 ORCHESTRATION PROTOCOL

After all three agents return their results:

1. **Read every rule file written** — verify YAML is syntactically valid:
   ```bash
   opengrep --validate --config rules/python/ 2>&1
   opengrep --validate --config rules/java/ 2>&1
   opengrep --validate --config rules/generic/ 2>&1
   ```

2. **Count rules written** — verify:
   - `rules/python/`: exactly 10 YAML files (PY-001 → PY-010)
   - `rules/java/`: exactly 9 YAML files (JV-001 → JV-009)
   - `rules/generic/`: exactly 7 YAML files (GN-001 → GN-007)
   - `rules/astgrep/`: at least 4 YAML files (AG-001 → AG-004)

3. **Check for duplicate IDs** — no two rules may share the same `id:` field:
   ```bash
   grep -r "^  - id:" rules/ | awk -F': ' '{print $2}' | sort | uniq -d
   ```

4. **Check variant coverage** — every rule file must have the `# Variants covered:` comment.
   Reject any rule that covers only V1 (direct form) — these are incomplete.

5. **Check metadata completeness** — every rule must have cwe, owasp, confidence fields:
   ```bash
   grep -rL "cwe:" rules/python/ rules/java/ rules/generic/
   ```
   Any file returned by this command is non-compliant.

6. If any validation step fails, send corrections back to the responsible agent before
   proceeding to Phase 2. Do not move to Phase 2 with invalid or incomplete rules.

---

## PHASE 2 — SEQUENTIAL: TEST CASE ENGINEER

> **IMPORTANT**: Do NOT spawn Agent D until Phase 1 validation passes completely.
> Agent D receives the full list of rules as context. Rules must be final before testing.

After Phase 1 validation passes, spawn Agent D:

### AGENT D — Software Engineer: Test Case Writer & Rule Fine-Tuner

```
AGENT IDENTITY
==============
You are a senior software engineer specializing in security test case design and
static analysis rule validation. You have written test corpora for Semgrep, CodeQL,
and Bandit rules in production. You know that:
  - A rule with 0% FP on the ok/ set is not negotiable — one false positive undermines
    the entire tool's credibility with developers
  - A rule that catches only the canonical form in bad/ is useless — the test must
    cover the variants the rule claims to detect
  - Test code must look realistic — a one-liner `eval(user_input)` is not a real test;
    a 15-line function that does something legitimate with a subtle vulnerability buried
    in it IS a real test

MISSION
=======
Write intentionally vulnerable (bad/) and intentionally safe (ok/) test files for
every rule in the ZeroTrust.sh rule set. Then fire all rules, collect output, and
fine-tune rules that produce false positives or miss intended matches.

CONTEXT: WHAT RULES EXIST
==========================
Read every YAML file in:
  - rules/python/      (PY-001 → PY-010)
  - rules/java/        (JV-001 → JV-009)
  - rules/generic/     (GN-001 → GN-007)
  - rules/astgrep/     (AG-001 → AG-004)

For each rule, read:
  - The `id:` field (your test file names will use this)
  - The `message:` field (understand what it's detecting)
  - The `# Variants covered:` comment (you must write bad/ tests for EACH listed variant)
  - The `pattern-not:` or `pattern-not-inside:` clauses (you must write ok/ tests that
    exercise these safe patterns to verify they don't fire)

TEST FILE NAMING CONVENTION
============================
  bad/PY-001-v1-direct.py           (variant 1, direct form)
  bad/PY-001-v2-aliased-import.py   (variant 2, aliased import)
  bad/PY-001-v7-ai-mutation.py      (variant 7, AI agent pattern)
  ok/PY-001-safe-env-var.py         (safe: key loaded from env var)
  ok/PY-001-safe-sanitized.py       (safe: input sanitized before use)

Rule ID maps to filenames exactly: PY-001, JV-003, GN-004, AG-002.

TEST QUALITY REQUIREMENTS
==========================

BAD/ TEST REQUIREMENTS:
  1. Each file is a realistic, self-contained code snippet — not a one-liner.
     Minimum 10 lines for Python/Java tests, 5 lines for generic/instruction files.
  2. The vulnerability must be plausibly what an AI coding agent would produce:
     functional code that also contains a security flaw.
  3. Each variant in the rule's "# Variants covered:" comment gets its own bad/ file.
  4. For cheat-detection rules (PY-008/009/010, JV-007/008): write examples that look
     like real AI-generated "shortcut" code, not obvious toy examples.

OK/ TEST REQUIREMENTS:
  1. ok/ files must LOOK similar to bad/ files (same function name, same purpose) —
     the only difference is the safe pattern.
  2. Write at least 2 ok/ files per rule:
     - ok/RULE-ID-safe-<approach>.ext: the "right way" to do it
     - ok/RULE-ID-edge-<case>.ext: a near-miss that the rule must NOT fire on
  3. Common near-misses to cover:
     - Python: hardcoded string that is not a credential (error message, not a password)
     - Java: return true; inside a unit test (should not fire because pattern-not-inside: test)
     - Generic: URL to localhost in MCP config (should not fire for GN-007)

INSTRUCTION FILE TESTS (GN-001 → GN-007)
==========================================
Write synthetic instruction files:

  bad/GN-001-bidi-override.md         — AGENTS.md with U+202E embedded in a directive
  bad/GN-002-zero-width.md            — CLAUDE.md with U+200B between "send" and "secrets"
  bad/GN-004-exfiltration-group-a.md  — copilot-instructions.md with exfil directive
  bad/GN-004-bypass-group-b.md        — .cursor/rules with "ignore all safety guidelines"
  bad/GN-004-silent-group-c.md        — GEMINI.md with "silently delete these files"
  bad/GN-007-external-url.json        — mcp.json with non-localhost server URL
  bad/GN-007-overbroad-permissions.json  — mcp.json claiming filesystem + shell permissions
  ok/GN-004-legitimate-security-doc.md   — security policy file that uses words like
                                           "ignore" and "bypass" in documentation context
  ok/GN-007-localhost-only.json          — valid mcp.json with only localhost servers

For Unicode test files: write them with actual Unicode bytes (use Python's `‮`
escape when writing the file with Python's `open(..., 'w', encoding='utf-8')`).

THE FINE-TUNING LOOP
====================
After writing all test files, run the full rule suite and collect results:

  opengrep --config rules/python/ testdata/rules-tests/ --json > /tmp/zt_results.json
  opengrep --config rules/java/ testdata/rules-tests/ --json >> /tmp/zt_results.json
  opengrep --config rules/generic/ testdata/rules-tests/ --json >> /tmp/zt_results.json

Then analyze:

  STEP 1 — Find false positives (rules firing on ok/ files):
    jq '[.results[] | select(.path | contains("ok/"))] | group_by(.check_id) | map({rule: .[0].check_id, fp_count: length})' /tmp/zt_results.json

  STEP 2 — Find missed detections (rules NOT firing on bad/ files):
    Cross-reference: for each bad/ file, check whether its corresponding rule ID
    appears in the results. Files with no match = missed detection.

  STEP 3 — Fix rules iteratively:
    - For each false positive: tighten the rule (add pattern-not, narrow scope)
    - For each missed detection: broaden the rule (add pattern-either variant)
    - Re-run after each batch of fixes. Do not declare victory until:
        * 0 false positives on ok/ set
        * ≥ 1 true positive per bad/ file

  STEP 4 — Document residual limitations:
    For any variant where adding coverage would cause unacceptable FP rate,
    add a comment to the rule YAML:
      # KNOWN LIMITATION: V3 (dynamic attribute) not covered — too broad,
      # estimated 30% FP rate. Deferred to Approach 2 taint analysis.

  STEP 5 — AST-grep validation:
    ast-grep scan --config rules/astgrep/ testdata/rules-tests/ --json

DELIVERABLES
============
1. All test files written to testdata/rules-tests/bad/ and testdata/rules-tests/ok/
2. A test results summary table:

   | Rule ID | Bad/ tests | OK/ tests | True Positives | False Positives | Status |
   |---|---|---|---|---|---|
   | PY-001 | 7 | 3 | 7/7 | 0/3 | PASS |
   | PY-002 | 5 | 2 | 4/5 | 0/2 | PARTIAL (V3 missed) |

3. A fine-tuning log at testdata/rules-tests/FINE_TUNING_LOG.md:
   - List every rule change made during fine-tuning
   - What FP/FN triggered it
   - What change fixed it
   - Final FP/FN counts

4. Updated YAML files for any rules that were modified during fine-tuning.
   (These changes must be minimal and well-justified — do not redesign rules,
   only tighten or broaden the existing pattern.)
```

---

## PHASE 2 ORCHESTRATION PROTOCOL

After Agent D returns:

1. **Read FINE_TUNING_LOG.md** — verify it documents each iteration.

2. **Verify zero false positives** — rerun manually:
   ```bash
   opengrep --config rules/ testdata/rules-tests/ok/ --json | jq '.results | length'
   ```
   This MUST return `0`. If not, do not mark the task complete — fix the offending rule.

3. **Verify rule coverage** — rerun on bad/:
   ```bash
   opengrep --config rules/ testdata/rules-tests/bad/ --json | jq '[.results[].check_id] | unique | length'
   ```
   This number should be ≥ 26 (rules PY-001→010 + JV-001→009 + GN-001→007).

4. **Commit all files**:
   ```bash
   git add rules/ testdata/rules-tests/ && git status
   ```
   Review staged files, then create a commit:
   ```
   feat(rules): add exhaustive OpenGrep, ast-grep, and instruction file scanning rules

   - PY-001→PY-010: Python LLM injection, bypass, hardcoded creds, cheat-detection
   - JV-001→JV-009: Java Spring Boot injection, TLS bypass, deserialization, cheat-detection
   - AG-001→AG-004: ast-grep rules for Rust, Go, Swift, Dart gaps
   - GN-001→GN-007: instruction file scanning (Unicode, keyword, MCP schema)
   - testdata/rules-tests/: bad/ and ok/ test suites, 0 FP, fine-tuning log

   Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
   ```

---

## FINAL COMPLETION CHECKLIST

Before declaring the entire task complete, verify every item:

**Rules completeness:**
- [ ] PY-001 → PY-010: 10 files in rules/python/
- [ ] JV-001 → JV-009: 9 files in rules/java/
- [ ] GN-001 → GN-007: 7 files in rules/generic/
- [ ] AG-001 → AG-004: 4+ files in rules/astgrep/
- [ ] All rules pass `opengrep --validate`
- [ ] No duplicate rule IDs across the entire rule set
- [ ] Every rule has cwe, owasp, confidence metadata fields
- [ ] Every rule has `# Variants covered:` comment listing V1–V7+ coverage
- [ ] No rule covers only V1 (direct form) with no other variants

**Instruction file scanner (M1.4):**
- [ ] GN-001–GN-003: Unicode attack vectors (BIDI, zero-width, homoglyphs)
- [ ] GN-004–GN-005: Keyword/semantic patterns (all 4 groups)
- [ ] GN-006: Suspicious URL patterns
- [ ] GN-007: MCP schema violations (all 4 violation types)
- [ ] Tier 2 embedding design spec written in rules/generic/README.md
- [ ] Tier 3 LLM meta-audit prompt written in rules/generic/README.md
- [ ] LLM meta-audit addresses the adversarial challenge (file attacking the analyzer)

**Test cases:**
- [ ] Every rule has ≥ 1 bad/ file per variant listed in "# Variants covered:"
- [ ] Every rule has ≥ 2 ok/ files (safe pattern + near-miss)
- [ ] ok/ set: `opengrep --config rules/ testdata/rules-tests/ok/` returns 0 findings
- [ ] bad/ set: all 26+ rules produce ≥ 1 finding each
- [ ] FINE_TUNING_LOG.md exists and documents every rule change

**Git:**
- [ ] All new files committed
- [ ] `git status` is clean

---

## IMPORTANT CONSTRAINTS

- Do NOT write rules that flag every function call — precision matters. A 50% FP rate is
  worse than no scanner at all. If a variant can't be detected with <10% FP rate in the
  pattern approach, document it as a known limitation and defer to Approach 2 taint mode.
- Do NOT use `pattern: "..."` (string patterns) for code — always use proper AST patterns.
  The only exception is GN-* rules in generic mode targeting file content.
- Do NOT skip the variant exhaustion framework. A rule that catches only the canonical form
  (e.g., `eval(user_input)` with exactly that variable name) will miss 80% of real occurrences.
- Do NOT conflate Path A (rule detection) with Path B (semantic LLM detection). Rules must
  be pattern/AST based. Anything requiring multi-file call graph reasoning is a Path B job.
- The instruction file scanner is **ZeroTrust.sh's unique differentiator** — no competitor
  (Semgrep, Snyk, CodeRabbit, IRIS) scans this surface. Agent C's output must be thorough
  and academically defensible.
