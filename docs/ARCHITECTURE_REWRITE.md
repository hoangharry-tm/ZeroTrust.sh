# ZeroTrust.sh: Complexity-Class Architecture (Rewrite Proposal)

**Status**: Architecture proposal for research + implementation discussion  
**Date**: 2026-07-14  
**Authored by**: Claude (architecture consultant, systems researcher)

---

## Executive Summary

The current ZeroTrust.sh architecture has fundamental design issues that limit its ability to scale economically while maintaining security posture. This document proposes a rewrite based on **complexity-class driven design**—a principled approach that separates vulnerability detection into layers by computational decidability, enabling cost-graduated deployment (free → enterprise).

**Key claim**: Not all vulnerabilities require LLM reasoning. By filtering first with deterministic analysis, we can:
- **Free users**: Get 70% coverage with 0 LLM cost
- **Enterprise users**: Get 95% coverage with transparent, tiered LLM cost
- **All users**: Maintain high security posture (no false economies)

---

## Part 1: The Problem With Current Architecture

### Issue 1: Pseudo-Determinism in DCC

**Current approach**: DCC uses pattern matching to claim "deterministic" decidability.

```go
// Current (broken):
SafeNodes: []string{"paramQuery", "prepareStmt", ...}
// If pattern found → safe
// If pattern not found → vulnerable
```

**Problem**: Patterns aren't sound. What if:
- Custom library wraps `PreparedStatement`?
- Framework provides implicit parameterization?
- Code uses non-standard sanitization?

**Result**: False positives (saying vulnerable when safe), missed surfaces.

### Issue 2: Path A/B Silos

**Current design**: Path A (fast rules) and Path B (semantic) are sequential.

```
Path A → findings
Failures → Path B → findings
```

**Problem**: No principled separation. Why does Path A exist if Path B is more accurate? When should each handle what?

**Result**: Unclear mental model; feels like "best of both" but actually "worst of both."

### Issue 3: Implicit LLM Cost Model

**Current design**: Send all inconclusive cases to Tier 3 LLM.

**Problem**: No budget. Users don't know how many LLM calls will be needed. Can't offer "free" mode.

**Result**: Can't compete with open-source SAST for cost-conscious users.

### Issue 4: Framework Coupling

**Current approach**: Source-to-sink requires knowing framework (Spring, custom, ORM).

**Problem**: If codebase uses in-house library, taint analysis fails to identify sources/sinks.

**Result**: "Technology-agnostic" claim is aspirational, not true.

### Issue 5: No Mode Switching

**Current design**: One pipeline for all users.

**Problem**: Free users pay the cost of enterprise features (LLM layers). Enterprises get nothing they don't already get with Semgrep.

**Result**: Can't serve both markets simultaneously.

---

## Part 2: The Theoretical Foundation

### Complexity Classes in Vulnerability Detection

Not all security properties are computationally equivalent. From Rice's Theorem and program verification theory:

| Class | Property | Decidable? | Example | Method |
|-------|----------|-----------|---------|--------|
| **Syntactic** | "Does bytecode contain dangerous API call?" | ✓ Yes | `Runtime.exec()` call | Pattern matching on bytecode |
| **Structural** | "Is there a path from input to sink?" | ~ Semi | User data → SQL query | Taint analysis + heuristics |
| **Semantic** | "Is this path exploitable?" | ✗ No | Does auth guard all paths to resource? | Reasoning / LLM |

**Key insight**: Attempting to make semantic properties "deterministic" (via DCC patterns) is fighting theory. Accept the classification and structure around it.

### Proposed Separation

- **Layer 0 (Syntactic)**: Fully decidable; 0 LLM cost
- **Layer 1 (Structural)**: Semi-decidable; 0 LLM cost (heuristic pre-filter)
- **Layer 2 (Semantic)**: Undecidable; minimal LLM cost (spec-guided)
- **Layer 3 (Logic)**: Complex reasoning; high LLM cost (enterprise only)

---

## Part 3: Architecture Design

### Layer 0: Syntactic/Structural Analysis

**Goal**: Catch all findings that are **statically checkable** without reasoning.

**Decidability**: ✓ Yes (these are mathematical facts about the bytecode)

**Cost**: O(methods), no LLM, sub-second

**Methods**:

#### 0A. Bytecode Static Analysis
- Extract opcode sequences from compiled code
- Identify dangerous stack effects (string concat, execute calls)
- Framework-agnostic (bytecode is universal across Spring, custom libs)

**Example (CWE-89 SQL Injection)**:
```
Pattern: ALOAD_1 (user input)
         ALOAD_2 (SQL string)
         INVOKESTATIC String.concat
         INVOKEVIRTUAL Connection.query
→ Violated (string concat to query sink)

Pattern: ALOAD_1 (user input)
         INVOKEVIRTUAL PreparedStatement.setString
→ Safe (bound as parameter)
```

#### 0B. Type System Violations
- Unsafe casts
- Type mismatches
- Generic type erasure vulnerabilities

#### 0C. Hardcoded Secrets
- Entropy analysis on string constants
- Regex patterns (API keys, passwords)
- Known secret formats

#### 0D. Dangerous API Calls
- Known-bad methods: `Runtime.exec()`, `eval()`, etc.
- No need to trace; mere presence is risky
- Whitelist/blacklist approach

#### 0E. Dead Code Analysis
- Unreachable paths to sinks (confirmed dead)
- Unused variables initialized with secrets
- Dead branches

**Output**: Decided safe/violated + confidence 95%+

**Example workflow**:
```
For each method in bytecode:
  Check all opcodes against Layer 0 rules
  If rule matches with high certainty → Add to results (safe/violated)
  If rule matches with ambiguity → Forward to Layer 1
```

---

### Layer 1: Data-Flow Analysis

**Goal**: Track user-controlled data to sinks; identify risky surfaces for deeper analysis.

**Decidability**: ~ Semi-decidable (can approximate, but may have false paths)

**Cost**: O(methods × bounded_depth), no LLM, 1-2 seconds

**Methods**:

#### 1A. Taint Analysis
- Identify sources: user inputs, environment, external API returns
- Track explicit flows: assignments, method returns
- Track implicit flows: control dependencies, storage writes
- Identify sinks: SQL queries, file operations, exec calls

**Framework-agnostic approach**:
```
Source identification:
  - HTTPServletRequest.getParameter → tainted
  - System.getenv → tainted
  - Database read → tainted (unless known-safe DB)
  - Dependency method return → tainted (unless marked trusted)

Sink identification:
  - Connection.executeQuery(String) → SQL sink
  - File.write(String) → File sink
  - Runtime.exec(String) → Command sink
  - response.write(String) → Output sink

Sanitization:
  - PreparedStatement.setString → SQL parameter binding
  - File.getCanonicalPath + allowlist → Safe file path
  - HTML encode + context validation → Safe XSS output
```

#### 1B. Smart Pre-Filtering
- Path constraint solving: eliminate infeasible paths
- Reachability analysis: can control flow reach sink?
- Dead path elimination: is sink unreachable?

**Example**:
```java
if (isAdmin) {
  db.query(userInput + "DELETE");  // Only reachable if isAdmin=true
}
// Confidence: still high (admin bypass), but different threat model
```

#### 1C. Implicit Flows
- Storage writes: cache, session, database writes tagged as secondary sources
- Storage reads: trace DB read → output/execute chains (second-order SQLi, XSS)
- Control-dependent data: value determined by confidential condition

#### 1D. Supply Chain Marking (ZTD_Java)
- Mark return values from dependency methods as untrusted
- Propagate "from_dependency" flag through dataflow
- Separate finding type: "Risky dependency usage" vs "Logic error in our code"

#### 1E. Second-Order Detection
- DB write at Line X → DB read at Line Y → SQL query at Line Z
  - Flags as: "Stored XSS / Second-Order SQLi candidate"
- Cache write → cache read → output
  - Flags as: "Cache-based information leak"
- Session attribute write → multi-request read → action
  - Flags as: "IDOR candidate"

**Output**: Ranked suspicious surfaces + taint paths + confidence 60-85%

**Confidence scoring**:
```
High (>0.85):   Direct taint to sink, no sanitization visible
Medium (0.4-0.85): Taint path exists but sanitization unclear
Low (<0.4):     Many branches, unclear if taint reaches sink
```

---

### Layer 2: Semantic Verification (Spec-Guided LLM)

**Goal**: For ambiguous cases from Layer 1, verify using **formal specifications** (not free-form reasoning).

**Decidability**: Bounded (spec defines the question)

**Cost**: O(flagged_surfaces), ~50-100 tokens/surface, 5-10 minutes total

**LLM Model**: Qwen 2.5-Coder 1.5B (or DeepSeek-Coder 1.3B)

**Key difference from current Tier 3**: 
- Current: "Is this vulnerable?" (open-ended, expensive)
- Proposed: "Does the code satisfy the SQL parameterization contract?" (bounded, cheap)

#### Specification Library

Formalize CWE requirements as machine-readable specifications:

```yaml
vulnerabilities:
  CWE-89:
    name: SQL Injection
    layer: 2  # Semantic
    cwe_description: |
      Improper neutralization of special elements used in an SQL command
    contract:
      requires: "SQL query must be parameterized (not string concatenation)"
      forbiddens:
        - "string_concatenation_to_sql_sink"
        - "format_string_to_sql_sink"
        - "user_data + literal + query_method"
      safe_patterns:
        - "PreparedStatement.setString / setInt / setObject"
        - "ORM.bind() / param() / where() with parameter objects"
        - "String.format with hardcoded placeholders only"
      confidence_if_violated: 0.85
      confidence_if_safe: 0.82
  
  CWE-22:
    name: Path Traversal
    contract:
      requires: "File path must be canonicalized and allowlisted"
      forbiddens:
        - "user_data + file_read"
        - "path_join with user input"
      safe_patterns:
        - "new File(userInput).getCanonicalPath() + allowlist check"
        - "Path.of(root).resolve(userInput).toRealPath() + allowlist"
      confidence_if_violated: 0.88
      confidence_if_safe: 0.80
  
  CWE-79:
    name: Cross-Site Scripting
    contract:
      requires: "Output must be HTML-encoded OR in safe context"
      forbiddens:
        - "response.write(userInput)"
        - "innerHTML with unsanitized data"
      safe_patterns:
        - "HtmlEncoder.encode(userInput)"
        - "response.encodeRedirectURL()"
        - "JSP <c:out> tag"
      confidence_if_violated: 0.85
      confidence_if_safe: 0.80
  
  CWE-862:
    name: Missing Authorization
    contract:
      requires: "Authorization check must dominate all paths to protected resource"
      forbiddens:
        - "resource_access without auth_check"
        - "auth_check on wrong branch"
        - "auth_check after resource_access"
      safe_patterns:
        - "if (!hasPermission) throw Exception; resource.read();"
        - "@RolesAllowed annotation on method"
        - "AuthInterceptor.before() + ThreadLocal.set(principal)"
      confidence_if_violated: 0.80
      confidence_if_safe: 0.75
```

#### 2A. Contract Checking

Verify if code satisfies the contract:

```go
type ContractVerifier struct {
  spec       *Specification
  codeSlice  *CodeSlice
  llm        *LLMClient
}

func (v *ContractVerifier) Verify() (Verdict, string, float64) {
  // Step 1: Check forbiddens (if any present → immediately violated)
  for _, forbidden := range v.spec.Forbiddens {
    if v.codeSlice.Contains(forbidden) {
      return Violated, "Forbidden pattern found: " + forbidden, 0.88
    }
  }
  
  // Step 2: Check safe patterns (if any present → immediately safe)
  for _, safePattern := range v.spec.SafePatterns {
    if v.codeSlice.Contains(safePattern) {
      return Safe, "Safe pattern detected: " + safePattern, 0.82
    }
  }
  
  // Step 3: Ambiguous → Ask LLM (spec-guided)
  question := v.spec.BuildQuestion(v.codeSlice)
  llmAnswer := v.llm.Ask(question)  // Yes/No + evidence
  
  if llmAnswer.Confidence > 0.7 {
    if llmAnswer.Answer == "Yes" {
      return Safe, "LLM verified: " + llmAnswer.Evidence, llmAnswer.Confidence
    } else {
      return Violated, "LLM detected violation: " + llmAnswer.Evidence, llmAnswer.Confidence
    }
  }
  
  return Inconclusive, "Could not verify contract", 0.5
}
```

#### 2B. Control-Flow Dominance

For CWE-862 (Authorization), verify that auth check **dominates** (guards all paths to) resource access:

```go
func (v *CFGVerifier) AuthCheckDominates(authNode, resourceNode *CFGNode) bool {
  // Build CFG from method
  cfg := v.BuildCFG()
  
  // Question: are ALL paths from entry to resourceNode guarded by authNode?
  // i.e., does authNode post-dominate resourceNode on all paths?
  
  allPaths := cfg.AllPathsTo(resourceNode)
  for _, path := range allPaths {
    if !path.Contains(authNode) {
      return false  // Found path that skips auth
    }
    
    // Also check: does authNode come BEFORE resourceNode?
    if authNode.LineNo > resourceNode.LineNo {
      return false  // Auth after resource access (too late)
    }
  }
  
  return true  // All paths guarded
}
```

#### 2C. Activation Conditions

Verify preconditions are actually checked:

```
CWE-22 (Path Traversal) precondition:
  "File path must be canonicalized"
  
Code: new File(userInput).getCanonicalPath()
  LLM: "Is the result of getCanonicalPath() passed directly to file.read()?"
  Answer: "Yes" → violation
  Answer: "No, it's checked against allowlist" → safe
```

#### 2D. Spec-Guided LLM Prompting

Instead of:
```
"Here's a taint path. Is it vulnerable?"
```

Use:
```
"According to CWE-89, SQL injection requires that user input reaches 
a SQL query without parameterization. In this code:
  Line 10: User input from request.getParameter('id')
  Line 15: String query = 'SELECT * WHERE id=' + id;
  Line 18: connection.executeQuery(query);

Is the input parameterized? Yes / No. Evidence:"
```

**Why cheaper**: Bounded question + formal spec = lower hallucination + faster inference.

**Output**: Confirmed violations or safe signatures; confidence 75-90%

---

### Layer 3: Business Logic Analysis (Enterprise Only)

**Goal**: Detect complex vulnerabilities requiring multi-hop reasoning (BOLA, authorization races, payment flows).

**Decidability**: Complex reasoning (Turing-complete)

**Cost**: O(flagged_surfaces × reasoning_depth), 5-10 LLM calls per surface, 20-40 minutes

**LLM Model**: Claude Opus (or Qwen 7B for cost-conscious enterprises)

**Availability**: Enterprise mode only (`--enterprise` flag)

#### 3A. Multi-Agent Orchestration

```
Reconnaissance Agent:
  "Understand what this function does (in 2-3 sentences)"
  → LLM generates feature summary
  
Reasoning Agent:
  "Given [feature], [user_roles], [data_accessed], is there an IDOR?"
  → Multi-hop reasoning
  
Verification Agent:
  "Generate a PoC exploit path to verify this IDOR exists"
  → Validate reasoning
```

#### 3B. Domain-Specific Rules

- **BOLA/IDOR**: Resource ID not validated against user's permissions
- **Race Conditions**: State changes between check and action
- **Privilege Escalation**: Role/permission bypass chains
- **Payment Flow Violations**: Amount modification, duplicate charges
- **State Machine**: Skipping steps in workflow

#### 3C. Exploit Simulation

- Generate request sequences that exploit the vulnerability
- Execute in sandbox (Docker)
- Trace impact (data leak, state change)
- Validate exploitability

#### 3D. Custom Business Logic

- Rules specific to customer domain
- Encoded via prompts or structured specs
- Extensible per deployment

**Output**: Business logic vulnerabilities; confidence 50-80% (higher if PoC verified)

---

## Part 4: Cost Tiers

Users select a mode that determines which layers to run:

### Free Mode (`--scan-mode free`)

**Layers**: 0 + 1  
**Cost**: $0 / scan  
**LLM Calls**: 0  
**Coverage**: ~70% of vulnerabilities  
**Runtime**: ~5 minutes for 100k LOC  
**Confidence**: 60-95% (Layer 0 is high, Layer 1 is medium)

**Example findings**:
- Hardcoded secrets (Layer 0)
- Dangerous API calls (Layer 0)
- Direct taint to SQL sink, no sanitization (Layer 1)
- String concatenation in file paths (Layer 1)

**Use case**: OSS projects, privacy-conscious orgs, dev sanity checks

**Positioning**: "Competitive with open-source SAST (Semgrep, SonarQube community)"

---

### Default Mode (`--scan-mode default`)

**Layers**: 0 + 1 + 2  
**Cost**: $10-20 / scan  
**LLM Calls**: 50-100 (Qwen 1.5B)  
**Coverage**: ~85-90% of vulnerabilities  
**Runtime**: ~15 minutes for 100k LOC  
**Confidence**: 65-90% (Layer 2 boosts ambiguous cases)

**Example findings**:
- All Layer 0 findings
- All Layer 1 findings
- Ambiguous taint paths verified via spec (Layer 2)
- Authorization checks validated to guard resource (Layer 2)

**Use case**: Mid-size companies, startups, DevSecOps teams

**Positioning**: "Better coverage than Semgrep, lower cost than SonarQube"

---

### Enterprise Mode (`--scan-mode enterprise`)

**Layers**: 0 + 1 + 2 + 3  
**Cost**: $100-500 / scan  
**LLM Calls**: 200-500 (Qwen 1.5B + Claude Opus)  
**Coverage**: ~95% of vulnerabilities  
**Runtime**: ~30-45 minutes for 100k LOC  
**Confidence**: 70-90% (business logic adds context)

**Example findings**:
- All Layer 0, 1, 2 findings
- Business logic vulnerabilities (BOLA, race conditions, payment bypass)
- Exploit PoCs (optional)
- Supply chain risk assessment

**Use case**: Fortune 500, regulated industries, security-critical systems

**Positioning**: "Comprehensive security analysis with explainable findings"

---

## Part 5: Key Design Decisions

### Decision 1: Bytecode-First (Not Source-First)

**Rationale**:
- Framework-agnostic: `PreparedStatement` compiles to same bytecode regardless of wrapper library
- Fast: compiled code is smaller, simpler to analyze than source
- Deterministic: operations are explicit (no implicit framework behavior)

**Implementation**:
```
Input: .java source
  ↓
Compile to .class (javac)
  ↓
Layer 0-1: Analyze .class bytecode
  ↓
Layer 2-3: For ambiguous cases, load source for LLM context
```

**Benefit**: Scales to custom libraries without framework knowledge.

### Decision 2: Specification as First-Class Config

**Current**: Rules hardcoded in Go (`SafeNodes: []string{...}`)

**Proposed**: Specs in YAML (versioned, auditable, extensible)

```yaml
# docs/specifications/cwe-89.yaml
vulnerabilities:
  CWE-89:
    name: SQL Injection
    requires: "Parameterized query"
    forbiddens:
      - string_concatenation_to_sink
    safe_patterns:
      - PreparedStatement.setString
```

**Benefit**: Non-engineers can review/update specs. Changes don't require code recompile.

### Decision 3: Confidence Scores Are Explicit

**Current**: DCC says "decided" but confidence is implicit (0 or 1).

**Proposed**: Each layer outputs explicit confidence 0.0-1.0

```
Layer 0 (Syntactic): 95%+ confidence (statically checkable)
Layer 1 (Taint): 60-80% confidence (may have false paths)
Layer 2 (Semantic): 75-90% confidence (spec-guided LLM)
Layer 3 (Logic): 50-80% confidence (reasoning-heavy, domain-dependent)
```

**Benefit**: Users understand certainty. Can filter by confidence threshold.

### Decision 4: Supply Chain Built-In (Not Bolt-On)

**Current**: Supply chain marked as separate finding type.

**Proposed**: Layer 1 taint analysis tags data from dependencies.

```
Finding: "Stored XSS via dependency cache"
Tags: ["CWE-79", "supply_chain", "second_order"]
Source: "com.google.guava:guava.Cache.getIfPresent()"
```

**Benefit**: Contextualizes risk (dependency + logic error = worse).

### Decision 5: Modes Are User-Selected (Not Automatic)

**Current**: One pipeline for all users.

**Proposed**: User chooses mode before scan.

```bash
zerotrust scan --project myapp --mode free      # $0, 5 min
zerotrust scan --project myapp --mode default   # $15, 15 min
zerotrust scan --project myapp --mode enterprise # $250, 45 min
```

**Benefit**: Free users can compete with Semgrep. Enterprises pay for depth they use.

---

## Part 6: Implementation Roadmap

### Phase 1: Layer 0 + 1 (6-7 weeks)

**Deliverable**: Bytecode analyzer + taint engine

**Tasks**:
1. Build bytecode parser (Java bytecode format)
2. Implement dangerous API detection (Layer 0A)
3. Implement type system checks (Layer 0B)
4. Implement taint analysis engine (Layer 1A-1E)
5. Wire to existing Joern CPG (Layer 1 may use existing call graph)
6. Test on WebGoat (validate ~70% coverage)

**Output**: Free mode works, competitive with Semgrep

### Phase 2: Layer 2 (4-5 weeks)

**Deliverable**: Specification library + spec-guided LLM

**Tasks**:
1. Define CWE-89/78/22/79/94/918/862 specs (YAML)
2. Build contract verifier (Layer 2A)
3. Build CFG dominance checker (Layer 2B)
4. Implement spec-guided prompting (Layer 2D)
5. Fine-tune Qwen 1.5B prompts
6. A/B test vs free-form LLM (validate 40-45% cost reduction)

**Output**: Default mode works, better coverage than free

### Phase 3: Layer 3 + Modes (4-5 weeks)

**Deliverable**: Business logic agent + cost tier selection

**Tasks**:
1. Implement multi-agent orchestration (Layer 3A)
2. Add BOLA/IDOR/race condition rules (Layer 3B)
3. Wire exploit simulator (Layer 3C)
4. Add `--scan-mode` flag to CLI
5. Test enterprise mode on complex apps
6. Validate 95% coverage claim

**Output**: Enterprise mode works

### Phase 4: Validation + Research (3-4 weeks)

**Deliverable**: Research paper + benchmark results

**Tasks**:
1. Benchmark against SARD/BigVul corpus
2. Measure F1 / precision / recall per layer
3. Validate cost model (actual LLM calls vs estimate)
4. Write arXiv paper: "Complexity-Class Driven SAST"
5. Publish on ResearchGate / ACM portal
6. Submit to USENIX Security or CCS 2026

**Output**: Publishable research

**Total**: ~4-5 months (realistic, with parallel work)

---

## Part 7: Risk Analysis

### Technical Risks

**Risk**: Bytecode semantic features for Java (unproven)
- COBRA proved it works for smart contracts, unproven for general Java
- **Mitigation**: Phase 1 prototypes on 3-5 test cases; pivot if unfeasible

**Risk**: Layer 1 false paths (taint analysis is approximation)
- **Mitigation**: Validate false positive rate on labeled data; adjust confidence threshold

**Risk**: Layer 2 LLM spec-guided prompts don't achieve 40-45% cost reduction
- **Mitigation**: Early Phase 2 validation; fallback to full LLM if needed

### Market Risks

**Risk**: Free mode not competitive with Semgrep
- **Mitigation**: Focus on second-order + supply chain (differentiators)

**Risk**: Enterprise customers want PoE layer (not yet built)
- **Mitigation**: Phase 3 includes PoE; position as "roadmap feature"

---

## Part 8: Success Criteria

### Technical Success

- [ ] Layer 0 catches 100% of hardcoded secrets, dangerous APIs, dead code
- [ ] Layer 1 achieves 70% F1-score on BigVul corpus (without LLM)
- [ ] Layer 2 achieves 85% F1-score on CWE-89/22/79 (with spec-guided LLM)
- [ ] Free mode runtime < 10 min for 100k LOC
- [ ] Default mode runtime < 20 min
- [ ] Enterprise mode runtime < 60 min

### Economic Success

- [ ] Free mode costs $0 (no LLM budget)
- [ ] Default mode LLM cost < $20/scan
- [ ] Enterprise mode LLM cost < $500/scan
- [ ] Actual LLM calls align with estimates (±20%)

### Research Success

- [ ] Paper accepted to USENIX Security / CCS / NDSS
- [ ] Open-source release with reproducibility kit
- [ ] 50+ GitHub stars within 3 months

---

## Part 9: FAQ

**Q: Why rewrite vs. incremental fix?**  
A: Current architecture has fundamental issues (pseudo-deterministic DCC, silo'd paths, implicit cost). Incremental fixes can't solve these without major refactoring anyway. Rewrite aligns architecture with theory.

**Q: What happens to current WebGoat validation work?**  
A: Keep it running in parallel. Use current results to validate new architecture (should see improvement per layer).

**Q: Will this take longer than current development?**  
A: Similar timeline (4-5 months). But you get a defensible product + research publication at end.

**Q: Can we start with just Layer 0?**  
A: Yes. Phase 1 delivers working free mode. Can release early, iterate on Layers 2-3.

**Q: How do you handle framework-specific vulnerabilities?**  
A: Layer 0-1 are framework-agnostic. Layer 2-3 can include framework-specific rules (Spring Security checks, etc.) as optional configs. Base architecture doesn't require them.

**Q: What about Python / C++ / Go codebases?**  
A: Architecture is language-agnostic (works for any compiled IR). Phase 2-4 focuses on Java bytecode; later phases adapt to LLVM IR (C++), Python AST, Go IR.

---

## Conclusion

This rewrite is justified because:

1. **Theoretical soundness**: Aligns with complexity theory (not all vulns equally decidable)
2. **Economic scalability**: Supports free → enterprise gradient without false economy
3. **Research credibility**: Publishable contribution (novel architecture)
4. **Product quality**: Removes pseudo-determinism, adds auditability

**Recommendation**: Authorize Phase 1 (Layers 0+1) as parallel effort to current work. If Phase 1 achieves 70%+ coverage without LLM, proceed to Phase 2. If not, pivot back to incremental fixes.

**Next step**: Present this to team + stakeholders. Discuss appetite for rewrite vs. incremental fixes.

---

**Document version**: 1.0  
**Last updated**: 2026-07-14  
**Contact**: Architecture research team
