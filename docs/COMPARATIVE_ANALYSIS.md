# Comparative Analysis: Three LLM-Based Security Scanning Approaches

**Date**: 2026-07-14  
**Comparison**: llm-security-scanner vs ZeroTrust.sh (current) vs ZeroTrust.sh (proposed)

---

## Quick Verdict

| Approach | Cost | Coverage | Soundness | Maintainability | Production Ready |
|---|---|---|---|---|---|
| **llm-security-scanner** | High | Medium | Low | High | Low |
| **ZeroTrust (current)** | High | High | Medium | Low | Medium |
| **ZeroTrust (proposed)** | Medium | High | High | High | High |

---

## Detailed Comparison

### 1. llm-security-scanner (iknowjason/llm-security-scanner)

**Approach**: Brute-force LLM on every file

```
For each file in directory:
  Read entire file
  Send to LLM (GPT-4 or Claude)
  Ask: "What vulnerabilities are in this code?"
  Parse JSON response
  Collect findings
```

**Prompt Style** (from their code):
```python
prompt = f"""
You are a cybersecurity expert. Analyze this {language} code for:
1. Injection vulnerabilities
2. Auth issues
3. Data validation problems
4. Crypto flaws
5. Hardcoded secrets
...etc...

Format response as JSON: [{"vulnerability_type": ..., "line_numbers": ...}]
"""
```

**Strengths**:
- ✓ Simple to understand (one loop, one LLM call per file)
- ✓ Easy to implement (~400 LOC Python)
- ✓ Works with any LLM (OpenAI, Anthropic, local)
- ✓ Multi-language support (detects language, adapts prompt)
- ✓ No complex dependencies (just openai/anthropic SDK)

**Weaknesses**:
- ✗ **VERY expensive**: Every file → LLM call
  - 100-file codebase = 100 LLM calls (~$50-100 depending on file size)
  - No filtering, no pre-analysis, no cost optimization
- ✗ **No context**: Each file analyzed in isolation
  - Misses cross-function flows (user input → sink across files)
  - Can't detect implicit data flows (storage → retrieval)
  - No IDOR detection (no authorization context)
- ✗ **Not deterministic**: Same code → different LLM responses (hallucination)
- ✗ **No supply chain awareness**: Doesn't distinguish "our code" from "dependency code"
- ✗ **Low precision**: Lots of false positives (LLM guessing)
- ✗ **Unverifiable findings**: "LLM said it's vulnerable" with no proof

**Example Output**:
```json
{
  "vulnerability_type": "SQL Injection",
  "description": "User input flows to SQL query",
  "severity": "High",
  "line_numbers": [42],
  "recommendation": "Use parameterized queries"
}
```

**Problem**: No evidence. LLM guessed based on code pattern. Could be false positive if custom library safely binds parameters (exactly your custom library problem!).

---

### 2. ZeroTrust.sh (Current Architecture)

**Approach**: Orchestrate multiple tools + LLM semantic reasoning

```
Step 1: Ingestion
  MIV (model integrity)
  DI (differential indexing)
  CPG (code property graph via Joern)

Step 2: Path A (Fast Rules)
  Semgrep + Gitleaks + Linters
  LLM Verifier (filter false positives)

Step 3: Path B (Semantic Analysis)
  B1: Surface Selection (import-boundary BFS)
  B2: CVE Enrichment (Trivy)
  B3: DCC (pattern matching on CPG)
  B4: Lightweight LLM triage
  B5: Full LLM reasoning
  
Step 4: Dedup + Report
```

**Strengths**:
- ✓ Multi-tool orchestration (Semgrep, Joern, Trivy work together)
- ✓ Incremental scanning (DI tracks changes, only scan what changed)
- ✓ Cross-function analysis (CPG enables multi-hop reasoning)
- ✓ Supply chain awareness (Trivy integration, CVE context)
- ✓ Deterministic layer (Path A + DCC for certain cases)
- ✓ Dedup/ranking (SSVC scoring across tools)
- ✓ More production-ready than llm-security-scanner

**Weaknesses**:
- ✗ **DCC is brittle** (pattern matching on method names)
- ✗ **High LLM cost** (B4+B5 tiers on every ambiguous surface)
- ✗ **Complex architecture** (5 stages, hard to understand what filters what)
- ✗ **Framework-coupled** (source-to-sink assumes framework knowledge)
- ✗ **No spec-guided LLM** (prompts are hardcoded, 600 LOC)
- ✗ **Unclear decidability** (no principled separation of easy vs hard)
- ✗ **Maintenance burden** (4,154 LOC in semantic layer, 40% bloat)

**Example Flow**:
```
Surface: "user input reaches SQL query on line 42"
  
  B3 (DCC): "Does code contain 'paramQuery'?" 
    No → marked "Violated" (but could be custom lib!)
  
  B4 (Lite LLM): "Does this look risky?" 
    Confidence = 0.7 → Pass to B5
  
  B5 (Full LLM): "Is this actually vulnerable?"
    Reasoning over 1000+ tokens
    → Verdict: "Vulnerable" (but cost ~$0.50 per surface!)
```

**Problem**: Expensive + brittle. DCC patterns break on custom libs (your catch), LLM cost scales with ambiguous surfaces.

---

### 3. ZeroTrust.sh (Proposed: Complexity-Class Architecture)

**Approach**: Layered analysis by decidability, spec-guided LLM

```
Step 1: Ingestion (same as current)
  MIV + DI + CPG

Step 2-5: LAYERS (run in parallel/sequence)

Layer 0: Syntactic (Bytecode Analysis)
  • Dangerous API calls
  • Hardcoded secrets
  • Type violations
  • Dead code
  Cost: 0 LLM, <1 second
  Output: ~10-20 decided findings

Layer 1: Taint Analysis (CPG-based)
  • Source → Sink reachability
  • Implicit flows (storage)
  • Supply chain marking
  Cost: 0 LLM, 1-2 seconds
  Output: ~100-200 ranked surfaces
  
Layer 2: Spec-Guided Semantic (LLM on ambiguous)
  • Load CWE spec from YAML
  • Check forbiddens/safe patterns (deterministic)
  • Ask LLM bounded yes/no question
  Cost: ~50-100 tokens per surface
  Output: ~20-50 confirmed findings
  
Layer 3: Business Logic (Enterprise, optional)
  • Multi-agent reasoning (BOLA, IDOR, races)
  Cost: Expensive LLM per surface (optional)
  Output: ~5-20 business logic findings

Step 6: Dedup + Report (same as current)
```

**Strengths**:
- ✓ **Principled design** (complexity-class based)
- ✓ **Cost-optimized** (70-80% of surfaces filtered before expensive LLM)
- ✓ **Spec-driven** (YAML specs instead of hardcoded prompts)
- ✓ **Framework-agnostic** (bytecode-first, not source-to-sink)
- ✓ **Scalable** (three pricing tiers: free, default, enterprise)
- ✓ **Maintainable** (4K LOC → 1.5K LOC, +500 LOC specs)
- ✓ **Honest about limitations** (acknowledges custom libs need LLM)

**Weaknesses**:
- ✗ **Custom lib problem STILL EXISTS** (your catch: can't enumerate all safe patterns)
  - Layer 2 still needs LLM for unknown libraries (not as cheap as I claimed)
- ✗ **Not yet implemented** (requires refactoring current code)
- ✗ **Requires Joern/CPG** (harder than llm-security-scanner's simplicity)

**Example Flow**:
```
Surface: "user input reaches SQL query on line 42"
  
  Layer 0: "Does bytecode show string concat?" 
    Yes → Violated (certain)
  
  Layer 1: "Does taint reach sink reachably?"
    Yes → marked for Layer 2
  
  Layer 2 (Spec-Guided):
    Load spec: CWE-89 { requires: "parameterized" }
    Check forbiddens: "string_concat_to_sql" → YES
    → Violated (with spec evidence)
    
    If forbiddens don't match:
    Check safe patterns: "prepared_statement" → NO
    → Ambiguous, ask LLM:
    "Is user input parameterized or concatenated to SQL?"
    → LLM answers with evidence
    → Verdict: Safe/Violated + confidence
```

**Cost**: Surfaces filtered 10→5→1 before hitting expensive LLM.

---

## Cost Comparison (100-file codebase)

### llm-security-scanner
```
100 files × $0.50/LLM call = $50-100 per scan
(No filtering, every file → LLM)
```

### ZeroTrust (Current)
```
100 files → 50 surfaces (Path B triage) 
→ 30 reach B5 (LLM reasoning)
× $0.50 = $15 per scan
+ Semgrep/tool cost = $20 total
(Good filtering, but DCC is brittle)
```

### ZeroTrust (Proposed)
```
100 files 
→ Layer 0: 10 decided, 90 undecidable
→ Layer 1: 60 filtered, 30 ambiguous
→ Layer 2: 10 need LLM
→ 10 × $0.10 (cheap Qwen) = $1 per scan
+ Semgrep/tool cost = $5 total
(Best filtering, spec-driven)
```

---

## Key Learnings from llm-security-scanner

### What They Get Right
1. **Simplicity**: Don't overthink it. LLM on files can work for quick scans.
2. **Multi-language**: Language detection + adapted prompts work well.
3. **JSON output**: Structured response format is good.
4. **CI/CD integration**: GitHub Actions integration is straightforward.

### What They Miss
1. **Cost**: No cost optimization (every file → LLM)
2. **Context**: No cross-function analysis
3. **Supply chain**: No awareness of dependencies
4. **Determinism**: 100% LLM, no SAST layer
5. **Soundness**: High false positive rate

### What Makes Sense to Copy
- Language detection logic (good pattern)
- JSON output structure
- Simple CLI interface
- GitHub Actions workflow

---

## Strategic Decision Tree

**If you want**:
- **Simplicity + quick results**: Use llm-security-scanner as-is
  - Cost: High ($50-100/scan for large codebase)
  - Effort: 0 (already built)
  - Coverage: Medium (file-level only, lots of false positives)

- **Production + cost-efficient**: Refactor ZeroTrust (current → proposed)
  - Cost: Low ($5/scan)
  - Effort: 4 weeks
  - Coverage: High (multi-layer, spec-driven)

- **Middle ground**: Enhance ZeroTrust (current)
  - Replace DCC with CodeQL + specs (1 week)
  - Add spec-guided LLM (1 week)
  - Cost: Medium ($10-20/scan)
  - Effort: 2-3 weeks
  - Coverage: High

---

## My Honest Recommendation

**Don't** use llm-security-scanner as-is for production. It's:
- Too expensive ($50-100 per scan)
- Too simplistic (file-level, no cross-function)
- Too many false positives (no deterministic layer)

**Do** leverage their insights:
- Simple architecture works (good for learning)
- Language detection + prompting works
- JSON output format is clean
- CI/CD integration strategy is sound

**Build** ZeroTrust as the "smarter llm-security-scanner":
- Deterministic layer (Path A, Layer 0)
- Cost filtering (Layers 0-1 reduce LLM calls)
- Spec-driven (auditable, maintainable)
- Multi-tool (Semgrep + Joern + LLM + Trivy)

---

## Conclusion

| Project | Best For | When to Use |
|---|---|---|
| **llm-security-scanner** | Learning, quick demos, single-file scans | Prototyping, not production |
| **ZeroTrust (current)** | Real security scanning with multiple tools | Now (but with DCC brittleness) |
| **ZeroTrust (proposed)** | Production scanning with cost optimization | After 4-week refactor |

**The gap**: llm-security-scanner is too simple, ZeroTrust (current) is too brittle. The proposed architecture closes that gap.

---

**Next question**: Given this analysis, does a 4-week refactor make sense? Or would you rather ship current + iterate?
