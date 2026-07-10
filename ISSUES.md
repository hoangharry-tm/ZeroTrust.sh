# ZeroTrust.sh — Implementation Assessment

> Assessment date: 2026-07-10  
> Scope: Path B semantic analysis pipeline (T1 → T2 → T3)  
> Basis: Full source review of targeting, enrichment, contracts, triage, analysis, joern packages

---

## Strengths

### S1: IBA is architecturally sound and genuinely multi-language

`import_boundary.go` covers Java, Python, and Go with `sourcePkgPrefixes`, `sinkPkgPrefixes`, `authPkgPrefixes`, and `storagePkgPrefixes` — all keyed by file extension, all matching on canonical package import strings, not method names. The 250-line early-stop scan is efficient. The bitmask `BoundaryKind` is clean and composable. Skipping test directories prevents false signal pollution. This is exactly what the blueprint specified and it delivers.

### S2: Bidirectional BFS is correct and efficient

The `bfsForward` + `buildReverseCG` + intersection pattern is the right algorithm: O(V+E), allocation-efficient (pre-sized maps), stable-sorted for determinism. `bfsDepths` giving call graph distance for prioritisation (IDOR > AuthBoundary > ExternalInput, then depth ascending) is a legitimate prioritisation signal.

### S3: Phantom taint filter shows real systems thinking

`isPhantomTaintPath` with three independent conditions (internal source name + intermediate corroboration, intermediate chain domination, very-long-path fast-path) is thoughtful and measured. It dropped 340 phantom flows in scan 5 (58.8% reduction). The `internalSourceNames` and `internalIntermediateNames` maps are heuristic but grounded in real JDBC/IO naming conventions.

### S4: SQLite CPG ingestion eliminates redundant Joern round-trips

`IngestCPGToSQLite` draining the CPG into SQLite with paginated stable-sorted queries decouples the graph query layer from the Joern JVM, allows fast repeated queries without hitting the HTTP API, and survives Joern crashes after ingestion. The `sqliteDB` / `sqliteProjectID` split is clean.

### S5: Project-wide taint query is the correct Joern approach

`queryProjectWideTaintFlows` runs a single global Joern query rather than per-method queries. Per-method queries break Joern's inter-procedural DFG context and return 0 results — this was discovered and fixed. The constructor sink handling (`ctorSinkSet` + `ctorCallSinks.flatMap(_.argument.l)`) is a non-obvious Joern requirement that was correctly addressed.

### S6: B5 prompt is well-structured with real evidence layers

The SCL + CFP + AIP structure in `prompt.go` is sound. The AIP profiles per CWE are accurate. `filterSinksByCWE` preventing cross-CWE sink contamination in prompts is a subtle but important correctness detail. Self-consistency check for frontier mode is a legitimate confidence calibration technique. Per-surface deadlines (45s/120s/300s by mode) prevent a single hung LLM call from blocking the batch.

### S7: Call path sink filter prevents sink label bleeding

The `filterSinksByCallPath` logic in `enrichment.go` — retaining only sink labels that appear in the call path, with fallback to original list if filtering empties it — is a pragmatic and effective guard against phantom sink attribution.

### S8: `readFunctionBody` anomaly handling is deep and well-tested

After multiple rounds of fixes, the function handles 5+ distinct Joern line inflation classes (braceless lambda, class-level `<init>`, multi-line sig, bytecode EOF inflation, annotation array brace, backward scan class boundary, import-block Joern mispoint) with 22 tests covering real-world cases from WebGoat. The name-based fallback for both EOF-overflow and within-EOF forward-scan failures is architecturally correct.

---

## Weaknesses

### W1 — CRITICAL: DCC is text pattern matching disguised as structural analysis

**File**: `internal/semantic/contracts/check.go` ~line 156  
**Requirement violated**: No pattern matching in Path B; technology-agnostic

The code-level anchor fallback block:

```go
if !anchorMatched && surface.Code != "" && cwe != "CWE-89" {
    stripped := stripCode(surface.Code)
    for _, anchor := range inv.SinkAnchors {
        if strings.Contains(stripped, anchor) { ... }
    }
}
```

This is Path A logic inside Path B. It fires on variable names, comments, string literals, and is framework-sensitive. A custom `runQuery()` wrapping `executeQuery` won't match. The entire code-level fallback block needs to be replaced with Joern PDG edge queries: "does an untransformed taint edge exist from a `MethodParameterIn` node to a node whose `methodFullName` is in the IBA-classified sink set for this CWE?"

**Fix**: Remove the code-level anchor block. Ensure Joern sink query returns qualified sink nodes so `SinkNodes` is reliably populated. If `SinkNodes` is empty after a qualified Joern query, the correct verdict is `VerdictInconclusive` — not a forced violation via text search.

---

### W2 — CRITICAL: CFP is a prompt label, not an implementation

**File**: `internal/semantic/analysis/prompt.go`, `buildCFP()`  
**Requirement violated**: Blueprint T3-B (Control Flow Predicate Checker)

`buildCFP()` builds a section called "Control Flow Evidence" containing only: surface kind, file name, sink nodes (already from enrichment), and the taint path (already from Joern). There is **no CFG path enumeration, no dominator tree query, no predicate node detection**. The CFP section tells the LLM "taint path: A → B → C" — it does not tell it whether a conditional guard exists on all paths from A to C.

This is the blueprint's most important component for CWE-862 and for detecting auth-on-wrong-branch, skippable state machine steps, and post-hoc authorization. It does not exist yet.

**Fix**: Add a new Joern query `GetCFGDominators(methodID, sinkNodeID)` returning whether a dominating conditional node exists on all CFG paths from method entry to sink. Feed this result into `buildCFP()` as structured evidence. This makes CWE-862 detection framework-agnostic by definition — any conditional that dominates the path to the sink is a guard, regardless of its name.

---

### W3 — CRITICAL: `isAuthMethod` contains 15 name-pattern strings plus Spring-specific annotations

**File**: `internal/semantic/targeting/targeting.go` ~line 369  
**Requirement violated**: Technology-agnostic; no pattern matching on method names

```go
patterns := []string{"auth", "login", "logout", "token", "verify", "validate",
    "permission", "authorize", "authenticate", "access",
    "security", "credential", "principal", "session", "jwt", "oauth"}
```

Plus hardcoded: `@PreAuthorize`, `@Secured`, `@RolesAllowed`, `@WithMockUser`.

A company with `AccessGate.enforce()` or `RequestValidator.check()` gets zero auth seed coverage. Worse: when `isAuthMethod` returns nothing, `anyAuthMethod=false` and the fallback sets `authSeeds = fallbackAuthSeeds` (all `BoundaryAuth` files — too broad), which produced the 28-surface `SurfaceAuthBoundary` noise observed in scan 6.

**Fix**: Remove `isAuthMethod` entirely. Auth seeds should come **only from IBA classification**: a method is an auth seed if its containing file was IBA-classified as `BoundaryAuth` based on imports. No name matching. Auth seed granularity should be file-level (all methods in a `BoundaryAuth` file are auth seeds), not method-level filtered by name patterns.

---

### W4 — HIGH: `identifyIDOR` uses 20 name-pattern strings

**File**: `internal/semantic/targeting/idor.go`  
**Requirement violated**: No pattern matching; technology-agnostic

```go
var idorSignals = []string{
    "getById", "findById", "loadById", "fetchById",
    "getBy", "findBy", "fetchBy",
    "byId", "byUsername", "byEmail", "byUser",
    "resource", "profile", "account",
    "order", "invoice", "document", "record", "item", "asset",
}
```

A codebase using `fetchRecord()`, `loadAsset()`, or `getDocument()` misses all IDOR signals. The structural definition of IDOR — a surface that reaches a resource read without an ownership predicate on the path — is a pure graph property, yet the implementation gatekeeps it behind name heuristics.

**Fix**: Remove `hasIDORSignal`. Promote any surface that cannot reach an auth boundary (already computed as `!canReachAuth[id]`) AND reaches a storage-read sink (IBA-classified `BoundaryStorage` file in its backward-reachable set) to `SurfaceIDORCandidate`. No name matching required.

---

### W5 — HIGH: `canReachAuth` BFS is unlimited depth with no confirmation requirement

**File**: `internal/semantic/targeting/targeting.go` ~line 257  
**Requirement violated**: Targeting precision; `SurfaceAuthBoundary` noise

An `<init>` constructor in a file 6 call-graph hops away from any auth method is labeled `SurfaceAuthBoundary`. This produced 28 noisy CWE-862 INCONCLUSIVE handoffs to B4 in scan 6, all stub-dropped by triage (93% drop rate). The label carries no semantic meaning at that depth.

**Fix**: Cap `canReachAuth` BFS at depth 2. A surface is a genuine auth boundary only if an auth-boundary file is a direct callee (depth ≤ 1) or the surface's own file is IBA-classified `BoundaryAuth`. Implement as `bfsForwardDepthLimited(reverseCG, authSeeds, 2)`.

---

### W6 — HIGH: Joern sink query uses bare unqualified method names

**File**: `internal/scanner/joern/queries.go`, `queryProjectWideTaintFlows`  
**Requirement violated**: Technology-agnostic; no pattern matching

Sink set: `Set("executeQuery","executeUpdate","execute","readValue","exec",...)`. These are unqualified:

- `execute` matches `ProcessBuilder.execute`, `JdbcTemplate.execute`, and any custom `execute()` in the codebase
- `readValue` matches Jackson AND any other method named `readValue`
- `readObject` matched 280-node internal JDBC chains (fixed in scan 6 but the underlying mechanism is unchanged)

The constructor sink handling (`ctorSinkSet.exists(t => c.methodFullName.contains(t))`) is better but still uses `String.contains`.

**Fix**: IBA already classifies files as `BoundarySink`. Feed the set of IBA-classified sink file paths into the Joern query and filter: a call is a sink only if it resides in an IBA-classified sink file. This eliminates false sink attribution entirely without any method name matching:

```scala
val sinkFiles = Set("path/to/FileA.java", ...) // from IBA output
val callSinks = cpg.call.filter(c => sinkFiles.contains(c.file.name))
```

---

### W7 — MEDIUM: Second-order detector loses surface metadata

**File**: `internal/semantic/targeting/second_order.go`  
**Impact**: All second-order surfaces produce zero-char `enrich_body`

The output `Surface` struct sets only `ID` and `IsSecondOrder: true` — `File` and `FunctionName` are empty strings. Enrichment cannot call `readFunctionBody` without a file path, so every second-order surface produces no code in the LLM prompt.

**Fix**: Look up the full `cpg.Node` by ID from the `methods` slice passed into `DetectSecondOrder` and populate all `Surface` fields (`File`, `FunctionName`, `NodeType`, `CallGraphDepth`) from it, exactly as `targeting.go`'s Phase 5 does for primary surfaces.

---

### W8 — MEDIUM: CWE-862 rulebook `SinkAnchors` are semantically inverted

**File**: `internal/semantic/contracts/rulebook.go`  
**Requirement violated**: DCC correctness for CWE-862

```go
"CWE-862": {
    SinkAnchors: []string{"doFilter", "hasRole", "isAuthenticated", "checkPermission", ...},
```

These anchors signal **presence** of auth checks, but the DCC fires `VerdictViolation` when they appear — meaning "auth check is present, therefore violation." CWE-862 is _Missing_ Authorization; the violation condition is **absence** of a guard, not presence. The current anchor model cannot express absence — that requires the CFP dominator query (W2).

**Fix**: Once CFP is implemented (W2), remove the `SinkAnchors` list for CWE-862 entirely. The DCC verdict for CWE-862 becomes: `HasDominatingGuard(methodID, sinkNodeID) → VerdictSafe`, else `VerdictViolation`. Until CFP exists, CWE-862 should return `VerdictInconclusive` unconditionally rather than a wrong violation.

---

### W9 — MEDIUM: `applicableCWEs` maps CWE-22 to `SurfaceAuthBoundary`

**File**: `internal/semantic/contracts/check.go` ~line 70  
**Impact**: 158 false CWE-22 INCONCLUSIVE handoffs to B4 per scan

```go
case targeting.SurfaceAuthBoundary:
    return []string{"CWE-862", "CWE-89", "CWE-78", "CWE-22"}
```

Path traversal (CWE-22) requires external input → file sink — that is `SurfaceExternalInput`'s domain. Auth boundary surfaces have no structural relationship to file I/O sinks. When none of CWE-862/89/78 anchors match, DCC falls through to CWE-22, producing spurious INCONCLUSIVE results.

**Fix**:

```go
case targeting.SurfaceAuthBoundary:
    return []string{"CWE-862", "CWE-89", "CWE-78"}  // remove CWE-22
case targeting.SurfaceIDORCandidate:
    return []string{"CWE-862", "CWE-89", "CWE-78"}  // remove CWE-22
```

---

### W10 — LOW: `stripCode` doesn't handle block comments or Java text blocks

**File**: `internal/semantic/contracts/check.go`, `stripCode()`

`stripCode` strips `//` line comments and `"..."` string literals but not `/* ... */` block comments, Javadoc (`/** ... */`), or Java 13+ text blocks (`"""`). An anchor like `"readObject"` appearing in a Javadoc comment `/** calls readObject internally */` survives stripping and produces a false anchor match.

**Fix**: Add a state machine for `/* */` block comment detection. Text blocks (`"""`) are rarer but should also be handled.

---

### W11 — LOW: Joern CPG path orientation is positional, not typed

**File**: `internal/scanner/joern/graph.go`, `queryProjectWideTaintFlows`

The path orientation — `elems.head` = CALL (sink), `elems.last` = MethodParameterIn (source) — is inverted from intuition and enforced only by a comment. It has caused bugs (the Scala `MethodParameterIn` case producing empty `Sink.Name` in scan 5). Positional indexing on an `[]interface{}` slice is fragile.

**Fix**: Make orientation explicit at the type level. The `joernFlow` struct already has `Source` and `Sink` fields — enforce in the Scala query that `Source` is always the `MethodParameterIn` and `Sink` is always the `Call`, with a runtime assertion in the Go unmarshal layer.

---

## Fix Priority Matrix

| ID  | Severity | Effort         | Blocks                                  |
| --- | -------- | -------------- | --------------------------------------- |
| W1  | Critical | High           | DCC correctness, tech-agnostic          |
| W2  | Critical | High           | CWE-862, CFP, all auth detection        |
| W3  | Critical | Low            | Auth seed quality, canReachAuth noise   |
| W4  | High     | Low            | IDOR coverage                           |
| W5  | High     | Low            | SurfaceAuthBoundary noise, B4 stub rate |
| W6  | High     | Medium         | Sink attribution accuracy               |
| W7  | Medium   | Low            | Second-order surface enrichment         |
| W8  | Medium   | Low (after W2) | CWE-862 rulebook correctness            |
| W9  | Medium   | Trivial        | 158 false B4 handoffs per scan          |
| W10 | Low      | Low            | stripCode completeness                  |
| W11 | Low      | Low            | Path orientation safety                 |

**Recommended sequence**: W9 → W3 → W5 → W7 → W6 → W1 → W2+W8 → W4 → W10 → W11

Rationale: W9/W3/W5 are trivial changes with immediate measurable scan improvement. W7 unblocks second-order coverage. W6 removes unqualified sink names. W1 is the largest single change (requires IBA-qualified Joern sinks to be fully in place first). W2+W8 are the architectural milestone (CFP implementation). W4 is a targeting improvement that can follow once the core pipeline is clean.
