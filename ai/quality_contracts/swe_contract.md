# SWE Quality Contract

## Preamble

This contract governs every code change to ZeroTrust.sh. It exists because security scanners must be held to a higher standard than ordinary applications: a bug here is not a failed checkout flow but a missed vulnerability that ships to production. Every violation of this contract is a regression risk that must be justified in the PR description. The contract applies to all Go code in `cmd/` and `internal/`, all Python code in `worker/`, and any supporting scripts that ship in the binary or Docker image.

**Three absolute prohibitions** (no justification accepted):
1. No bare error discards (`_, _ = rand.Read(...)`) or blanket `//nolint:errcheck` — every error must be assigned or explicitly ignored with a documented reason.
2. No `context.Background()` inside request-handling goroutines — cancellation chains must never be severed.
3. No fire-and-forget goroutines — every `go` statement must have a shutdown path and a lifecycle owner.

**Enforcement**: All new code and refactored files must pass `golangci-lint run --config .golangci.yml` (Go) and `mypy --strict worker/` (Python) in CI. `//nolint` comments require a justification on the same line. Violations block merge.

---

## Go Standards

### Error Handling

**E1. Wrap every error with context.** Every `if err != nil` block in a function that is not the top-level handler must wrap with `fmt.Errorf("doing X: %w", err)`. The message describes *what the caller was trying to do*, not *what the callee returned*.

```go
// GOOD
user, err := s.store.GetUser(ctx, id)
if err != nil {
    return fmt.Errorf("get user %s: %w", id, err)
}

// BAD
user, err := s.store.GetUser(ctx, id)
if err != nil {
    return err  // caller has no context
}
```

**E2. Prefer `errors.AsType` (Go 1.26+) over `errors.As`.** The new generic function is type-safe, avoids reflection, allocates less, and is 5–10× faster. Never use `errors.As` in new code.

```go
// GOOD (Go 1.26+)
if pe, ok := errors.AsType[*fs.PathError](err); ok {
    fmt.Println(pe.Path)
}

// BAD — reflection-based, panics on wrong pointer type
var pe *fs.PathError
if errors.As(err, &pe) {
    fmt.Println(pe.Path)
}
```

**E3. Use `errors.Is` for sentinel checks, `errors.AsType` for typed extraction.** Sentinel errors use `errors.Is`; custom error types use `errors.AsType`. Never string-match errors.

```go
var ErrNotFound = errors.New("not found")

if errors.Is(err, ErrNotFound) {
    return nil  // sentinel check
}

if ve, ok := errors.AsType[*ValidationError](err); ok {
    fmt.Println(ve.Field)  // type extraction
}
```

**E4. Define sentinel errors with `errors.New`, not `fmt.Errorf`.** In Go 1.26, `fmt.Errorf("x")` now allocates as little as `errors.New("x")`, but `errors.New` remains semantically clearer: it signals a fixed, non-wrapping error.

```go
// GOOD
var ErrUserNotFound = errors.New("user not found")

// ACCEPTABLE (with formatting)
var ErrInvalidInput = fmt.Errorf("input must be at least %d characters", 8)
```

**E5. Log or return, never both.** A function either handles the error (logs, metrics, recovery) or propagates it to the caller. Doing both produces duplicate log lines and confuses root-cause analysis.

```go
// GOOD — propagate
func (s *Service) GetUser(ctx context.Context, id string) (*User, error) {
    user, err := s.store.GetUser(ctx, id)
    if err != nil {
        return nil, fmt.Errorf("get user %s: %w", id, err)
    }
    return user, nil
}

// GOOD — handle
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    user, err := h.svc.GetUser(r.Context(), id)
    if err != nil {
        slog.Error("request failed", "id", id, "error", err)
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
    // ...
}
```

**E6. Translate errors at package boundaries.** A storage error becomes a domain error; a domain error becomes an HTTP response. Never let raw `sql.ErrNoRows` or `io.EOF` escape the package that produced them.

```go
// GOOD
func (s *SQLStore) GetUser(ctx context.Context, id string) (*User, error) {
    var u User
    err := s.db.QueryRowContext(ctx, "SELECT ...", id).Scan(&u)
    if errors.Is(err, sql.ErrNoRows) {
        return nil, fmt.Errorf("%w: user %s", ErrUserNotFound, id)
    }
    if err != nil {
        return nil, fmt.Errorf("query user %s: %w", id, err)
    }
    return &u, nil
}
```

**E7. Use `errors.Join` for multi-error aggregation.** When collecting errors from loop iterations or independent validations, use `errors.Join` (Go 1.20+) rather than custom error slices.

```go
func validateOrder(o *Order) error {
    var errs []error
    if o.Total <= 0 {
        errs = append(errs, &ValidationError{Field: "total", Message: "must be positive"})
    }
    if o.UserID == "" {
        errs = append(errs, &ValidationError{Field: "user_id", Message: "required"})
    }
    return errors.Join(errs...)
}
```

**E8. Never panic.** Panic is reserved for truly unrecoverable states (nil dereference in a type switch that should be impossible). All expected error conditions return `error`. Use `errors.AsType` with a fatal log instead of panic at top-level main.

### Concurrency & Context

**C1. Context is the first parameter.** Every function that does I/O, blocks, or spawns a goroutine takes `ctx context.Context` as its first parameter. No exceptions.

```go
// GOOD
func (s *Service) Scan(ctx context.Context, path string) (*Result, error)

// BAD — no context
func (s *Service) Scan(path string) (*Result, error)
```

**C2. Never store context in a struct.** Context is a request-scoped value. Store it in a struct only in a single documented exception: a context derived from a constructor-provided parent for controlling background goroutines owned by the struct.

```go
// GOOD — pass through call chain
func (h *Handler) Handle(ctx context.Context, req Request) (*Response, error) {
    return h.svc.Process(ctx, req)
}

// BAD — stored in struct
type Handler struct {
    ctx context.Context  // NO
}
```

**C3. Always `defer cancel()` immediately after `WithTimeout` or `WithCancel`.** The `go vet` `lostcancel` check catches omissions. This is non-negotiable.

```go
ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
defer cancel()  // MUST be on next line
```

**C4. Use `errgroup.WithContext` for fan-out.** Any goroutine that participates in a request-scoped fan-out must use `golang.org/x/sync/errgroup`. The derived context is automatically cancelled on first error, stopping sibling goroutines.

```go
g, ctx := errgroup.WithContext(ctx)
g.SetLimit(10)  // always bound concurrency

for _, f := range files {
    f := f
    g.Go(func() error {
        result, err := s.analyze(ctx, f)
        if err != nil {
            return fmt.Errorf("analyze %s: %w", f, err)
        }
        results <- result
        return nil
    })
}

if err := g.Wait(); err != nil {
    return fmt.Errorf("analysis failed: %w", err)
}
```

**C5. Every goroutine must have a lifecycle owner.** When you write `go fn()`, you must:
- Have a mechanism to stop the goroutine (context cancellation or channel close)
- Await its completion (via `sync.WaitGroup`, `errgroup.Wait`, or channel drain)
- Document who owns the goroutine's lifecycle

```go
// GOOD
func (w *Worker) Start(ctx context.Context) error {
    w.wg.Add(1)
    go func() {
        defer w.wg.Done()
        for {
            select {
            case <-ctx.Done():
                return
            case job := <-w.jobs:
                w.process(job)
            }
        }
    }()
    return nil
}

func (w *Worker) Shutdown(ctx context.Context) error {
    done := make(chan struct{})
    go func() {
        w.wg.Wait()
        close(done)
    }()
    select {
    case <-done:
        return nil
    case <-ctx.Done():
        return ctx.Err()
    }
}
```

**C6. Bound concurrency.** Every fan-out goroutine pattern must use `g.SetLimit(N)` or a channel-based semaphore. Unbounded goroutine spawning is a self-inflicted DoS.

**C7. Check `ctx.Done()` in long-running loops.** Any loop that iterates over files, records, or packets must check for context cancellation at regular intervals.

```go
for _, file := range files {
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
    }
    // process file
}
```

**C8. Use signal.NotifyContext for graceful shutdown.** The `main()` function must install `SIGTERM`/`SIGINT` handlers using `signal.NotifyContext` and propagate that context through the entire service tree.

```go
func main() {
    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    if err := run(ctx); err != nil {
        log.Fatal(err)
    }
}
```

### Package & File Organization

**P1. `cmd/` contains one `main.go` per binary, ≤50 lines each.** The `main.go` is a thin wrapper: parse flags, instantiate dependencies, run. All logic lives in `internal/`.

```
cmd/zerotrust/main.go         ← ≤50 lines, calls internal/app.Run(ctx)
cmd/zerotrust-agent/main.go   ← ditto
```

**P2. `internal/` is the default home for all logic.** Go's compiler-enforced import restriction is the best access modifier. Everything lives in `internal/` unless there is a concrete reason to export it. Never create `pkg/` for code that might be useful "someday" — promote when the need is real.

**P3. Packages are organized by dependency, not by layer.** Prefer `internal/scanner/`, `internal/report/`, `internal/db/` (horizontal by domain) over `internal/services/`, `internal/models/`, `internal/repositories/` (vertical by layer). A package should be importable by at most 3–5 other packages within the module.

**P4. No cyclic imports.** The Go compiler enforces this, but the contract is stricter: a package at `internal/a/` must not import `internal/b/` that imports `internal/a/`. Use interface inversion to break cycles.

**P5. One file is one responsibility.** `scanner.go` contains the `Scanner` type and its constructor. Options, test helpers, and types used only by tests live in `scanner_test.go` or a `scanner_opts.go` sibling. Files exceeding 600 lines must be broken up.

**P6. Keep `go.mod` dependencies minimal.** Every new dependency must be justified in the PR description. Prefer stdlib. No dependency on `pkg/errors`, `glog`, `logrus`, or other deprecated/duplicative libraries. Use `slog` for structured logging.

### Naming Conventions

**N1. Acronyms are all-upper or all-lower.** `HTTP`, `URL`, `ID`, `API`, `JSON`, `DB`, `SQL`, `CLI`, `CLAUDE.md`, `CPG`.

```go
type HTTPServer struct { ... }   // not HttpServer
func ParseURL(s string) (*URL, error)
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

**N2. Single-letter receiver names.** `s *Service`, `h *Handler`, `r *Repo`, `m *Matcher`. Only use longer names when two receivers of different types share a package.

**N3. Constructor is `New<Type>`.** `NewScanner(cfg Config) *Scanner`. Returns the concrete type, not an interface.

**N4. Interface names end in `-er` for one method, describe the role for multiple.** `Scanner`, `Parser`, `Renderer`. `Storage` (role), `Finder` (action). Never suffix interfaces with `I` (Java style) or include `Interface` in the name.

**N5. Test files name the function being tested.** `TestScanner_Scan`, `TestParse_URL_Invalid`. Table-driven tests with `t.Run(name, func(t *testing.T) { ... })`.

### Interface & Generics

**I1. Accept interfaces, return structs.** Functions accept the narrowest interface the caller can provide. Functions return concrete types so the caller has access to all methods.

```go
// GOOD — consumer defines interface
type userFinder interface {
    FindByID(ctx context.Context, id string) (*User, error)
}

func NewHandler(finder userFinder) *Handler {
    return &Handler{finder: finder}
}

// BAD — struct parameter
func NewHandler(db *sql.DB) *Handler  // locks caller to sql.DB
```

**I2. Define interfaces at the consumer, not the producer.** The package that *uses* the interface defines it. The package that *implements* it returns concrete types. The producer should not know about the interface.

```go
// internal/handler/handler.go
type userStore interface {
    GetByID(ctx context.Context, id string) (*User, error)
}

// internal/store/sqlite.go — does not import handler
func (s *SQLiteStore) GetByID(ctx context.Context, id string) (*User, error) { ... }
```

**I3. Exception: producer-side interfaces for polymorphic families.** `io.Reader`, `io.Writer`, `http.Handler` live with the producer because they represent a family of implementations. Use sparingly.

**I4. Prefer one-method interfaces.** If a consumer needs two capabilities, compose:

```go
type userFinder interface { Find(...) (*User, error) }
type userWriter interface { Write(...) error }

type userStore interface {
    userFinder
    userWriter
}
```

**I5. Use generics only when the constraint is narrow and eliminates a type assertion.** `comparable` and `cmp.Ordered` are the sweet spot. Avoid generics that require multi-paragraph constraint interfaces.

```go
// GOOD — eliminates type assertion, constraint is in stdlib
func Keys[K comparable, V any](m map[K]V) []K { ... }

// GOOD — small typed wrapper for a return value
type Result[T any] struct {
    Value T
    Err   error
}

// BAD — constraint is a paragraph; concrete copies would be simpler
func Process[T interface{ Read() ([]byte, error); Close() error }](r T) error { ... }
    // Just take io.ReadCloser
```

**I6. Zero generic types in the initial implementation is fine.** Every generic type adds cognitive overhead. Only introduce generics when you have 2+ concrete instantiations. The ZeroTrust.sh codebase starting at zero is acceptable — but new code must justify not using generics where they'd eliminate duplication.

### Documentation

**D1. Every exported identifier has a godoc comment.** Package, type, function, method, constant, variable. The comment starts with the identifier name.

```go
// Scanner scans a filesystem path for AI-generated code vulnerabilities.
// It runs both pattern detection (Path A) and semantic detection (Path B)
// in parallel, returning merged findings.
type Scanner struct { ... }

// Scan executes a full scan of the given path and returns findings.
// It blocks until both detection paths complete or ctx is cancelled.
func (s *Scanner) Scan(ctx context.Context, path string) (*Report, error)
```

**D2. Package-level godoc describes the package's purpose.** Every package under `internal/` must have a `doc.go` or a leading package comment explaining what the package provides and what imports it.

**D3. Error sentinel docs say when they are returned.**

```go
// ErrNotFound is returned when a requested resource does not exist.
var ErrNotFound = errors.New("not found")
```

**D4. Test functions have a comment explaining the scenario.** `// TestScan_EmptyDirectory verifies that scanning an empty directory returns zero findings without error.`

**D5. `//nolint` comments include a reason.** `//nolint:errcheck // rand.Read is best-effort; failure does not affect scan integrity — only reduces entropy quality`

---

## Python Standards

### Type Safety

**T1. Every function signature has type annotations.** Parameters and return types. No `def foo(x, y):` without types. `mypy --strict` must pass.

```python
# GOOD
def scan_file(path: str, rules: list[Rule]) -> Finding | None: ...

# BAD
def scan_file(path, rules): ...
```

**T2. Use `X | None` over `Optional[X]`.** Python 3.10+ union syntax is shorter and consistent with the type checker's display.

```python
# GOOD
def load(path: str) -> dict[str, Any] | None: ...

# BAD
from typing import Optional
def load(path: str) -> Optional[dict[str, Any]]: ...
```

**T3. Use `TypedDict` for dictionary shapes.** When passing dicts with known keys, do not use `dict[str, Any]`. Define a `TypedDict`.

```python
from typing import TypedDict, NotRequired

class FindingDict(TypedDict):
    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    patch: NotRequired[str]
```

**T4. Use `dataclass` for internal data structures, Pydantic for boundary validation.** Dataclasses are lightweight and type-checked. Pydantic models are for data arriving from outside (CLI args, file I/O, NDJSON from Go parent).

```python
@dataclass
class BatchResult:
    findings: list[Finding]
    tokens_used: int
    duration_ms: float
```

**T5. Avoid `Any`; it disables checking everywhere it flows.** If a third-party library is untyped, wrap it in a thin typed facade. Tag the untyped import with `# type: ignore[import]` and document why.

**T6. Use `# type: ignore[code]` with specific error codes, never bare.** Bare `# type: ignore` suppresses all errors on that line. Always specify the code: `# type: ignore[arg-type]`.

### Error Handling

**E1. Raise specific exception types.** Never `raise Exception("something broke")`. Define domain exceptions in `worker/exceptions.py`.

```python
class ModelLoadError(Exception):
    """Raised when a model cannot be loaded from disk."""

class InferenceTimeout(Exception):
    """Raised when inference exceeds the configured timeout."""
```

**E2. Use `logging` with structured fields, not print.** Every module gets `logger = logging.getLogger(__name__)`. Include context as extra fields, not f-string interpolation.

```python
logger.error("inference failed", extra={"model": model_name, "tokens": token_count, "duration_ms": elapsed})
```

**E3. Never silence exceptions without a comment.** Bare `except: pass` is prohibited. Use `except Exception: logger.exception("...")` or a specific handler with a documented reason.

```python
# GOOD
try:
    result = model.predict(inputs)
except RuntimeError as e:
    if "CUDA out of memory" in str(e):
        logger.warning("OOM, falling back to CPU", extra={"batch_size": len(inputs)})
        result = model.cpu().predict(inputs)
    else:
        raise
```

**E4. Handle NDJSON protocol errors explicitly.** The Go parent communicates via newline-delimited JSON. Malformed lines, missing fields, and unexpected message types must produce structured error responses (JSON `{"error": "...", "code": "PARSE_ERROR"}`), not bare exceptions.

### Organization

**O1. Module layout follows a flat, handler-per-file structure.**

```
worker/
  main.py                  ← async NDJSON dispatcher (event loop)
  exceptions.py            ← domain exception types
  schemas.py               ← TypedDict definitions for all IPC messages
  handlers/
    scan.py                ← handle "scan" message type
    classify.py            ← handle "classify" message type
    enrich.py              ← handle "enrich" message type
  models/
    unixcoder.py           ← CodeT5+ model wrapper
    classifier.py          ← classifier interface + implementations
    registry.py            ← model registry (load, cache, evict)
```

**O2. `main.py` is the event loop, ≤100 lines.** It reads NDJSON from stdin, dispatches to the correct handler, and writes NDJSON to stdout. Handlers are stateless functions or thin classes injected at startup.

**O3. All imports are explicit.** No `from module import *`. No wildcard imports. Use `isort` with the default Black-compatible config.

**O4. Handlers are synchronous (for now), but structured for async.** Wrap the synchronous handler body in a function that returns a coroutine or use `asyncio.to_thread` for CPU-bound model inference. Event-driven I/O for NDJSON dispatch must not block.

```python
async def handle_scan(msg: dict) -> dict:
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, _scan_sync, msg)
    return result
```

---

## Development Techniques

### Function Design Discipline

Every function in this codebase must carry its weight. The era of "write a function for every 3-line operation" or "make one giant 200-line function" ends now. Function boundaries are the single most consequential design decision in the codebase — they determine testability, reusability, readability, and change-propagation cost.

**F1. A function must pass the Name Test.** If you cannot name what a function does in ≤5 words using a verb-noun pair (`ParseConfig`, `ValidatePort`, `BuildCPG`), the abstraction is wrong. Names like `processData`, `handleStuff`, `doWork`, `run`, `execute`, `performOperation` are banned — they describe nothing and conceal everything.

```go
// GOOD — clear verb-noun
func ParseConfig(data []byte) (*Config, error)
func BuildCPG(ctx context.Context, dir string) (string, error)
func TaintPaths(ctx context.Context, cpgID string) ([]TaintPath, error)

// BAD — name tells you nothing
func process(data []byte) (*Config, error)
func run(ctx context.Context, dir string) (string, error)
func get(ctx context.Context, cpgID string) ([]TaintPath, error)
```

**F2. Justifications for creating a new function.** A function must satisfy at least one of these criteria. If it satisfies none, the code must be inlined.

| # | Criterion | Check | Example |
|---|-----------|-------|---------|
| 1 | **Unit of abstraction** | The function encapsulates a distinct operation that can be named with a clear verb-noun | `ParseConfig`, `ValidateInput`, `HashFile` |
| 2 | **Unit of reuse** | The code is called from 2+ call sites | The 3rd occurrence triggers extraction (three-strikes rule) |
| 3 | **Unit of testability** | The logic has multiple paths (branching, error handling, loops) that require table-driven testing | `func validatePort(port string) error` needs 10+ test cases |
| 4 | **Unit of change** | The logic changes for different reasons than its caller (SRP at function level) | Token parsing changes when format changes; report rendering changes when layout changes — separate functions |
| 5 | **Interface satisfaction** | The function implements an interface method | Required by Go's type system |
| 6 | **Readability decomposition** | The parent function exceeds 40 lines and splitting produces named steps where each step name explains intent | `func Scan(ctx) error { findFiles(); classify(); deduplicate(); report() }` |

**F3. Conditions that prohibit creating a new function.** If any of these apply, the code MUST NOT be extracted into a separate function:

| # | Condition | Why | Fix |
|---|-----------|-----|-----|
| 1 | **Body is 1–3 lines, single call site** | The indirection costs more than the code saves | Inline it |
| 2 | **Name is less clear than the code** | `processItem(x)` is worse than `x.Normalize(); x.Validate()` | Inline or find a real name |
| 3 | **5+ parameters all forwarded from caller** | The function is just a passthrough — callers must know all params anyway | Use a struct parameter or inline |
| 4 | **Test-only usage** | If only tests call it, make it unexported or test through the public API | Move to `_test.go` or delete |
| 5 | **Standard library duplicate** | `sort.Slice(x, ...)` beats writing `sortItems(x)` | Remove the wrapper |
| 6 | **Single boolean parameter that splits behavior** | `process(x, true)` vs `process(x, false)` are two functions pretending to be one | Split into `processEnabled(x)` and `processDisabled(x)` |

```go
// BAD — 3 lines, single call site, name is opaque
func saveResult(path string, data []byte) error {
    return os.WriteFile(path, data, 0o644)  // just calls WriteFile — why wrap it?
}

// BAD — 5 forwarded parameters
func processOrder(ctx, db, userID, orderID, status string) error {
    return processOrderInternal(ctx, db, userID, orderID, status)
}

// BAD — boolean parameter splits behavior
func handleRequest(ctx context.Context, admin bool) error {
    if admin {
        return handleAdminRequest(ctx)
    }
    return handleUserRequest(ctx)
}
// FIX: caller chooses which to call
```

**F4. Conditions for unifying multiple functions into one.** Proliferation is as harmful as monolithic functions. Unify when:

| # | Condition | Pattern |
|---|-----------|---------|
| 1 | **Same start + end, different middle** | Extract the middle as a callback/parameter |
| 2 | **Differ only by a constant, type, or operator** | Parameterize the difference |
| 3 | **Always called in sequence, output→input chain** | Compose them into one function, or keep separate but document the calling order |
| 4 | **Operate on the same struct, share state** | They should be methods, not standalone functions |
| 5 | **Names differ by one word, bodies ≤30% different** | Parameterize the varying part. `parseJSONConfig` + `parseYAMLConfig` → `parseConfig(format string)` |
| 6 | **Orphan functions** | A function exported from a package but imported by zero other packages within the module (check with `go list -deps`) | Unexport or inline |

```go
// BAD — two functions, same logic, differ only by default value
func defaultRetry() int { return 3 }
func aggressiveRetry() int { return 10 }
// FIX: func retryPolicy(level string) int { switch level { ... } }

// BAD — two functions always called together
cfg := parseConfig(path)
validateConfig(cfg)
saveConfig(cfg)
// FIX: one function does all three, OR document that callers MUST call all three

// GOOD — legitimately different abstractions
func generateCPG(ctx context.Context, path string) error    // invokes Joern
func analyzeCPG(ctx context.Context, cpgID string) error     // queries Joern
// These change for different reasons and have separate test surfaces — keep separate
```

**F5. Function size boundaries (hard limits).**

| Size | Rating | Rule |
|------|--------|------|
| 1–7 lines | **Inline territory** | Must satisfy ≥1 criterion from F2. If not, inline. |
| 8–20 lines | **Ideal** | No justification needed. Fits one screen. |
| 21–40 lines | **Acceptable** | Must pass the Name Test (F1). Consider whether a helper extraction would improve readability. |
| 41–60 lines | **Warning** | Requires a comment: `// >40 lines justified: <reason>`. Acceptable reasons: complex switch/table dispatch, long but straight-line initialization, generated code. Unacceptable: "it all belongs together" — if it belongs together, it belongs in a smaller function. |
| >60 lines | **Blocked** | Must be decomposed. If you cannot decompose it, the abstraction is wrong — reconsider the design. No function in the ZeroTrust.sh codebase may exceed 60 lines. |

**Exception**: Function-literals passed to `sort.Slice`, `slices.SortFunc`, or similar higher-order functions when the body is a single comparison expression.

**F6. Maximum nesting depth: 3.** Any function with 4+ levels of indentation (`if` inside `if` inside `if` inside `for`) must be restructured. Extract inner blocks as named functions, use guard clauses, or invert conditions.

```go
// BAD — 4 levels deep
func (s *Scanner) process(path string) error {
    file, err := os.Open(path)
    if err == nil {
        defer file.Close()
        data, err := io.ReadAll(file)
        if err == nil {
            for _, rule := range s.rules {
                if rule.Matches(data) {
                    if rule.Severity > 5 {
                        s.report.Add(...)
                    }
                }
            }
        }
    }
    return nil
}

// GOOD — guard clauses, flat
func (s *Scanner) process(path string) error {
    file, err := os.Open(path)
    if err != nil {
        return fmt.Errorf("open %s: %w", path, err)
    }
    defer file.Close()

    data, err := io.ReadAll(file)
    if err != nil {
        return fmt.Errorf("read %s: %w", path, err)
    }

    for _, rule := range s.rules {
        s.checkRule(data, rule)
    }
    return nil
}
```

**F7. No multi-function files without a clear grouping principle.** If a `.go` file contains 5+ function definitions, they must all be methods on the same type OR all be pure functions in the same concern. An 800-line file with 20 unrelated functions is prohibited — split by function group.

```
scanner.go              ← Scanner type + its methods
scanner_config.go       ← config parsing for Scanner (if >1 function)
scanner_helpers.go      ← unexported helpers for Scanner (if >3 functions)
```

### DRY & Abstraction Discipline

**A1. Three-strikes rule.** The first time you write something, write it inline. The second time, leave it. The third time, extract. Never abstract for a hypothetical fourth occurrence.

**A2. Every function must justify its existence.** A function that is called from a single site must be either:
- A well-named, self-documenting extraction (the name tells you what it does better than inline code would)
- Required by an interface
- A test helper

**A3. Every interface must justify its existence.** An interface with a single concrete implementation needs a reason: testability (mock injection), polymorphic dispatch (multiple implementations), or dependency inversion (breaking a cycle). Document the reason.

**A4. Every type parameter (generic) must justify its existence.** A generic type parameter that is instantiated with exactly one concrete type across the entire codebase should be replaced with that concrete type.

**A5. Favor composition over embedding.** Embedding a struct in Go is not inheritance — it is syntactic sugar for delegation. Use it when the embedded type's full interface is part of the embedding type's contract. For selective reuse, use a named field.

### Computational Complexity

**C1. Document Big-O on hot paths.** Any function that iterates over unbounded input must have a comment documenting its time and space complexity. The threshold: if `n` can exceed 1,000 in production, document it.

```go
// ParseResults deduplicates findings by fingerprint.
// Time: O(n log n) due to sort + two passes over findings.
// Space: O(n) for the dedup map.
func ParseResults(findings []Finding) ([]Finding, error) { ... }
```

**C2. No quadratic or worse algorithms without justification.** O(n²) nested loops over file lists, finding lists, or scan targets must have a comment explaining why a more efficient algorithm doesn't apply (e.g., "pairwise comparison required because scoring is non-associative").

**C3. Always use the standard library's sorted/map/set operations.** Never reimplement binary search (`sort.Search`), set operations (maps with `struct{}` values), or deduplication (map keyed by fingerprint). The stdlib is tested, tuned, and understood by every Go developer.

### Concurrency Patterns

**C1. Fan-out/fan-in for independent parallel work.** Use `errgroup.WithContext` with `g.SetLimit(N)` for fan-out. Collect results via a buffered channel sized to the number of workers, then drain in the fan-in.

```go
func (s *Scanner) scanFiles(ctx context.Context, files []string) ([]Finding, error) {
    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(runtime.GOMAXPROCS(0))

    results := make(chan Finding, len(files))

    for _, f := range files {
        f := f
        g.Go(func() error {
            finding, err := s.scanOne(ctx, f)
            if err != nil {
                return fmt.Errorf("%s: %w", f, err)
            }
            if finding != nil {
                results <- *finding
            }
            return nil
        })
    }

    go func() {
        g.Wait()
        close(results)
    }()

    var all []Finding
    for r := range results {
        all = append(all, r)
    }

    if err := g.Wait(); err != nil {
        return nil, err
    }
    return all, nil
}
```

**C2. Pipeline pattern for sequential stages.** When processing follows a producer → transformer → consumer flow, use channels between stages. Each stage is an `errgroup` goroutine. Context cancellation propagates through the pipeline.

**C3. Worker pool for bounded CPU work.** Use `g.SetLimit(N)` with `N = runtime.GOMAXPROCS(0)` for CPU-bound work and `N = 100+` for I/O-bound work. Tune via benchmarks, not guesses.

**C4. Never use `sync.WaitGroup` for error-producing goroutines.** Use `errgroup.Group`. Reserve `sync.WaitGroup` for goroutines that genuinely cannot fail (e.g., background log flusher).

### Hot Path Optimization

**H1. Profile before optimizing.** No performance optimization is accepted without a benchmark or profile showing the bottleneck. `go test -bench=. -benchmem` or `pprof` must demonstrate the improvement.

**H2. Minimize allocations in hot paths.** Use `sync.Pool` for frequently allocated temporary objects (e.g., buffer pools for file I/O). Pre-allocate slices with `make([]T, 0, n)` when size is known.

**H3. I/O is the enemy; batch it.** File reads, network calls, and database queries must be batched where possible. Reading 10,000 files one-at-a-time sync is wrong; use `errgroup` fan-out or `filepath.Walk` with concurrent processing.

**H4. Zero-copy where practical.** Use `io.ReaderFrom`, `io.WriterTo`, and `bytes.Buffer` to avoid unnecessary copies between buffers.

**H5. For Python hot paths in inference:**
- Use `torch.no_grad()` and `torch.compile` for model forward passes
- Use `run_in_executor` with a `ProcessPoolExecutor` to keep model inference off the async event loop
- Batch inference requests (await 20ms or 8 samples, whichever comes first) for GPU utilization

---

## Enforcement

**Self-check before every PR.** Run this checklist before opening a pull request:

- [ ] `golangci-lint run --config .golangci.yml ./...` passes cleanly (Go)
- [ ] `mypy --strict worker/` passes (Python)
- [ ] `go vet ./...` passes
- [ ] `go test -race ./...` passes
- [ ] No `//nolint` without an inline reason comment
- [ ] No `context.Background()` inside request-handling goroutines
- [ ] Every `go` statement has a documented shutdown path and lifecycle owner
- [ ] Every error is wrapped with `fmt.Errorf("...: %w", err)` or explicitly handled
- [ ] All exported symbols have godoc comments
- [ ] No function exceeds 60 lines — if it does, it must be decomposed (F5)
- [ ] Every new function satisfies ≥1 criterion from F2 (Function Design Discipline)
- [ ] No function violates the prohibition conditions F3 (boolean parameter splitting, 5+ forwarded params, etc.)
- [ ] No orphan functions — check with `go list -deps` before exporting
- [ ] No file exceeds 600 lines
- [ ] Nesting depth ≤3 in every function
- [ ] All new dependencies in `go.mod` or `requirements.txt` are justified in PR description
- [ ] Complexity: no unbounded O(n²) or worse without a comment explaining why it's unavoidable

**Non-compliance procedure:**
1. First offense in a PR: reviewer marks the file and the agent fixes it before merge.
2. Second offense in the same PR: the entire PR is rejected and must be re-scoped.
3. Repeated offenses across PRs: the agent's commit access is revoked and all changes require manual review.

---

*This contract evolves. PRs that improve its rules — adding clarity, removing ambiguity, updating for new Go versions — are always welcome. PRs that add loopholes are not.*
