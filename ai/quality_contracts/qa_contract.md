# QA Quality Contract

## Preamble

Tests exist to find bugs, not to satisfy coverage. A test that never fails is worse than no test. A suite that passes against broken code is not a test suite — it's a build step that wastes everyone's time.

Every test in this repository will be judged by one criterion: **would this test fail if the code were wrong?** If the answer is "no" or "maybe," the test is rejected.

This contract is binding on all coding agents writing tests for ZeroTrust.sh. Violations are review-blockers.

---

## Test Levels

### Unit Tests

**Scope**: A single function, method, or struct. All external dependencies mocked or provided as test doubles.

**Speed**: <1ms per test. If a unit test takes longer than that, it's either not a unit test or it's doing something wrong.

**When to write**: Every public function. Every private function complex enough to warrant it. Bug fixes must include a unit test that exercises the exact path that was broken.

**Characteristics**:
- No network calls
- No disk I/O (no reading files, no writing to testdata)
- No database queries
- Deterministic — same inputs always produce same outputs
- Run with `go test -short` and `go test -race`

**Rejected patterns**:
- Tests that only call a function and check it doesn't panic
- Tests that assert `NoError` but never check the output is correct
- Tests that mock everything so thoroughly they test the mock, not the code

### Integration Tests

**Scope**: Verification that a component works with its real dependencies — SQLite, Ollama, Joern, filesystem.

**Gate**: Build tag `//go:build integration` (Go) or `@pytest.mark.integration` (Python). Never run in `-short` mode.

**Speed**: <5s per test. If it's slower, it's an E2E test.

**Characteristics**:
- Use `testcontainers-go` or local processes for dependencies
- Clean up all resources (close connections, remove temp dirs, kill subprocesses)
- Assert on behavior, not implementation
- Include error path testing: what happens when Ollama returns 503? When SQLite disk is full? When Joern crashes?

**When to write**: One integration test per major happy path + one per known failure mode. Not one per unit test case.

### End-to-End Tests

**Scope**: Full pipeline from CLI invocation to HTML report output.

**Gate**: Build tag `//go:build e2e` or `@pytest.mark.e2e`. Requires special CI runner.

**Speed**: Minutes. Run on main branch merges and release candidates only.

**Quantity**: 3–5 max. One golden-path happy case, two failure cases (bad input, dependency unavailable), one regression case for every confirmed production bug.

**Characteristics**:
- Use golden file comparison for HTML output
- Measure: exit code, stderr content, report existence, key findings present
- Do NOT assert on exact line numbers or timestamps (change detector trap)

### Acceptance Tests

**Scope**: Business scenarios — "as a security engineer, I want to scan a modified codebase and see only new findings."

**Gate**: Build tag `//go:build acceptance` or `@pytest.mark.acceptance`.

**Characteristics**:
- Written in plain language with structured GIVEN/WHEN/THEN comments
- Test the contract, not the implementation
- Use the public CLI API only (package `cmd/zerotrust`)

---

## Go Test Standards

### Table-Driven Tests

Table-driven tests are the **default pattern** for every Go test with more than one input case. Exceptions require justification in a comment.

**Required structure**:

```go
func TestValidateEmail(t *testing.T) {
    t.Parallel()

    tests := []struct {
        name  string
        input string
        want  bool
    }{
        {name: "valid email", input: "user@example.com", want: true},
        {name: "missing @", input: "userexample.com", want: false},
        {name: "empty string", input: "", want: false},
        {name: "only domain", input: "@example.com", want: false},
        {name: "unicode email", input: "üser@example.com", want: true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()
            got := validateEmail(tt.input)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

**Rules**:
- Every test case **must** have a `name` field (descriptive, lowercase, underscores allowed)
- Every case must be a `t.Run` subtest — flat test functions are banned for multi-case scenarios
- No branching logic (`if`, `switch`) inside the test body. Every case exercises the same assertions
- Use `t.Parallel()` in the parent AND in each subtest
- Each case must be self-contained — no shared mutable state between cases
- Error cases and success cases must be in the same table, interleaved
- Adding a case must be a one-line struct literal addition. If you need more than that, you're testing something different and need a separate test function

**Good**: One table, 15 cases, 15 subtests, all parallel, each case is a single struct.
**Bad**: Five separate `TestXxx` functions that differ only in the input value.
**Rejected**: A `for` loop without `t.Run` that stops at the first failure.

### Test Helpers & Parallelism

**`t.Helper()`** is mandatory on every function that accepts `*testing.T` and is not itself a test:

```go
// BAD — failure points to line inside readFile, not the test
func readFile(t *testing.T, path string) string {
    data, err := os.ReadFile(path)
    require.NoError(t, err)
    return string(data)
}

// GOOD — failure points to the caller's line
func readFile(t *testing.T, path string) string {
    t.Helper()
    data, err := os.ReadFile(path)
    require.NoError(t, err)
    return string(data)
}
```

**`t.Parallel()`** on every top-level test function and every subtest that is independent:

```go
func TestFinder_Scan(t *testing.T) {
    t.Parallel() // marks the parent

    t.Run("finds nothing in empty dir", func(t *testing.T) {
        t.Parallel() // marks the subtest
        // ...
    })

    t.Run("finds finding in seeded dir", func(t *testing.T) {
        t.Parallel()
        // ...
    })
}
```

**`t.Cleanup()`** over `defer` in any test that uses `t.Parallel()` in subtests:

```go
// BAD — defer runs before parallel subtests finish
func TestWithServer(t *testing.T) {
    srv := httptest.NewServer(handler)
    defer srv.Close() // NOT SAFE with parallel subtests

    t.Run("sub", func(t *testing.T) {
        t.Parallel()
        // srv may be closed before this runs
    })
}

// GOOD — cleanup runs after all parallel subtests complete
func TestWithServer(t *testing.T) {
    srv := httptest.NewServer(handler)
    t.Cleanup(srv.Close)

    t.Run("sub", func(t *testing.T) {
        t.Parallel()
        // srv is still open
    })
}
```

**Rationale**: `defer` in the parent function executes when the parent returns. With `t.Parallel()`, subtests are **paused** (not finished) when the parent returns. `t.Cleanup()` is aware of the testing lifecycle and runs after all subtests complete.

### Error & Edge Case Coverage

Every test must exercise **both** the success path and the error path. A function that returns `(result, error)` must be tested with inputs that produce each error.

**Minimum edge case checklist** (apply to every function):

| Case | Example | Why it matters |
|------|---------|----------------|
| Nil input | `ParseConfig(nil)` | Panic in production |
| Empty input | `ParseConfig([]byte{})` | Off-by-one, slice bounds |
| Boundary | `len == 0`, `len == max` | Integer overflow, slice capacity |
| Timeout | `ctx, cancel := context.WithTimeout(ctx, 1*time.Nanosecond)` | Goroutine leak, hanging |
| Cancellation | `ctx, cancel := context.WithCancel(ctx); cancel()` | Not checking ctx.Err() |
| Concurrent access | `go func() { ... }()` from 10 goroutines | Race condition, data corruption |
| Overflow | `math.MaxInt64 + 1` | Silent wraparound |
| Negative | `count = -1` | Panic in make(), loop bounds |

**Example — a complete test for a function with edge cases**:

```go
func TestParsePort(t *testing.T) {
    t.Parallel()

    tests := []struct {
        name    string
        input   string
        want    int
        wantErr string
    }{
        {name: "valid port", input: "8080", want: 8080, wantErr: ""},
        {name: "zero port", input: "0", want: 0, wantErr: "port must be positive"},
        {name: "negative", input: "-1", want: 0, wantErr: "invalid syntax"},
        {name: "overflow", input: "999999", want: 0, wantErr: "port out of range"},
        {name: "empty", input: "", want: 0, wantErr: "invalid syntax"},
        {name: "non-numeric", input: "abc", want: 0, wantErr: "invalid syntax"},
        {name: "max valid", input: "65535", want: 65535, wantErr: ""},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()
            got, err := parsePort(tt.input)
            if tt.wantErr != "" {
                require.Error(t, err)
                assert.Contains(t, err.Error(), tt.wantErr)
            } else {
                require.NoError(t, err)
                assert.Equal(t, tt.want, got)
            }
        })
    }
}
```

**Assertion discipline**:
- `require.*` — use for fatal conditions. If setup fails, the test can't proceed. If the function under test returns an error you're about to pass to `assert`, use `require`.
- `assert.*` — use for non-fatal value checks. Multiple assertions per test case are fine.
- Default to `require.NoError` over `assert.NoError` when the result value is used immediately after.

### Mocking & Dependency Isolation

**Strategy**: Interface-based mocks injected through constructors. No global state, no monkey-patching, no init() overrides.

```go
// GOOD — mock injected via constructor
type FileFinder struct {
    fs FS // interface
}

func NewFileFinder(fs FS) *FileFinder {
    return &FileFinder{fs: fs}
}

// test
func TestFileFinder_Scan(t *testing.T) {
    mockFS := newMockFS()
    mockFS.SetFile("testdata/result.json", []byte(`{"finding": "XSS"}`))
    finder := NewFileFinder(mockFS)

    results, err := finder.Scan(".")
    require.NoError(t, err)
    assert.Len(t, results, 1)
}
```

**Rules**:
- Prefer hand-rolled stub implementations (small, readable, no framework) over mock frameworks
- If you use `testify/mock`, generate mocks for interfaces only, not concrete types
- Mock at boundary interfaces — not one level deeper than the code under test uses
- Every mock must document what it returns for each call and what assertions it makes about call arguments
- `gomock` is acceptable if already in use; `testify/mock` preferred for consistency

**Rejected patterns**:
- Mocking a function you just wrote (test the real function instead)
- Mocking the standard library (wrap it in your own interface if you must)
- Mocking so the test never exercises error handling in the real code

### Test Function Discipline

Test functions are not exempt from the SWE contract's Function Design Discipline. A test that is too long, too vague, or testing multiple things at once is a maintenance liability that will be skipped, ignored, or deleted.

**TF1. One test function = one scenario.** A function named `TestScanner` that tests happy path, error path, edge cases, and concurrency is four tests in one. Every `t.Run` name must complete the sentence "it should ___": `"return error on empty input"`, `"skip hidden files"`, `"handle context cancellation"`.

```go
// BAD — one function, multiple unrelated concerns
func TestScanner(t *testing.T) {
    // tests happy path
    // tests error path
    // tests concurrency
    // tests edge cases
    // 80 lines later...
}

// GOOD — each scenario is a named subtest or a separate function
func TestScanner_Scan(t *testing.T) {
    t.Parallel()
    tests := []struct {
        name string  // completes "it should ..."
        // ...
    }{
        {name: "return findings for vulnerable file"},
        {name: "return empty for clean file"},
        {name: "skip files larger than max size"},
        {name: "propagate context cancellation"},
        {name: "handle empty directory without error"},
    }
    // ...
}
```

**TF2. Test function size boundaries.**

| Size | Rating | Rule |
|------|--------|------|
| 1–15 lines | **Ideal** | Setup + single assertion. The `require.NoError` + `assert.Equal` pattern. |
| 16–25 lines | **Acceptable** | Table-driven setup with 5–10 cases. If the test body exceeds 25 lines, extract helpers. |
| 26–40 lines | **Warning** | Must have a comment explaining why. Acceptable: complex mock setup for an integration test. |
| >40 lines | **Rejected** | Must be decomposed. A test that takes 40+ lines to set up is testing the wrong abstraction — the code under test needs better design, not the test. |

**TF3. Test helpers are not tests.** A helper function that calls `require.NoError` or `assert.Equal` on behalf of a test is acceptable. A helper that performs the entire test scenario, calls multiple assertions, and is shared across test files is a hidden test — if it fails, the developer has to debug which caller triggered the failure.

```go
// GOOD — helper does one thing
func mustReadFile(t *testing.T, path string) []byte {
    t.Helper()
    data, err := os.ReadFile(path)
    require.NoError(t, err)
    return data
}

// BAD — helper is a hidden test
func assertValidConfig(t *testing.T, data []byte) {
    t.Helper()
    cfg, err := ParseConfig(data)
    require.NoError(t, err)
    require.NotNil(t, cfg)
    assert.NotEmpty(t, cfg.Name)
    assert.Positive(t, cfg.Port)
    assert.InDelta(t, 1.0, cfg.Version, 0.01)
    // This is a full test scenario — callers can't tell which assertion failed
}
```

**TF4. Test setup must not duplicate production logic.** A test that constructs an expected result using the same code path as the function under test tests nothing — it tests that `x == x`. Use literal expected values, golden files, or independently derived expected values.

```go
// BAD — test replicates production logic
func TestHashFile(t *testing.T) {
    data := []byte("hello")
    hash := sha256.Sum256(data)
    // test calls sha256.Sum256 internally — passes by construction
    got, err := HashFile(bytes.NewReader(data))
    require.NoError(t, err)
    assert.Equal(t, hex.EncodeToString(hash[:]), got)
}

// GOOD — known-answer test
func TestHashFile(t *testing.T) {
    // Known SHA-256 of "hello" — independently verified
    const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    got, err := HashFile(strings.NewReader("hello"))
    require.NoError(t, err)
    assert.Equal(t, want, got)
}
```

**TF5. Test hooks vs test code.** When production code needs testability hooks (e.g., `var timeNow = time.Now` for injecting fixed timestamps), the hook must be:
1. A package-level variable (not a function parameter added for testing)
2. Documented with `// overridden in tests` comment
3. Replaced by interface injection before the 3rd test file needs it

```go
// ACCEPTABLE — documented override point
var timeNow = time.Now  // overridden in tests

func TestExpiredToken(t *testing.T) {
    timeNow = func() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }
    t.Cleanup(func() { timeNow = time.Now })  // restore
    // ...
}
```

**TF6. Test files have the same organization rules as production files.** A `_test.go` file exceeding 400 lines must be split. Test helper functions go in `export_test.go` (for accessing unexported symbols) or `*_test.go` alongside the tests. No `testutil/` or `helpers_test.go` grab-bag packages.

### Golden Files & Snapshot Testing

For complex outputs (HTML reports, serialized findings, multi-line logs), use golden file comparisons:

```go
func TestReportGeneration(t *testing.T) {
    t.Parallel()
    report := generateReport(testFindings)
    golden := filepath.Join("testdata", "report.golden.html")
    expected, err := os.ReadFile(golden)
    require.NoError(t, err)
    assert.Equal(t, string(expected), report)
}
```

**Rules**:
- Store golden files in `testdata/` next to the test file
- Use `-update` flag convention to regenerate: `go test -update` writes new golden files
- Review golden file diffs in PRs carefully — they're change detectors and must be semantically meaningful
- Never assert on exact whitespace, timestamps, or randomly generated IDs unless they're the subject of the test

---

## Python Test Standards

### Fixtures & Parametrization

**Fixtures** are mandatory for any shared setup. `conftest.py` at each test directory level for shared fixtures.

```python
# GOOD — fixture with cleanup
@pytest.fixture
def temp_scan_dir(tmp_path):
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    (scan_dir / "main.py").write_text("x = 1")
    yield scan_dir
    # cleanup happens automatically via tmp_path


def test_scanner_finds_files(temp_scan_dir):
    scanner = Scanner(temp_scan_dir)
    results = scanner.scan()
    assert len(results) == 1
```

**Parametrization** for table-driven testing:

```python
# GOOD — parametrize with explicit IDs
@pytest.mark.parametrize("input,expected", [
    ("user@example.com", True),
    ("not-an-email", False),
    ("", False),
    pytest.param(None, False, id="none input"),
], ids=["valid", "invalid", "empty", "none"])
def test_validate_email(input, expected):
    assert validate_email(input) is expected
```

**Rules**:
- Every parametrized case must have an explicit `id` or use `ids=` keyword
- Error cases and success cases in the same parametrize block
- Use `pytest.param` for cases needing special marks (xfail, skip)
- Fixture scope: `function` by default, `module` for expensive setup, `session` only for truly global resources (and only with cleanup)
- Never use Mutable default arguments in fixture factories

### Mocking Strategy

**Tool**: `pytest-mock` (the `mocker` fixture) — auto-cleanup, no manual `stopall`.

```python
# GOOD — mock at the right level
def test_scanner_ollama_timeout(mocker):
    mock_post = mocker.patch("httpx.Client.post", side_effect=TimeoutException)
    scanner = Scanner()
    with pytest.raises(ScanError, match="timeout"):
        scanner.analyze("test.py")
    assert mock_post.call_count == 3  # retry logic exercised

# BAD — mocking too deep, testing the mock
def test_scanner_ollama_timeout_bad(mocker):
    mock_client = mocker.MagicMock()
    mock_client.post.side_effect = TimeoutException
    mocker.patch("worker.models.ollama.OllamaClient", return_value=mock_client)
    # This tests that MagicMock works, not that our code handles timeouts
```

**Rules**:
- Mock at the **import boundary** of the code under test, not the third-party library
- Prefer `mocker.spy` over `mocker.patch` when verifying existing behavior
- Use `pytest.raises` for exception assertions, not `try/except` in tests
- Verify call counts and call args when mocking external services
- Never mock what you don't own without wrapping it in your own interface first

**Coverage thresholds** (enforced via `pytest-cov`):
- Unit tests: minimum 85% line coverage, 80% branch coverage
- Integration tests: minimum 60% line coverage on paths not covered by unit tests
- No coverage enforcement on `__init__.py`, `conftest.py`, or migration files

---

## Quality Gates

Every test submitted for review must pass these gates. Failure on any gate is a hard reject.

### Gate 1: The Test Fails When Code Is Wrong

Manually verify: introduce a deliberate bug in the code under test and confirm the test catches it.

| Mutation | Expected result |
|----------|-----------------|
| Change `>` to `>=` on a boundary check | Test must fail |
| Remove an `if err != nil` block | Test must fail |
| Swap the order of arguments in a call | Test must fail |
| Change a literal constant | Test must fail |
| Comment out a security check (auth, validation) | Test must fail |

If any of these mutations passes your test, the test is rejected. You must add the missing case.

### Gate 2: No Greenwasher Assertions

A greenwasher assertion is one that always passes regardless of the code's behavior:

```go
// REJECTED — always passes, proves nothing
func TestConfig_Parse(t *testing.T) {
    cfg, err := ParseConfig([]byte(`{}`))
    assert.NoError(t, err)
    // No assertion on cfg — the test "passes" even if ParseConfig returns nil
}

// REJECTED — testing the trivial case only
func TestValidatePort(t *testing.T) {
    err := ValidatePort("8080")
    assert.NoError(t, err)
    // Never tests what happens with invalid ports
}
```

**Detection**: If removing the assertion also makes the test pass, the assertion is a greenwasher. Remove it or replace it with a real assertion.

### Gate 3: Mutation Score Threshold

Run mutation testing on any new or modified code before submitting tests:

```
go-mutesting ./pkg/myfeature/...
```

Target: **≥80% mutation score on new code**. If mutants survive, add test cases until they're killed.

Priority mutation operators to cover:
- Relational operator replacement (`>`, `>=`, `<`, `<=`, `==`, `!=`)
- Boundary removal (`len(x) > 0` → `false`, `true`)
- Conditional boundary (`if a > b` → `if a >= b`)
- Negation of boolean expressions

### Gate 4: Race Condition Freedom

Every Go test must pass with the race detector:

```
go test -race ./...
```

A test that introduces a new race violation is rejected. Period.

If the race detector finds an existing violation in unrelated code, file a bug — don't silence the detector.

### Gate 5: No Goroutine Leaks

Every Go package must add `goleak.VerifyTestMain(m)` in a `TestMain` function:

```go
func TestMain(m *testing.M) {
    goleak.VerifyTestMain(m)
}
```

If a test legitimately leaks goroutines (long-lived server, background worker), use `goleak.IgnoreCurrent()` in the test's setup and document why.

### Gate 6: The Five-Second Rule

Read a test file you haven't seen before. Can you understand what's being tested in ≤5 seconds?

- If you need to scroll: **structure failure** — group setup at the top, cases in the middle, assertions predictable
- If you need to read helper functions to understand the test: **abstraction failure** — inline the logic or give the helper a better name
- If the test name doesn't describe the scenario: **naming failure** — `TestConfig` is not a name, `TestConfig_RejectsInvalidPort` is

---

## Enforcement

### Pre-Submit Self-Check (Agent Must Run)

Before writing a single test case, the coding agent must answer:

1. What am I testing? (one sentence)
2. What are the error paths? (list them)
3. What are the edge cases? (nil, empty, boundary, overflow, timeout, cancellation)
4. Is this a unit, integration, E2E, or acceptance test? (one answer)
5. How will I know the test is correct? (introduce a bug and verify)

If the agent cannot answer all five, it must not write the test.

### Mandatory Test Structure

Every Go test file must follow this skeleton:

```go
package mypackage

import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
    goleak.VerifyTestMain(m)
}

func TestFeature(t *testing.T) {
    t.Parallel()

    // --- setup ---
    // (use t.Cleanup, not defer)

    // --- test cases ---
    tests := []struct {
        name string
        input string
        want  string
        wantErr string
    }{
        // success and error cases interleaved
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()

            got, err := Feature(tt.input)

            if tt.wantErr != "" {
                require.Error(t, err)
                assert.Contains(t, err.Error(), tt.wantErr)
                return
            }
            require.NoError(t, err)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

Every Python test file must follow:

```python
import pytest


class TestFeature:
    """Tests for Feature."""

    @pytest.mark.parametrize("input,expected", [
        pytest.param("valid", "output", id="happy-path"),
        pytest.param("", None, id="empty-input"),
        pytest.param(None, None, id="none-input"),
    ])
    def test_basic(self, input, expected, some_fixture):
        result = feature(input)
        assert result == expected

    def test_error_case(self, some_fixture):
        with pytest.raises(ValueError, match="invalid"):
            feature("bad-input")
```

### Code Review Rejection Criteria

A reviewer must reject a test if it exhibits any of:

| Pattern | Example | Reason |
|---------|---------|--------|
| No error case | Tests only the happy path | Doesn't catch real failures |
| Flat without subtests | 15 top-level functions | Hard to read, can't target single case |
| Missing `t.Helper()` | Helper function without it | Failure points to wrong line |
| `defer` with `t.Parallel()` | Defer in parent of parallel subtest | Teardown runs too early |
| Greenwasher | `assert.NotNil(result)` with no value check | Passes even when code is wrong |
| Testing the mock | Mock setup > 3x the test assertions | Tests mock framework, not code |
| Untested edge case | No nil/empty/boundary case | Missing coverage on common failure |
| `for` without `t.Run` | Loop with `t.Errorf` | Stops on first failure, no naming |
| Missing `t.Parallel()` | Independent test running solo | Slow CI, no race detection |
| No `-race` pass | Race detector failure | Misses concurrency bugs |
| Magic numbers | Constants buried in test | Can't tell what's expected |
| Snapshot without review | Golden file never inspected | Change detector, not test |
| Exception test without `pytest.raises` | `try/except` in test | Error handling not validated |

### CI Enforcement

The CI pipeline must enforce:

1. `go test -short -race ./...` passes (unit tests)
2. `go vet ./...` passes
3. Mutation score ≥80% on changed packages (additive)
4. `goleak.VerifyTestMain` present in every package with goroutine-spawning tests
5. `pytest --cov-fail-under=85` passes
6. Integration tests pass (`go test -tags=integration ./...`)
7. No race violations (`go test -race ./...`)

Any test that requires `-skip`, `-flake-attempts`, or `-retry` to pass in CI is considered flaky and must be quarantined within 24 hours.

---

## Appendices

### A. Priority Migration Targets

From the project audit (2026-06-23), the following must be addressed in order:

1. **Add `t.Run()` subtests** to the 451 functions that lack them — every test file with ≥3 test cases must use table-driven pattern
2. **Add `t.Parallel()`** to all independent tests — starting with the pattern and semantic detection packages
3. **Add `t.Helper()`** to the 7+ helper functions identified as missing it
4. **Add `t.Cleanup()`** to all test server setups — replace `defer srv.Close()` where subtests use `t.Parallel()`
5. **Add `goleak.VerifyTestMain`** to every Go package
6. **Add edge case coverage** — nil inputs, empty inputs, boundary values, timeouts, cancellations — starting with parser and validator functions
7. **Replace ad-hoc mocks** with testify/mock or hand-rolled interface stubs with call-count verification

### B. ZeroTrust.sh-Specific Conventions

| Concern | Convention |
|---------|-----------|
| Assertion library | `github.com/stretchr/testify` v1.11.1 — `assert` for non-fatal, `require` for fatal |
| Test file location | `*_test.go` alongside the source file it tests |
| Test data | `testdata/` directory per-package, `.gitignore`-friendly |
| Integration gate | `//go:build integration` (Go), `@pytest.mark.integration` (Python) |
| E2E gate | `//go:build e2e` (Go), `@pytest.mark.e2e` (Python) |
| Python test dir | `worker/tests/` with `conftest.py` per subdirectory |
| Goroutine leak check | `goleak.VerifyTestMain` in every package's `TestMain` |
| Build tag examples | `go test -tags=integration ./...`, `go test -tags=e2e ./...` |
| Race detection | `go test -race ./...` — always, in CI and locally |

### C. References

- Go Table-Driven Tests: https://go.dev/wiki/TableDrivenTests
- Go Subtests: https://go.dev/blog/subtests
- Go Test Comments: https://go.dev/wiki/TestComments
- testify: https://pkg.go.dev/github.com/stretchr/testify
- goleak: https://github.com/uber-go/goleak
- go-mutesting: https://github.com/zimmski/go-mutesting
- pytest fixtures: https://docs.pytest.org/en/stable/how-to/fixtures.html
- pytest parametrize: https://docs.pytest.org/en/stable/how-to/parametrize.html
- pytest-mock: https://pytest-mock.readthedocs.io/
