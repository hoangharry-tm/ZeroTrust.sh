# CLI Output Design

Three output modes. **A** is the CI default (no TTY). **C** is the interactive non-TUI default (TTY, no Bubble Tea dependency). **TUI** is the full Bubble Tea experience, opt-in via `--output tui`.

 | Mode        | Flag               | Auto-selected when            | Use case                                 |
 |-------------|--------------------|-------------------------------|------------------------------------------|
 | A — Minimal | `--output minimal` | no TTY (pipe / redirect / CI) | CI/CD pipelines, servers, scripting      |
 | C — Tree    | `--output tree`    | TTY detected                  | Local dev, demos, interactive terminal   |
 | TUI         | `--output tui`     | never (always opt-in)         | Rich local experience, Bubble Tea panels |

---

## Mode selection

```go
switch outputFlag {
case "minimal":
    runMinimal()
case "tree":
    runTree()
case "tui":
    runTUI()
default:
    // auto-detect
    if isatty.IsTerminal(os.Stdout.Fd()) {
        runTree()    // TTY → tree (Option C)
    } else {
        runMinimal() // no TTY → minimal (Option A)
    }
}
```

---

## Option A — Minimal

Plain stdout. ANSI colors only when TTY; stripped when piped.
Target: CI/CD pipelines, servers, `| grep`, `> report.txt`.

```term
zerotrust scan ./spring-boot-app

zerotrust v0.1.0  spring-boot-app  default

» ingestion
  model   qwen2.5-3b · verified
  diff    4 files changed

» path/a
  opengrep    3 findings
  ast-grep    1 finding
  instrscan   clean

» path/b
  targeting   12 surfaces → 3 escalated
  classifier  2 safe · 1 uncertain
  llm         1 confirmed

» findings
  BLOCK  CWE-89   UserController.java:42   sql-injection-jdbc
  HIGH   CWE-798  config.py:11             hardcoded-ai-api-key
  HIGH   CWE-862  AuthService.java:88      missing-auth-guard
  MEDIUM CWE-94   CLAUDE.md:3              prompt-injection-directive

4 findings  (1 BLOCK · 2 HIGH · 1 MEDIUM)  2.3s
report → build/report.html
```

**Colors (TTY only):**

| Severity   | Style    |
|------------|----------|
| BLOCK      | Red bold |
| HIGH       | Red      |
| MEDIUM     | Yellow   |
| LOW        | Default  |
| SUPPRESSED | Dim      |

**Exit codes:**

| Code | Meaning                                   |
|------|-------------------------------------------|
| `0`  | No BLOCK or HIGH findings                 |
| `1`  | One or more BLOCK/HIGH findings — CI gate |
| `2`  | Scan error (tool failure)                 |

---

## Option C — Tree  ✓ selected for interactive non-TUI

Continuous log stream with indented tree structure.
Target: local dev, demos — feels like a real security audit running live. Zero extra dependencies beyond Lip Gloss for color.

```term
zerotrust v0.1.0 — spring-boot-app

  ┌ ingestion
  │  ✓ model     qwen2.5-3b · sha256:a3f9e1 · verified
  │  ✓ diff      4 changed · 18 unchanged · 0 deleted
  └

  ┌ path a — pattern detection
  │  ✓ opengrep  42 rules ················ 3 findings
  │  ✓ ast-grep  16 rules ················ 1 finding
  │  ✓ instrscan CLAUDE.md ·············· clean
  └

  ┌ path b — semantic detection
  │  ✓ targeting  12 surfaces selected
  │  ✓ classify   2 safe · 1 uncertain → escalated
  │  ✓ llm scan   1 confirmed
  └

  ┌ findings
  │  ✖ BLOCK   UserController.java:42    sql-injection-jdbc       CWE-89
  │  ● HIGH    config.py:11              hardcoded-ai-api-key     CWE-798
  │  ● HIGH    AuthService.java:88       missing-auth-guard       CWE-862
  │  ◌ MEDIUM  CLAUDE.md:3               prompt-injection         CWE-94
  └

  4 findings · 1 BLOCK · 2 HIGH · 1 MEDIUM · 2.3s
  report → build/report.html
```

---

## TUI (Bubble Tea) ✓ selected for `--output tui`

Stack: `bubbletea` + `lipgloss` + `bubbles` + `glamour`

Two states: **scanning** (live progress + log stream) and **done** (navigable findings + detail).

### Layout

Left panel — pipeline stage progress, always visible.
Right panel — tabbed, switchable with number keys.

| Tab | Key | Content |
|---|---|---|
| Log | `1` | Raw timestamped program log — all stages, hits, decisions. For devs to monitor and spot anomalies to report as issues. |
| Findings | `2` | Navigable findings list + selected finding detail, patch, suppress actions. |
| Summary | `3` | SSVC breakdown, scan metadata, module scope, timing per stage. |
| Suppressed | `4` | Auto-suppressed findings (test file, framework-safe, budget-exhausted, uncertain) — verifies nothing was silently dropped. |
| Patches | `5` | Unified diff view for all generated patches in one place, copyable. |

### Scanning state

```
  ZeroTrust.sh v0.1.0 — spring-boot-app — default
  ─────────────────────────────────────────────────────────────────────────────────────

  ┌─ pipeline ──────────────────┐  ┌─ [1:log] [2:findings] [3:summary] [4:suppressed] [5:patches] ─┐
  │                             │  │                                                                 │
  │  INGESTION          done    │  │  09:41:02  [MIV]      model qwen2.5-3b · hash match · verified │
  │  ✓ model   verified         │  │  09:41:02  [DI]       scanning 22 files · 4 changed            │
  │  ✓ diff    4 changed        │  │  09:41:03  [OG]       loaded 42 rules · starting scan          │
  │                             │  │  09:41:03  [AG]       loaded 16 rules · starting scan          │
  │  PATH A             done    │  │  09:41:04  [OG]       hit PY-006 · config.py:11                │
  │  ✓ opengrep  3 findings     │  │  09:41:04  [OG]       hit JV-002 · UserController.java:42      │
  │  ✓ ast-grep  1 finding      │  │  09:41:04  [AG]       hit AG-007 · CLAUDE.md:3                 │
  │  ✓ instrscan clean          │  │  09:41:05  [JOERN]    CPG built · 4 files · 1.2s               │
  │                             │  │  09:41:05  [TARGET]   12 surfaces selected                      │
  │  PATH B           running   │  │  09:41:06  [CLASSIFY] surface 1/3 · AuthService.java           │
  │  ✓ targeting  12 surfaces   │  │  09:41:06  [CLASSIFY] surface 1/3 · uncertain → escalated      │
  │  ✓ classify   1 escalated   │  │  09:41:07  [LLM]      analyzing AuthService.java:88 ...        │
  │  ⠿ llm scan  running...     │  │                                                                 │
  │                             │  │                                                                 │
  │  ████████████░░░░░  60%     │  │                                                                 │
  │                             │  │                                                                 │
  └─────────────────────────────┘  └─────────────────────────────────────────────────────────────────┘

  scanning · 1.7s                   1:log  2:findings  3:summary  4:suppressed  5:patches · q quit
```

### Done state — Tab 2 (findings)

```
  ┌─ pipeline ──────────────────┐  ┌─ [1:log] [2:findings] [3:summary] [4:suppressed] [5:patches] ─┐
  │                             │  │                                                                 │
  │  ✓ ingestion    0.1s        │  │  ✖  BLOCK   UserController.java:42   sql-injection-jdbc        │
  │  ✓ path a       0.8s        │  │  ●  HIGH    config.py:11             hardcoded-ai-api-key      │
  │  ✓ path b       1.4s        │  │  ●  HIGH    AuthService.java:88      missing-auth-guard        │
  │                             │  │  ◌  MEDIUM  CLAUDE.md:3              prompt-injection           │
  │  DONE           2.3s        │  │  ─────────────────────────────────────────────────────────     │
  │                             │  │  > UserController.java:42 · CWE-89 · confidence 0.97           │
  │  4 findings                 │  │                                                                 │
  │  1 BLOCK                    │  │    String query = "SELECT * FROM users WHERE id=" + userId;     │
  │  2 HIGH                     │  │                                                                 │
  │  1 MEDIUM                   │  │    Taint: HTTP param → JDBC sink · no sanitizer detected       │
  │  0 LOW                      │  │    Source: Path A (opengrep JV-002) + Path B (llm confirmed)   │
  │                             │  │                                                                 │
  │  report →                   │  │    [p] view patch   [s] suppress   [o] open in report          │
  │  build/report.html          │  │                                                                 │
  └─────────────────────────────┘  └─────────────────────────────────────────────────────────────────┘

  done · 2.3s                       ↑↓ navigate · p patch · s suppress · tab switch · q quit
```

### Done state — Tab 3 (summary)

```
  ┌─ pipeline ──────────────────┐  ┌─ [1:log] [2:findings] [3:summary] [4:suppressed] [5:patches] ─┐
  │                             │  │                                                                 │
  │  ✓ ingestion    0.1s        │  │  project      spring-boot-app                                  │
  │  ✓ path a       0.8s        │  │  mode         default                                          │
  │  ✓ path b       1.4s        │  │  started      2026-06-17 09:41:02                              │
  │                             │  │  duration     2.3s                                             │
  │  DONE           2.3s        │  │                                                                 │
  │                             │  │  files        4 changed · 18 unchanged                         │
  │  4 findings                 │  │  surfaces     12 selected · 9 eliminated · 1 escalated         │
  │  1 BLOCK                    │  │                                                                 │
  │  2 HIGH                     │  │  path a       4 findings  (opengrep 3 · ast-grep 1)            │
  │  1 MEDIUM                   │  │  path b       1 confirmed · 1 cross-path boost applied         │
  │  0 LOW                      │  │                                                                 │
  │                             │  │  scanned modules                                               │
  │  report →                   │  │    UserController · AuthService · SecurityConfig · +2 neighbors│
  │  build/report.html          │  │                                                                 │
  │                             │  │  SSVC dimensions                                               │
  │                             │  │    exploitation    PoC                                         │
  │                             │  │    automatable     Yes                                         │
  │                             │  │    tech impact     Total                                       │
  └─────────────────────────────┘  └─────────────────────────────────────────────────────────────────┘

  done · 2.3s                       ↑↓ navigate · tab switch · q quit
```

### Keyboard shortcuts

| Key | Action |
|---|---|
| `1`–`5` | Switch tabs |
| `↑` `↓` | Navigate findings list (tab 2) |
| `p` | View patch for selected finding |
| `s` | Suppress selected finding |
| `o` | Open finding in HTML report |
| `esc` | Cancel scan (during scanning) |
| `q` | Quit |
