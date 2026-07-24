# CLI Output Design

Two output paths. The terminal always shows plain-text progress (MinimalRenderer);
the self-contained HTML report is written to disk via the `--report` flag.

| Mode          | Flag               | Use case                            |
|---------------|--------------------|-------------------------------------|
| Minimal       | `--output minimal` | CI/CD pipelines, servers, scripting |
| HTML report   | `--report <path>`  | Local dev, interactive review       |

The `--output web` mode (SSE live dashboard) has been removed. The HTML report
is now a static file generated at the end of the scan — no HTTP server, no
Server-Sent Events, no browser overlay.

---

## Minimal mode (`MinimalRenderer`)

Plain-text stdout. ANSI colours on TTY; stripped on pipe/redirect (CI-safe).

```
zerotrust v0.1.0

» ingestion
  model   qwen2.5-3b · verified
  diff    4 files changed

» findings
  BLOCK  CWE-89  UserController.java:42  sql-injection-jdbc

5 findings  (1 BLOCK · 2 HIGH · 1 MEDIUM)  6.8s
report → build/report.html
```

Exit codes:
- `0` — no BLOCK or HIGH findings
- `1` — one or more BLOCK/HIGH findings (CI gate)
- `2` — scan error (tool failure, pipeline error)

---

## What was removed

The WebRenderer (SSE live dashboard) and its dependencies have been removed:
- `internal/output/web/` — entire package (hub, client management, `/events` endpoint)
- SSE event types (`stage`, `finding`, `summary`) — no longer broadcast to browser
- Client-side `EventSource` — JavaScript `ScanDialog`, pipeline graph, glassmorphism overlay
- `--output web` flag — only `--output minimal` is valid
- `--web-port` flag — no HTTP server to configure
- `ScanInProgress` template state — report is always rendered as a complete static file

The MinimalRenderer remains the sole terminal renderer. HTML output is produced
via `--report <path>` (default: `build/report.html`).

---

## What was removed (history)

The three-renderer stack (MinimalRenderer/TreeRenderer/TUIRenderer) and the standalone
`preview/main.go` Bubble Tea demo were previously replaced by:
- `WebRenderer` — the interactive path (now removed)
- `MinimalRenderer` — the CI/pipe path (still active)

`charmbracelet/bubbletea` and `charmbracelet/bubbles` are no longer dependencies.
`charmbracelet/lipgloss` is unused in the codebase now too — Docker orchestration (and
its dependency error box) was removed from the binary entirely — but it lingers as an
unpruned entry in `go.mod`.
