# CLI Output Design

Two output modes. The default on a TTY opens a **live HTML dashboard** in the browser;
the minimal mode is for CI pipelines, pipes, and file redirection.

| Mode          | Flag               | Auto-selected when            | Use case                            |
|---------------|--------------------|-------------------------------|-------------------------------------|
| Web (default) | `--output web`     | TTY detected                  | Local dev, interactive terminal     |
| Minimal       | `--output minimal` | no TTY (pipe / redirect / CI) | CI/CD pipelines, servers, scripting |

---

## Mode selection

```go
switch outputFlag {
case "minimal":
    return output.NewMinimalRenderer()
case "web":
    return web.NewRenderer()
default:
    if output.IsTTY() {
        return web.NewRenderer()  // TTY → live HTML dashboard
    }
    return output.NewMinimalRenderer() // no TTY → plain text
}
```

---

## Web mode (`WebRenderer`)

Starts a local HTTP server on a random free port. Prints the URL to stdout and waits for
the scan to complete.

```
  open → http://localhost:54321
```

The browser connects to `/events` (SSE). The Go server fans pipeline events as named
SSE events (`stage`, `finding`, `log`, `summary`). The browser inserts HTML fragments
directly via the native `EventSource` API — no external framework, fully offline.

**Architecture:**

```
pipeline → output.Event → WebRenderer → SSE hub → browser
                                    ↓
                              /events  (SSE)
                              /        (index.html)
                              /report  (proxied HTML report)
```

The dashboard (`internal/output/web/ui/index.html`) is embedded in the Go binary via
`//go:embed`. It has three live panels:

- **Scan Progress** — stage blocks + detail lines as the pipeline advances
- **Findings** — finding cards with severity filter chips and expandable detail rows
- **Live Logs** — structured log rows with level, component chip, and key=val attrs

The server shuts down 30 seconds after `EventDone` (or immediately on context cancel),
giving the user time to read the final state before the process exits.

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

The three-renderer stack (MinimalRenderer/TreeRenderer/TUIRenderer) and the standalone
`preview/main.go` Bubble Tea demo have been replaced by:
- `WebRenderer` — the interactive path
- `MinimalRenderer` — the CI/pipe path

`charmbracelet/bubbletea` and `charmbracelet/bubbles` are no longer dependencies.
`charmbracelet/lipgloss` is retained for the Docker dependency error box in `deps.go`.
