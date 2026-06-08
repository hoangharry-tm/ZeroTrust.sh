# ZeroTrust.sh

> **ZeroTrust.sh** — A local, privacy-first CLI security scanner and patch engine designed to secure codebases modified by AI coding agents. Audit code offline, block prompt injections, prevent package hallucinations, and verify fixes before you commit.

---

## Why ZeroTrust.sh?

AI coding agents (Cursor, Cline, Aider, GitHub Copilot) generate and modify code faster than any human can review. This speed comes with a cost: security vulnerabilities enter your codebase at machine speed. ZeroTrust.sh treats all AI-generated code as **untrusted by default** and audits it on your local machine — no cloud, no data leakage, no latency.

## Key Features

- 🔒 **100% Local & Offline** — Your source code never leaves your machine
- 📦 **ZIP or Directory Input** — Works independent of any VCS platform (GitHub, GitLab, etc.)
- 🤖 **AI-Specific Threat Detection** — Catches package hallucinations, prompt injection in comments, and AI-driven security bypasses
- ⚡ **Hybrid Analysis Engine** — Fast AST rule-based scanning + local LLM semantic verification
- 📊 **Interactive HTML Report** — Self-contained vulnerability dashboard with severity levels
- 🩹 **Patch Suggestions** — Generates unified Git diffs for confirmed vulnerabilities

## Threat Vectors Detected

| Threat | Description |
| :--- | :--- |
| **Package Hallucinations** | AI agents reference non-existent packages that attackers register with malicious payloads |
| **Prompt Injection** | Adversarial instructions hidden in comments or markdown that hijack AI agents |
| **Security Control Bypass** | Agents commenting out lint rules, disabling tests, or opening `0.0.0.0` ports |
| **Classic Vulnerabilities** | SQLi, XSS, SSRF, command injection, hardcoded secrets, broken access controls |

## Quick Start

```bash
# Install (coming soon)
brew install zerotrust

# Scan a directory
zerotrust scan ./my-project

# Scan a ZIP archive
zerotrust scan ./my-project.zip

# Output an HTML report
zerotrust scan ./my-project --output report.html
```

## How It Works

```
Codebase / ZIP
      │
      ▼
┌─────────────────────┐
│  Stage 1: AST Scan  │  ← Tree-sitter fast structural rules (high recall)
└─────────────────────┘
      │ Hotspots
      ▼
┌─────────────────────────────┐
│  Stage 2: Local LLM Verify  │  ← Quantized local model (Ollama / llama.cpp)
└─────────────────────────────┘
      │ Confirmed Findings + Patches
      ▼
┌──────────────────────┐
│  HTML Report Output  │  ← Interactive vulnerability dashboard
└──────────────────────┘
```

## License

Apache 2.0 — Free for individuals and open-source projects.

---

*ZeroTrust.sh — Because you shouldn't blindly trust code you didn't write.*
