# ZeroTrust.sh — Deployment Architecture

## Overview

ZeroTrust.sh uses a **single binary with two execution modes**. By default, the binary orchestrates a Docker image that contains all heavy dependencies (Joern, Python ML worker, OpenGrep, ast-grep). The `--native` flag runs the pipeline directly using locally installed toolchains.

```
┌─────────────────────────────────────────────────────────────────┐
│                      Developer Machine                          │
│                                                                 │
│   ┌─────────────────────────────────────────────────────┐       │
│   │              zerotrust binary (cmd/zerotrust)       │       │
│   │                                                     │       │
│   │   ┌─ Default: ──────────────────────────────────┐   │       │
│   │   │  docker run --rm -v $PWD:/workspace:ro ...  │   │       │
│   │   │  → forwards signals, streams output         │   │       │
│   │   └─────────────────────┬───────────────────────┘   │       │
│   │                         ▼                           │       │
│   │   ┌────────────────────────────────────────┐        │       │
│   │   │         Docker Container               │        │       │
│   │   │  ┌────────┐ ┌──────────┐ ┌──────────┐ │        │       │
│   │   │  │  Go    │ │  Joern   │ │  Python  │ │        │       │
│   │   │  │ Engine │ │ CPG HTTP │ │  Worker  │ │        │       │
│   │   │  └────────┘ └──────────┘ └──────────┘ │        │       │
│   │   │  ┌──────────────┐ ┌──────────────┐    │        │       │
│   │   │  │   OpenGrep   │ │   ast-grep   │    │        │       │
│   │   │  └──────────────┘ └──────────────┘    │        │       │
│   │   └────────────────────────────────────────┘        │       │
│   │                                                     │       │
│   │   ┌─ --native: ───────────────────────────────┐     │       │
│   │   │  runs pipeline directly using              │     │       │
│   │   │  local Joern, OpenGrep, ast-grep deps     │     │       │
│   │   └───────────────────────────────────────────┘     │       │
│   │                                                     │       │
│   │   ┌──────────────────────────────────────────┐      │       │
│   │   │   Ollama (on host, GPU-accelerated)      │      │       │
│   │   │   http://localhost:11434                  │◀─────│──────│── host.docker.internal:11434
│   │   └──────────────────────────────────────────┘      │       │
│   └─────────────────────────────────────────────────────┘       │
│                                                                  │
│  Volumes (Docker mode):                                          │
│    /Users/me/project   →  /workspace:ro                         │
│    ~/.zerotrust         →  /home/zt/.zerotrust                  │
└─────────────────────────────────────────────────────────────────┘
```

## Component Layout

| Component | Docker mode | Native mode |
|---|---|---|
| **zerotrust binary** | Host — orchestrates `docker run` | Host — runs pipeline directly |
| **Go engine** | In container | On host (same binary) |
| **Joern CPG** | In container (`127.0.0.1:8080`) | On host (spawned or pre-running) |
| **Python worker** | In container (NDJSON IPC) | On host (subprocess) |
| **OpenGrep / ast-grep** | In container (subprocess) | On host (subprocess) |
| **Ollama** | Host — `host.docker.internal:11434` | Host — `localhost:11434` |

## Network Isolation (Docker mode)

- **No host port exposure.** All container-internal services communicate over Docker's bridge network or stdin/stdout IPC.
- **One-way host access.** Container connects to host Ollama via `host.docker.internal:11434`. Host never initiates connections into the container.
- **Signal forwarding.** `docker run --init` propagates SIGINT/SIGTERM.
- **Air-gapped mode.** `--offline` disables network access inside the container.

## GPU Passthrough

The binary detects Ollama on the host (`GET http://localhost:11434`, 2s timeout):
- **Reachable:** sets `OLLAMA_URL=http://host.docker.internal:11434` and adds `--add-host host.docker.internal:host-gateway`
- **Unreachable:** container's entrypoint falls back to CPU-only llama-cpp-python

## State Persistence

Docker mode mounts two volumes:

| Host path | Container path | Purpose |
|---|---|---|
| `<project>` (read-only) | `/workspace` | Target codebase |
| `~/.zerotrust` | `/home/zt/.zerotrust` | SQLite state cache, serialized CPGs, HTML reports |

State is shared between Docker and native modes — the same `~/.zerotrust` directory is used for both.

## Native Mode

For development iteration and environments where Docker is unavailable:

```bash
# Install all dependencies natively
brew install joern opengrep ast-grep
pip install -e worker/[dev]

# Run scan with local toolchains
zerotrust --native ./project

# Or start Joern externally and point the engine at it
joern --server --server-host 127.0.0.1 --server-port 8080
zerotrust --native --joern-bin /opt/homebrew/bin/joern ./project
```

Native mode avoids the container overhead and JVM cold-start on each scan (useful when iterating).

## Container Image

- **Registry:** `ghcr.io/hoangharry-tm/zerotrust-engine:latest`
- **Size:** ~500 MB (multi-stage build: JRE + Joern + Python deps + Go binary + rule files)
- **Tags:** `latest`, `vX.Y.Z` (semver releases)
- **Build:** CI-triggered on merge to main; manual via `make docker-build`

## Development Workflow

```bash
# Build the binary
make build

# Run with Docker (default)
./build/zerotrust ~/my-project

# Run natively (faster iteration)
go run ./cmd/zerotrust --native --joern-bin /opt/homebrew/bin/joern ./testdata/demo-app

# Build and push the engine image
make docker-build
make docker-push
```
