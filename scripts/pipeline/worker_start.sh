#!/usr/bin/env bash
# Starts the Python ML worker in isolation for local testing.
# In production the Go orchestrator spawns this directly via os/exec.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
WORKER_DIR="${REPO_ROOT}/worker"

cd "${WORKER_DIR}"
export PYTHONPATH="${WORKER_DIR}"

exec uv run python main.py
