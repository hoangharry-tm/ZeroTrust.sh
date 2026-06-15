#!/usr/bin/env bash
# Approach 1 demo runner — OpenGrep scan of the fake Spring Boot test codebase.
# Pins the OpenGrep version to ensure reproducibility at the tech lead presentation.
set -euo pipefail

OPENGREP_VERSION="1.86.0"
RULES_DIR="$(git rev-parse --show-toplevel)/rules"
TARGET_DIR="$(git rev-parse --show-toplevel)/testdata/spring-boot-app"

echo "=== ZeroTrust.sh — Approach 1 Demo ==="
echo "OpenGrep version : ${OPENGREP_VERSION}"
echo "Rules directory  : ${RULES_DIR}"
echo "Target directory : ${TARGET_DIR}"
echo ""

if ! command -v opengrep &>/dev/null; then
  echo "ERROR: opengrep not found in PATH. Install from https://github.com/opengrep/opengrep" >&2
  exit 1
fi

actual_version=$(opengrep --version 2>&1 | head -1)
echo "Installed: ${actual_version}"
echo ""

opengrep --config "${RULES_DIR}" --json "${TARGET_DIR}" | python3 -m json.tool
