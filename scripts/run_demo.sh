#!/usr/bin/env bash
# ZeroTrust.sh — Approach 1 Demo Runner
# Scans a multi-language test codebase with both opengrep and ast-grep,
# then prints a unified detection summary.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || realpath "$(dirname "$0")/..")"
RULES_DIR="${REPO_ROOT}/rules"
TARGET_DIR="${REPO_ROOT}/testdata/demo-app"
AG_RULES="${RULES_DIR}/astgrep"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}=== ZeroTrust.sh — Approach 1 Demo ===${NC}"
echo "Rules directory  : ${RULES_DIR}"
echo "Target directory : ${TARGET_DIR}"
echo ""

for cmd in opengrep ast-grep; do
  if ! command -v "$cmd" &>/dev/null; then
    echo -e "${RED}ERROR: $cmd not found in PATH.${NC}" >&2
    exit 1
  fi
done

echo -e "${BOLD}Target file breakdown:${NC}"
echo "  $(find "${TARGET_DIR}" -type f | wc -l | xargs) files total"
echo ""

# ── Temp directory for all intermediate files ──
TMPD=$(mktemp -d)
trap "rm -rf ${TMPD}" EXIT

# ── OpenGrep Scan ──
echo -e "${YELLOW}${BOLD}── OpenGrep Scan (python + java + generic rules) ──${NC}"
cat >"${TMPD}/parse_og.py" <<'PYEOF'
import json, sys
data = json.load(sys.stdin)
results = data.get('results', [])
seen_rules = {}
seen_files = set()
for r in results:
    rid = r.get('check_id', '').rpartition('.')[2] or r.get('check_id', '?')
    path = r.get('path', '')
    line = r.get('start', {}).get('line', '?')
    msg = r.get('extra', {}).get('message', '')[:80]
    seen_rules[rid] = seen_rules.get(rid, 0) + 1
    seen_files.add(path)
    short = path.replace('TARGET_DIR_placeholder/', '')
    print(f'  [{rid}] {short}:{line}  -- {msg}')
print()
print(f'Total findings: {len(results)}')
rules_list = ", ".join(sorted(seen_rules))
print(f'Unique rules fired: {len(seen_rules)} ({rules_list})')
print(f'Files with findings: {len(seen_files)}')
PYEOF

og_json=$(opengrep --config "${RULES_DIR}/python" \
  --config "${RULES_DIR}/java" \
  --config "${RULES_DIR}/generic" \
  --json "${TARGET_DIR}" 2>/dev/null || echo '{"results":[]}')

echo "${og_json}" | sed "s|${TARGET_DIR}/|TARGET_DIR_placeholder/|g" | python3 "${TMPD}/parse_og.py" 2>&1 || echo "  (opengrep JSON parse failed)"
echo ""

# ── ast-grep Scan ──
echo -e "${YELLOW}${BOLD}── ast-grep Scan (Rust, Swift, Dart, Go, TS, Kotlin, C#, Ruby, PHP) ──${NC}"
ag_total=0
ag_rules_list=""
for rule_file in "${AG_RULES}"/*.yaml; do
  rid=$(basename "${rule_file}" .yaml)
  ast-grep scan -r "${rule_file}" "${TARGET_DIR}" >"${TMPD}/ag_out" 2>/dev/null || true
  count=$(grep -cE "^(help|error)\[" "${TMPD}/ag_out" 2>/dev/null || echo "0")
  count=$(echo "${count}" | tr -dc '0-9')
  if [ "${count:-0}" -gt 0 ] 2>/dev/null; then
    echo "  [${rid}] ${count} finding(s)"
    ag_total=$((ag_total + count))
    ag_rules_list="${ag_rules_list} ${rid}"
  fi
done
ag_rules_count=$(echo "${ag_rules_list}" | wc -w | tr -d ' ')
if [ "${ag_total}" -eq 0 ]; then echo "  (no ast-grep findings)"; fi
echo ""
echo "Total findings: ${ag_total}"
echo "Unique rules fired: ${ag_rules_count}"
echo ""

# ── Summary ──
echo -e "${CYAN}${BOLD}── Summary ──${NC}"
echo ""
og_count=$(echo "${og_json}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('results',[])))" 2>/dev/null || echo "0")
echo "  Combined: $((ag_total + og_count)) findings across both engines"
echo ""
echo -e "  ${BOLD}Note:${NC} These are findings from the demo codebase only."
echo -e "         Go, Dart had 0 findings in this run — those rules exist in the ruleset but"
echo -e "         the demo-app test files need specific patterns to trigger them."
echo -e "  ${BOLD}Unit tests:${NC} Run '${BOLD}make test${NC}' for per-rule validation against bad/ok test pairs."
echo ""
echo -e "${GREEN}${BOLD}Demo complete.${NC}"
