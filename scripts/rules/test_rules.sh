#!/usr/bin/env bash
# test_rules.sh — run opengrep + ast-grep rules against bad/ and ok/ fixtures.
# Exit 1 if any rule misses a TP or produces a FP.
set -euo pipefail

RULES_DIR="rules"
BAD_DIR="testdata/rules-tests/bad"
OK_DIR="testdata/rules-tests/ok"

PASS=0; FAIL=0; SKIP=0
FAILED_CASES=()

log_pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
log_fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); FAILED_CASES+=("$1"); }
log_skip() { echo "  [SKIP] $1 — $2"; SKIP=$((SKIP+1)); }

# ── opengrep: run one rule file against one fixture, return finding count ─────
og_count() {
  local rule="$1" file="$2"
  opengrep scan --config "$rule" --json "$file" 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('results',[])))"
}

# ── ast-grep: run one rule file against one fixture, return finding count ─────
ag_count() {
  local rule="$1" file="$2"
  # ast-grep exits 1 when findings exist; outputs empty string when none
  local out
  out=$({ ast-grep scan --rule "$rule" --json "$file" 2>/dev/null || true; })
  [[ -z "$out" ]] && echo 0 && return
  echo "$out" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d))"
}

# ── validate all opengrep rules first ─────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo " Phase 0 — Validate rule syntax"
echo "════════════════════════════════════════════"
INVALID=0
for rule in "$RULES_DIR"/python/*.yaml "$RULES_DIR"/java/*.yaml "$RULES_DIR"/generic/*.yaml; do
  [[ "$(basename "$rule")" == "README.md" ]] && continue
  out=$(opengrep scan --validate --config "$rule" 2>&1)
  if echo "$out" | grep -q "^.*\[.*ERROR.*\]"; then
    echo "  [INVALID] $rule"
    echo "$out" | grep "ERROR\|invalid" | head -3 | sed 's/^/    /'
    ((INVALID++))
  fi
done
if [[ $INVALID -gt 0 ]]; then
  echo ""
  echo "  $INVALID rule file(s) invalid — fix before running tests."
  exit 1
fi
echo "  All opengrep rule files valid."

# ── opengrep: python rules ─────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo " Phase 1 — OpenGrep: Python rules"
echo "════════════════════════════════════════════"
for rule in "$RULES_DIR"/python/*.yaml; do
  id=$(basename "$rule" .yaml)
  prefix=$(echo "$id" | grep -oE '^[A-Z]+-[0-9]+')

  # TP check: at least one bad/ file for this rule must fire
  bad_files=( "$BAD_DIR"/${prefix}-*.py )
  if [[ ! -e "${bad_files[0]}" ]]; then
    log_skip "$id / TP" "no bad/ fixture"
  else
    total=0
    for f in "${bad_files[@]}"; do
      n=$(og_count "$rule" "$f")
      total=$((total + n))
    done
    if [[ $total -gt 0 ]]; then
      log_pass "$id → $total finding(s) on bad/ (${#bad_files[@]} file(s))"
    else
      log_fail "$id → 0 findings on bad/ (${#bad_files[@]} file(s))"
    fi
  fi

  # FP check: no ok/ file for this rule must fire
  ok_files=( "$OK_DIR"/${prefix}-*.py )
  if [[ -e "${ok_files[0]}" ]]; then
    fps=0
    for f in "${ok_files[@]}"; do
      n=$(og_count "$rule" "$f")
      fps=$((fps + n))
    done
    if [[ $fps -eq 0 ]]; then
      log_pass "$id → 0 FP(s) on ok/ (${#ok_files[@]} file(s))"
    else
      log_fail "$id → $fps FP(s) on ok/"
    fi
  fi
done

# ── opengrep: java rules ───────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo " Phase 2 — OpenGrep: Java rules"
echo "════════════════════════════════════════════"
for rule in "$RULES_DIR"/java/*.yaml; do
  id=$(basename "$rule" .yaml)
  prefix=$(echo "$id" | grep -oE '^[A-Z]+-[0-9]+')

  bad_files=( "$BAD_DIR"/${prefix}-*.java )
  if [[ ! -e "${bad_files[0]}" ]]; then
    log_skip "$id / TP" "no bad/ fixture"
  else
    total=0
    for f in "${bad_files[@]}"; do
      n=$(og_count "$rule" "$f")
      total=$((total + n))
    done
    if [[ $total -gt 0 ]]; then
      log_pass "$id → $total finding(s) on bad/ (${#bad_files[@]} file(s))"
    else
      log_fail "$id → 0 findings on bad/ (${#bad_files[@]} file(s))"
    fi
  fi

  ok_files=( "$OK_DIR"/${prefix}-*.java )
  if [[ -e "${ok_files[0]}" ]]; then
    fps=0
    for f in "${ok_files[@]}"; do
      n=$(og_count "$rule" "$f")
      fps=$((fps + n))
    done
    if [[ $fps -eq 0 ]]; then
      log_pass "$id → 0 FP(s) on ok/ (${#ok_files[@]} file(s))"
    else
      log_fail "$id → $fps FP(s) on ok/"
    fi
  fi
done

# ── opengrep: generic rules ────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo " Phase 3 — OpenGrep: Generic rules"
echo "════════════════════════════════════════════"
for rule in "$RULES_DIR"/generic/*.yaml; do
  id=$(basename "$rule" .yaml)
  prefix=$(echo "$id" | grep -oE '^[A-Z]+-[0-9]+')

  # Generic rules use multiple file types; glob broadly
  bad_files=( "$BAD_DIR"/${prefix}-* )
  bad_files=( $(printf '%s\n' "${bad_files[@]}" | grep -v '/$' | grep -v '^\.' | sort) )
  if [[ ! -e "${bad_files[0]}" ]]; then
    log_skip "$id / TP" "no bad/ fixture"
  else
    total=0
    for f in "${bad_files[@]}"; do
      [[ -f "$f" ]] || continue
      n=$(og_count "$rule" "$f")
      total=$((total + n))
    done
    if [[ $total -gt 0 ]]; then
      log_pass "$id → $total finding(s) on bad/ (${#bad_files[@]} file(s))"
    else
      log_fail "$id → 0 findings on bad/ (${#bad_files[@]} file(s))"
    fi
  fi

  ok_files=( "$OK_DIR"/${prefix}-* )
  ok_files=( $(printf '%s\n' "${ok_files[@]}" | grep -v '/$' | grep -v '^\.' | sort) )
  if [[ -e "${ok_files[0]}" ]]; then
    fps=0
    for f in "${ok_files[@]}"; do
      [[ -f "$f" ]] || continue
      n=$(og_count "$rule" "$f")
      fps=$((fps + n))
    done
    if [[ $fps -eq 0 ]]; then
      log_pass "$id → 0 FP(s) on ok/ (${#ok_files[@]} file(s))"
    else
      log_fail "$id → $fps FP(s) on ok/"
    fi
  fi
done

# ── ast-grep rules ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo " Phase 4 — ast-grep rules"
echo "════════════════════════════════════════════"
for rule in "$RULES_DIR"/astgrep/*.yaml; do
  id=$(basename "$rule" .yaml)
  prefix=$(echo "$id" | grep -oE '^[A-Z]+-[0-9]+')

  bad_files=( "$BAD_DIR"/${prefix}-* )
  bad_files=( $(printf '%s\n' "${bad_files[@]}" | grep -v '/$' | grep -v '^\.' | sort) )
  if [[ ! -e "${bad_files[0]}" ]]; then
    log_skip "$id / TP" "no bad/ fixture"
  else
    total=0
    for f in "${bad_files[@]}"; do
      [[ -f "$f" ]] || continue
      n=$(ag_count "$rule" "$f")
      total=$((total + n))
    done
    if [[ $total -gt 0 ]]; then
      log_pass "$id → $total finding(s) on bad/ (${#bad_files[@]} file(s))"
    else
      log_fail "$id → 0 findings on bad/ (${#bad_files[@]} file(s)) [check KNOWN LIMITATIONS in FINE_TUNING_LOG.md]"
    fi
  fi

  ok_files=( "$OK_DIR"/${prefix}-* )
  ok_files=( $(printf '%s\n' "${ok_files[@]}" | grep -v '/$' | grep -v '^\.' | sort) )
  if [[ -e "${ok_files[0]}" ]]; then
    fps=0
    for f in "${ok_files[@]}"; do
      [[ -f "$f" ]] || continue
      n=$(ag_count "$rule" "$f")
      fps=$((fps + n))
    done
    if [[ $fps -eq 0 ]]; then
      log_pass "$id → 0 FP(s) on ok/ (${#ok_files[@]} file(s))"
    else
      log_fail "$id → $fps FP(s) on ok/"
    fi
  fi
done

# ── summary ────────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo " Summary"
echo "════════════════════════════════════════════"
echo "  PASS: $PASS   FAIL: $FAIL   SKIP: $SKIP"
if [[ $FAIL -gt 0 ]]; then
  echo ""
  echo "  Failed cases:"
  for c in "${FAILED_CASES[@]}"; do echo "    • $c"; done
  echo ""
  exit 1
fi
echo ""
echo "  All rule tests passed."
