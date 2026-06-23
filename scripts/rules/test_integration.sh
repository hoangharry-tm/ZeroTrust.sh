#!/usr/bin/env bash
# test_integration.sh — combined ZeroTrust + community rules integration test.
#
# Phases:
#   C0 — verify community-rules/ exists (optional; skip if absent)
#   C1 — community rules only vs. bad/ + spring-boot-app
#   C2 — ZT rules only vs. bad/ + spring-boot-app
#   C3 — combined (ZT + community) vs. bad/ + spring-boot-app
#   C4 — community rules vs. ok/ (FP rate; informational only)
#
# Prerequisites (one-time):
#   make setup-community-rules
set -euo pipefail

COMMUNITY_DIR="testdata/community-rules"
RULES_DIR="rules"
BAD_DIR="testdata/rules-tests/bad"
OK_DIR="testdata/rules-tests/ok"
SPRING_BOOT_DIR="testdata/spring-boot-app"
TOTAL_BAD=$(find "$BAD_DIR" -type f 2>/dev/null | wc -l)

# ── helpers ────────────────────────────────────────────────────────────────────

og_scan() {
  local config="$1" target="$2"
  opengrep scan --config "$config" --json "$target" 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('results',[])))"
}

section() {
  echo ""
  echo "════════════════════════════════════════════"
  echo " $1"
  echo "════════════════════════════════════════════"
}

# ── Phase C0 — setup check ────────────────────────────────────────────────────

section "Phase C0 — Community rules setup check"

if [[ ! -d "$COMMUNITY_DIR" ]]; then
  echo ""
  echo "  Community rules not found at $COMMUNITY_DIR."
  echo "  To enable integration test, run:"
  echo "    make setup-community-rules"
  echo ""
  echo "  Exiting 0 — this is non-blocking by default."
  exit 0
fi

echo "  Community rules found at $COMMUNITY_DIR"

# Build language-specific config paths.
LANG_PACKS=()
for lang in python java go rust kotlin ruby php javascript; do
  p="$COMMUNITY_DIR/$lang"
  [[ -d "$p" ]] && LANG_PACKS+=("$p")
done
COMMUNITY_CONFIG=$(IFS=,; echo "${LANG_PACKS[*]}")

# ── Phase C1 — community only vs. bad/ ─────────────────────────────────────────

section "Phase C1 — Community rules only vs. bad/ fixtures"

C1_BAD=0
for f in "$BAD_DIR"/*; do
  [[ -f "$f" ]] || continue
  n=$(og_scan "$COMMUNITY_CONFIG" "$f")
  C1_BAD=$((C1_BAD + n))
done

C1_SPRING=0
if [[ -d "$SPRING_BOOT_DIR" ]]; then
  C1_SPRING=$(og_scan "$COMMUNITY_CONFIG" "$SPRING_BOOT_DIR")
fi

echo "  Community findings on bad/ ($TOTAL_BAD fixtures): $C1_BAD"
echo "  Community findings on spring-boot-app:            $C1_SPRING"

# ── Phase C2 — ZT only vs. bad/ + spring-boot ──────────────────────────────────

section "Phase C2 — ZeroTrust rules only vs. bad/ + spring-boot"

ZT_CONFIG="$RULES_DIR"
C2_BAD=0
for f in "$BAD_DIR"/*; do
  [[ -f "$f" ]] || continue
  n=$(og_scan "$ZT_CONFIG" "$f")
  C2_BAD=$((C2_BAD + n))
done

C2_SPRING=0
if [[ -d "$SPRING_BOOT_DIR" ]]; then
  C2_SPRING=$(og_scan "$ZT_CONFIG" "$SPRING_BOOT_DIR")
fi

echo "  ZT findings on bad/ ($TOTAL_BAD fixtures): $C2_BAD"
echo "  ZT findings on spring-boot-app:            $C2_SPRING"

# ── Phase C3 — combined vs. bad/ + spring-boot ─────────────────────────────────

section "Phase C3 — Combined (ZT + community) vs. bad/ + spring-boot"

COMBINED_CONFIG="$RULES_DIR,$COMMUNITY_CONFIG"
C3_BAD=0
for f in "$BAD_DIR"/*; do
  [[ -f "$f" ]] || continue
  n=$(og_scan "$COMBINED_CONFIG" "$f")
  C3_BAD=$((C3_BAD + n))
done

C3_SPRING=0
if [[ -d "$SPRING_BOOT_DIR" ]]; then
  C3_SPRING=$(og_scan "$COMBINED_CONFIG" "$SPRING_BOOT_DIR")
fi

ZT_ONLY=$((C3_BAD - C1_BAD))
echo "  Combined findings on bad/ ($TOTAL_BAD fixtures): $C3_BAD"
echo "  Combined findings on spring-boot-app:            $C3_SPRING"
echo "  Incremental ZT-only findings (combined - community): $ZT_ONLY"

# ── Phase C4 — community FP rate on ok/ ────────────────────────────────────────

section "Phase C4 — Community rules vs. ok/ fixtures (FP check)"

C4_FP=0
OK_COUNT=0
for f in "$OK_DIR"/*; do
  [[ -f "$f" ]] || continue
  OK_COUNT=$((OK_COUNT + 1))
  n=$(og_scan "$COMMUNITY_CONFIG" "$f")
  C4_FP=$((C4_FP + n))
done

echo "  Community FPs on ok/ ($OK_COUNT fixtures): $C4_FP"
if [[ $C4_FP -gt 0 ]]; then
  echo "  ⚠  Community rules produce FPs on ZeroTrust's clean fixtures."
  echo "     This is informational — not blocking."
fi

# ── Summary ────────────────────────────────────────────────────────────────────

section "Summary"

printf "  %-30s %8s\n" "Metric" "Findings"
printf "  %-30s %8s\n" "──────────────────────────────" "────────"
printf "  %-30s %8d\n" "Community (C1)" "$C1_BAD"
printf "  %-30s %8d\n" "ZeroTrust only (C2)" "$C2_BAD"
printf "  %-30s %8d\n" "Combined (C3)" "$C3_BAD"
printf "  %-30s %8d\n" "Incremental ZT value" "$ZT_ONLY"
printf "  %-30s %8d\n" "Community FPs on ok/" "$C4_FP"
echo ""
echo "  Combined detection is the 'comparative value' number for demos."
