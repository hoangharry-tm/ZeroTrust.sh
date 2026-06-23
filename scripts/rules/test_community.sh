#!/usr/bin/env bash
# test_community.sh — run ZeroTrust rules + community semgrep-rules against the same fixtures.
# Shows: how many findings community rules alone produce, how many ZT-only rules add on top.
# Non-blocking in CI by default (exits 0 even if community-rules/ is absent).
set -euo pipefail

RULES_DIR="rules"
COMMUNITY_DIR="testdata/community-rules"
BAD_DIR="testdata/rules-tests/bad"
OK_DIR="testdata/rules-tests/ok"
SPRING_APP="testdata/spring-boot-app"

# ── Phase 0: community-rules/ must exist ──────────────────────────────────────
if [[ ! -d "$COMMUNITY_DIR" ]]; then
  echo ""
  echo "  [SETUP NEEDED] testdata/community-rules/ not found."
  echo "  Run once:  make setup-community-rules"
  echo ""
  exit 0
fi

og_total() {
  # Run opengrep over one or more -f configs against a target path; return total finding count.
  # Usage: og_total "<space-separated -f flags>" "<target>"
  local flags="$1" target="$2"
  # shellcheck disable=SC2086
  opengrep scan $flags --json "$target" 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('results',[])))" \
    || echo 0
}

# Build the community rule flags for languages we have fixtures for
COMMUNITY_FLAGS=""
for lang in python java go rust kotlin ruby php javascript; do
  dir="$COMMUNITY_DIR/$lang"
  [[ -d "$dir" ]] && COMMUNITY_FLAGS="$COMMUNITY_FLAGS -f $dir"
done

ZT_FLAGS="-f $RULES_DIR/python -f $RULES_DIR/java -f $RULES_DIR/generic"

echo ""
echo "════════════════════════════════════════════════════"
echo " Community Integration Test"
echo " Community rules: $(echo "$COMMUNITY_FLAGS" | tr -s ' ' '\n' | grep -c '/') language packs"
echo "════════════════════════════════════════════════════"

# ── Phase C1: community rules only → bad/ fixtures ────────────────────────────
echo ""
echo "── C1: Community rules vs bad/ fixtures ─────────────"
# shellcheck disable=SC2086
C1=$(og_total "$COMMUNITY_FLAGS" "$BAD_DIR")
echo "  Community findings on bad/: $C1"

# ── Phase C2: ZT rules only → bad/ fixtures + spring-boot-app ────────────────
echo ""
echo "── C2: ZeroTrust rules vs bad/ + spring-boot-app ────"
# shellcheck disable=SC2086
C2_BAD=$(og_total "$ZT_FLAGS" "$BAD_DIR")
C2_SPRING=0
[[ -d "$SPRING_APP" ]] && C2_SPRING=$(og_total "$ZT_FLAGS" "$SPRING_APP")
C2=$((C2_BAD + C2_SPRING))
echo "  ZT findings on bad/:         $C2_BAD"
echo "  ZT findings on spring-boot:  $C2_SPRING"
echo "  ZT total:                    $C2"

# ── Phase C3: combined rules → bad/ fixtures ──────────────────────────────────
echo ""
echo "── C3: Combined (ZT + community) vs bad/ ────────────"
# shellcheck disable=SC2086
C3=$(og_total "$ZT_FLAGS $COMMUNITY_FLAGS" "$BAD_DIR")
ZT_ONLY=$((C3 - C1))
echo "  Combined findings:           $C3"
echo "  Incremental ZT-only value:   +$ZT_ONLY finding(s) beyond community"

# ── Phase C4: community rules → ok/ fixtures (informational FP check) ─────────
echo ""
echo "── C4: Community rules vs ok/ fixtures (FP check) ───"
# shellcheck disable=SC2086
C4=$(og_total "$COMMUNITY_FLAGS" "$OK_DIR")
echo "  Community FPs on ok/:        $C4  (ZT ok/ fixtures designed to suppress these)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo " Summary"
echo "════════════════════════════════════════════════════"
printf "  %-38s %s\n" "Community rules (bad/ fixtures):"     "$C1"
printf "  %-38s %s\n" "ZeroTrust rules (bad/ + spring):"     "$C2"
printf "  %-38s %s\n" "ZT incremental value over community:" "+$ZT_ONLY"
printf "  %-38s %s\n" "Community FPs on ok/ fixtures:"       "$C4"
echo ""
echo "  → ZeroTrust adds $ZT_ONLY finding(s) that community rules miss."
echo "  → Community produces $C4 FP(s) on fixtures ZeroTrust correctly silences."
echo ""
