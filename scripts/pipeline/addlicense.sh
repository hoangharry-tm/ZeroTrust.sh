#!/usr/bin/env bash
# addlicense.sh — prepend Apache 2.0 license header to all .go source files.
#
# Usage:
#   ./scripts/addlicense.sh              # apply headers
#   ./scripts/addlicense.sh --dry-run    # preview changes without writing
#   ./scripts/addlicense.sh --check      # exit 1 if any file is missing a header
#
# Handles:
#   - Build constraint lines (//go:build, // +build) — preserved at top
#   - Files with existing Copyright headers — skipped
#   - testdata/, vendor/, auto-generated files — excluded

set -euo pipefail

YEAR="2026"

readonly HEADER="// Copyright ${YEAR} hoangharry-tm
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an \"AS IS\" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License."

mode="apply"
case "${1:-}" in
    --dry-run) mode="dry-run" ;;
    --check)   mode="check" ;;
esac

processed=0
skipped=0
missing=()

while IFS= read -r -d '' file; do
    if head -5 "$file" | grep -q "Copyright"; then
        skipped=$((skipped + 1))
        continue
    fi

    missing+=("$file")
    processed=$((processed + 1))

    if [[ "$mode" == "check" ]]; then
        continue
    fi

    tmp=$(mktemp)

    first=$(head -1 "$file")
    if [[ "$first" == "//go:build "* ]] || [[ "$first" == "// +build "* ]]; then
        {
            echo "$first"
            echo
            echo "$HEADER"
            echo
            tail -n +2 "$file" | awk '!found && /^$/ {next} !found {found=1} {print}'
        } > "$tmp"
    else
        {
            echo "$HEADER"
            echo
            cat "$file"
        } > "$tmp"
    fi

    if [[ "$mode" == "dry-run" ]]; then
        if ! diff -q "$file" "$tmp" > /dev/null 2>&1; then
            echo "--- $file"
            diff "$file" "$tmp" || true
            echo
        fi
    else
        cp "$tmp" "$file"
        echo "  + $file"
    fi

    rm -f "$tmp"
done < <(find . -name "*.go" -type f \
    -not -path "*/testdata/*" \
    -not -path "*/vendor/*" \
    -not -path "*_string.go" \
    -not -path "*_pb.go" \
    -not -path "*_pb.gw.go" \
    -not -path "*/.git/*" \
    -print0)

echo ""
case "$mode" in
    dry-run)
        echo "Dry run complete. $processed files need headers, $skipped already have them."
        ;;
    check)
        if [[ ${#missing[@]} -eq 0 ]]; then
            echo "OK — all files have license headers."
        else
            echo "FAIL — ${#missing[@]} files missing license headers:"
            printf '  %s\n' "${missing[@]}"
            exit 1
        fi
        ;;
    apply)
        echo "Done. $processed files updated, $skipped already have headers."
        ;;
esac
