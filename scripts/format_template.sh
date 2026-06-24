#!/usr/bin/env bash
set -euo pipefail

# Formats internal/report/template.html with prettier while preserving
# Go template expressions ({{ ... }}) that prettier's HTML parser chokes on.
#
# Strategy: replace Go template delimiters with unique HTML-safe tokens,
# run prettier, then restore the delimiters.

TEMPLATE="internal/report/template.html"
OPEN_TOKEN="__GT_OPEN__"
CLOSE_TOKEN="__GT_CLOSE__"

# Replace Go template delimiters with safe tokens
# Using | as sed delimiter to avoid escaping /
sed -i '' \
  -e "s/{{/${OPEN_TOKEN}/g" \
  -e "s/}}/${CLOSE_TOKEN}/g" \
  "$TEMPLATE"

# Run prettier on the sanitized file
npx prettier --write --parser html \
  --html-whitespace-sensitivity css \
  --print-width 120 \
  --tab-width 2 \
  --single-attribute-per-line \
  "$TEMPLATE"

# Restore Go template delimiters
sed -i '' \
  -e "s/${OPEN_TOKEN}/{{/g" \
  -e "s/${CLOSE_TOKEN}/}}/g" \
  "$TEMPLATE"

echo "✓ Formatted $TEMPLATE"
