#!/usr/bin/env sh
# gendoc.sh — regenerate Markdown API docs under godocs/api/.
# Called by "go generate ./..." via generate.go.
#
# IMPORTANT: Go API docs always go to godocs/api/, NEVER to docs/api/.
# docs/ is for human-authored content (architecture, planning, benchmarks).
# godocs/ is for generated content — committed to git for offline browsing.
#
# Output layout mirrors the import path:
#   godocs/api/pkg/cpg.md
#   godocs/api/internal/finding.md   … etc.
#
# Browse locally instead of reading these files:
#   pkgsite .   (serves at http://localhost:8080)
set -e

go run github.com/princjef/gomarkdoc/cmd/gomarkdoc \
  --output "godocs/api/{{.ImportPath}}.md" \
  ./pkg/... ./internal/...

echo "godocs/api/ updated ($(find godocs/api -name '*.md' | wc -l | tr -d ' ') files)"
