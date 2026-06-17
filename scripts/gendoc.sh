#!/usr/bin/env sh
# gendoc.sh — regenerate Markdown API docs under docs/api/.
# Called by "go generate ./..." via generate.go.
#
# Output layout mirrors the import path:
#   docs/api/pkg/cpg.md
#   docs/api/internal/finding.md   … etc.
#
# Browse locally instead of reading these files:
#   pkgsite .   (serves at http://localhost:8080)
set -e

go run github.com/princjef/gomarkdoc/cmd/gomarkdoc \
  --output 'docs/api/{{.ImportPath}}.md' \
  ./pkg/... ./internal/...

echo "docs/api/ updated ($(find docs/api -name '*.md' | wc -l | tr -d ' ') files)"
