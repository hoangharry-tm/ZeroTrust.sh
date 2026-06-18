#!/usr/bin/env sh
# gendoc.sh — regenerate Markdown API docs under docs/api/.
# Called by "go generate ./..." via generate.go.
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

echo "godocs/api/ updated ($(find docs/api -name '*.md' | wc -l | tr -d ' ') files)"
