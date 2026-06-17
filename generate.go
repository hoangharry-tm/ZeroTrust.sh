// Package zerotrust is the module root. It holds module-wide go:generate directives.
//
// Run "go generate ./..." from the repository root to regenerate all outputs.
//
// Browse the API reference locally with pkgsite:
//
//	pkgsite .
package zerotrust

// Regenerate Markdown API reference docs under docs/api/.
// gomarkdoc reads Go doc comments and writes one .md file per package.
// The version used is the one pinned in go.mod via tools.go.
//
//go:generate sh scripts/gendoc.sh
