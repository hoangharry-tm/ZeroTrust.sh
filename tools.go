//go:build tools

// Package zerotrust pins development tool dependencies so "go mod tidy" and
// "go mod download" keep them in go.sum. None of these are imported at runtime.
//
// Install all tools at once:
//
//	go generate -run tools ./...
//
// Or install individually:
//
//	go install golang.org/x/pkgsite/cmd/pkgsite@latest   # browse docs locally
//	go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest  # generate Markdown docs
package zerotrust

import (
	_ "github.com/princjef/gomarkdoc/cmd/gomarkdoc"
	_ "golang.org/x/pkgsite/cmd/pkgsite"
)
