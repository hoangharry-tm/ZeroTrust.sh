//go:build tools

// Copyright 2026 Minh Hoang Ton
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
