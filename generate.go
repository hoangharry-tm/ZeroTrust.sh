// Copyright 2026 hoangharry-tm
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

// Package zerotrust is the module root. It holds module-wide go:generate directives.
//
// Run "go generate ./..." from the repository root to regenerate all outputs.
//
// Browse the API reference locally with pkgsite:
//
//	pkgsite .
package zerotrust

// Regenerate Markdown API reference docs under godocs/api/.
// IMPORTANT: generated docs always go to godocs/api/, never docs/api/.
// gomarkdoc reads Go doc comments and writes one .md file per package.
// The version used is the one pinned in go.mod via tools.go.
//
//go:generate sh scripts/gendoc.sh
