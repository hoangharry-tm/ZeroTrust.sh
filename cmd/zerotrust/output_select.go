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

package main

import (
	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/output/web"
)

// selectRenderer returns the Renderer for the given --output flag value.
//
// Rules:
//   - "minimal"     → MinimalRenderer (always, CI-safe plain text)
//   - "web"         → WebRenderer (always, live HTML dashboard)
//   - "" (auto)     → WebRenderer when stdout is a TTY; MinimalRenderer otherwise
//   - anything else → MinimalRenderer (safe fallback)
func selectRenderer(mode string) output.Renderer {
	switch mode {
	case "minimal":
		return output.NewMinimalRenderer()
	case "web":
		return web.NewRenderer()
	default:
		if output.IsTTY() {
			return web.NewRenderer()
		}
		return output.NewMinimalRenderer()
	}
}
