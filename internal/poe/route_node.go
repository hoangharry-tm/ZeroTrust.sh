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

package poe

import (
	"log/slog"
	"regexp"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
)

// JS/TS (Express) route resolution: unlike Java/Python, a route registration
// call — app.get('/path', handlerName) — sits wherever the router is wired
// up, not necessarily next to the handler's own declaration. So this scans
// the whole file for a registration call whose handler argument matches
// node's function name, rather than a fixed window above the node's line.
//
// ponytail: same-file only — a router file that imports and registers a
// handler defined elsewhere won't resolve. Real Express apps sometimes split
// these; accepted as an MVP limitation, not solved here.
var jsRouteRe = regexp.MustCompile(
	`(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*["']([^"']*)["']\s*,\s*(\w+)`)

func jsRouteFromMethodNode(projectRoot string, node cpg_engine.Node) (Route, bool) {
	slog.Debug("resolving JS/TS route", "file", node.File, "method", node.Name)

	lines, err := readLines(absPath(projectRoot, node))
	if err != nil {
		slog.Debug("failed to read file for JS route resolution",
			"file", node.File, "error", err)
		return Route{}, false
	}
	content := strings.Join(lines, "\n")

	for _, m := range jsRouteRe.FindAllStringSubmatch(content, -1) {
		if m[3] == node.Name {
			slog.Debug("JS route resolved",
				"method", node.Name, "route", strings.ToUpper(m[1])+" "+m[2])
			return Route{Method: strings.ToUpper(m[1]), Path: m[2]}, true
		}
	}
	slog.Debug("no matching JS route found", "method", node.Name)
	return Route{}, false
}
