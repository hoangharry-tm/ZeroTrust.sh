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

// Python route resolution: Flask (@app.route("/path", methods=["POST"])) and
// FastAPI (@app.get("/path")) decorators sit directly above the function
// definition — same shape as Java annotations, different syntax. Django's
// urls.py-based routing is a distinct convention and not covered here.

var (
	// pythonFlaskRouteRe matches Flask's @app.route("/path"[, methods=[...]]).
	pythonFlaskRouteRe = regexp.MustCompile(
		`@\w+\.route\s*\(\s*["']([^"']*)["'](?:.*methods\s*=\s*\[([^\]]*)\])?`)

	// pythonFastAPIRouteRe matches FastAPI's @app.get("/path") / @router.post("/path") / etc.
	pythonFastAPIRouteRe = regexp.MustCompile(
		`@\w+\.(get|post|put|delete|patch)\s*\(\s*["']([^"']*)["']`)

	pythonMethodLiteralRe = regexp.MustCompile(`["'](GET|POST|PUT|DELETE|PATCH)["']`)
)

// pythonRouteFromMethodNode inspects the source immediately above node's
// declaration line for a Flask or FastAPI route decorator.
func pythonRouteFromMethodNode(projectRoot string, node cpg_engine.Node) (Route, bool) {
	slog.Debug("resolving Python route", "file", node.File, "method", node.Name)

	lines, err := readLines(absPath(projectRoot, node))
	if err != nil {
		slog.Debug("failed to read file for Python route resolution",
			"file", node.File, "error", err)
		return Route{}, false
	}
	window := windowAbove(lines, node.Line, 4)

	if m := pythonFastAPIRouteRe.FindStringSubmatch(window); m != nil {
		path := m[2]
		if path == "" {
			path = "/"
		}
		slog.Debug("Python FastAPI route resolved",
			"method", node.Name, "route", strings.ToUpper(m[1])+" "+path)
		return Route{Method: strings.ToUpper(m[1]), Path: path}, true
	}

	if m := pythonFlaskRouteRe.FindStringSubmatch(window); m != nil {
		path := m[1]
		if path == "" {
			path = "/"
		}
		method := "GET"
		if len(m) > 2 && m[2] != "" {
			if mm := pythonMethodLiteralRe.FindStringSubmatch(m[2]); mm != nil {
				method = mm[1]
			}
		}
		slog.Debug("Python Flask route resolved",
			"method", node.Name, "route", method+" "+path)
		return Route{Method: method, Path: path}, true
	}

	slog.Debug("no matching Python route found", "method", node.Name)
	return Route{}, false
}
