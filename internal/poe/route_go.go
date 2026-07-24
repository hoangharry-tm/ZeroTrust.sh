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

// Go route resolution: covers the two most common registration shapes —
// net/http's mux.HandleFunc("/path", handlerName) (no verb; defaults to GET,
// since net/http dispatches by method inside the handler, not at
// registration) and Gin/chi/Echo's r.GET("/path", handlerName) style (verb
// encoded in the call). Same whole-file scan approach as route_js.go, for
// the same reason: registration doesn't sit next to the handler's declaration.
var goRouteRe = regexp.MustCompile(
	`\.(?:HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch)\s*\(\s*"([^"]*)"\s*,\s*(\w+)`)

// goVerbRe extracts just the verb token from a matched call, e.g. "GET" from
// "r.GET(...)" — recovered separately since goRouteRe's outer group spans the
// whole alternation.
var goVerbRe = regexp.MustCompile(`\.(HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|Patch)\s*\(`)

func goRouteFromMethodNode(projectRoot string, node cpg_engine.Node) (Route, bool) {
	slog.Debug("resolving Go route", "file", node.File, "method", node.Name)

	lines, err := readLines(absPath(projectRoot, node))
	if err != nil {
		slog.Debug("failed to read file for Go route resolution",
			"file", node.File, "error", err)
		return Route{}, false
	}
	content := strings.Join(lines, "\n")

	matches := goRouteRe.FindAllStringSubmatchIndex(content, -1)
	for _, idx := range matches {
		path := content[idx[2]:idx[3]]
		handler := content[idx[4]:idx[5]]
		if handler != node.Name {
			continue
		}
		call := content[idx[0]:idx[1]]
		verb := "GET"
		if vm := goVerbRe.FindStringSubmatch(call); vm != nil && vm[1] != "HandleFunc" && vm[1] != "Handle" {
			verb = strings.ToUpper(vm[1])
		}
		slog.Debug("Go route resolved",
			"method", node.Name, "route", verb+" "+path)
		return Route{Method: verb, Path: path}, true
	}
	slog.Debug("no matching Go route found", "method", node.Name)
	return Route{}, false
}
