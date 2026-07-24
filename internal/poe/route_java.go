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

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
)

// Java/Spring route resolution: mapping annotations sit directly above the
// method declaration; a class-level @RequestMapping supplies a path prefix.

var (
	// javaClassMappingRe matches a class-level @RequestMapping("/prefix") or
	// @RequestMapping(value = "/prefix", ...). Only the first path literal is used.
	javaClassMappingRe = regexp.MustCompile(`@RequestMapping\s*\(\s*(?:value\s*=\s*)?"([^"]*)"`)

	// javaMethodMappingRe matches @GetMapping/@PostMapping/@PutMapping/@DeleteMapping/
	// @PatchMapping/@RequestMapping annotations with an optional path literal, e.g.
	// @GetMapping("/{id}") or @RequestMapping(method = RequestMethod.POST, value = "/x").
	javaMethodMappingRe = regexp.MustCompile(
		`@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(([^)]*)\)`)
	javaPathLiteralRe   = regexp.MustCompile(`"([^"]*)"`)
	javaRequestMethodRe = regexp.MustCompile(`RequestMethod\.(GET|POST|PUT|DELETE|PATCH)`)

	// javaClassDeclRe finds a top-level class/interface declaration line, used
	// to scope the nearest-preceding class-level @RequestMapping to that class.
	javaClassDeclRe = regexp.MustCompile(`\b(?:class|interface)\s+\w+`)
)

// javaRouteFromMethodNode inspects the raw source around node's declaration
// line for a Spring mapping annotation and, if found, the enclosing class's
// @RequestMapping prefix.
func javaRouteFromMethodNode(projectRoot string, node cpg_engine.Node) (Route, bool) {
	slog.Debug("resolving Java route", "file", node.File, "method", node.Name)

	lines, err := readLines(absPath(projectRoot, node))
	if err != nil {
		slog.Debug("failed to read file for Java route resolution",
			"file", node.File, "error", err)
		return Route{}, false
	}

	window := windowAbove(lines, node.Line, 4)

	m := javaMethodMappingRe.FindStringSubmatch(window)
	if m == nil {
		slog.Debug("no Spring mapping annotation found", "method", node.Name)
		return Route{}, false
	}

	method := javaMappingVerb(m[1], m[2])
	path := javaFirstPathLiteral(m[2])
	if prefix, ok := javaClassPrefix(lines, node.Line); ok {
		slog.Debug("found class-level prefix", "prefix", prefix)
		path = joinPath(prefix, path)
	}
	if path == "" {
		path = "/"
	}
	slog.Debug("Java route resolved",
		"method", node.Name, "route", method+" "+path)
	return Route{Method: method, Path: path}, true
}

// javaMappingVerb maps a Spring mapping annotation name to an HTTP method.
func javaMappingVerb(annotation, args string) string {
	switch annotation {
	case "Get":
		return "GET"
	case "Post":
		return "POST"
	case "Put":
		return "PUT"
	case "Delete":
		return "DELETE"
	case "Patch":
		return "PATCH"
	default: // "Request" — method comes from RequestMethod.X, default GET
		if rm := javaRequestMethodRe.FindStringSubmatch(args); rm != nil {
			return rm[1]
		}
		return "GET"
	}
}

// javaFirstPathLiteral extracts the first quoted string from an annotation's
// argument list — the path, whether written as a bare literal or `value = "..."`.
func javaFirstPathLiteral(args string) string {
	if m := javaPathLiteralRe.FindStringSubmatch(args); m != nil {
		return m[1]
	}
	return ""
}

// javaClassPrefix looks backward from methodLine for the nearest class-level
// @RequestMapping that precedes the class declaration containing methodLine.
func javaClassPrefix(lines []string, methodLine int) (string, bool) {
	classLine := -1
	for i := methodLine - 1; i >= 0 && i < len(lines); i-- {
		if javaClassDeclRe.MatchString(lines[i]) {
			classLine = i
			break
		}
	}
	if classLine == -1 {
		slog.Debug("no enclosing class declaration found")
		return "", false
	}
	window := windowAbove(lines, classLine+1, 5)
	if m := javaClassMappingRe.FindStringSubmatch(window); m != nil {
		return m[1], true
	}
	return "", false
}
