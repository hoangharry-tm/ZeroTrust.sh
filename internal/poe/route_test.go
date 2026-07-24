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
	"path/filepath"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// fakeGraph is a minimal cpg_engine.Graph stub. Only QueryNodesByFile and
// GetCallers are exercised by route.go; the rest panic if ever called so a
// test relying on unstubbed behaviour fails loudly instead of silently.
type fakeGraph struct {
	nodesByFile map[string][]cpg_engine.Node
	callers     map[string][]cpg_engine.Node
}

func (g *fakeGraph) QueryNodes(cpg_engine.NodeType) ([]cpg_engine.Node, error) { panic("unused") }
func (g *fakeGraph) QueryNodesByFile(relPath string, _ cpg_engine.NodeType) ([]cpg_engine.Node, error) {
	return g.nodesByFile[relPath], nil
}
func (g *fakeGraph) QueryEdges(string, string) ([]cpg_engine.Edge, error) { panic("unused") }
func (g *fakeGraph) GetCallGraph() (cpg_engine.CallGraph, error)          { panic("unused") }
func (g *fakeGraph) GetCallers(functionID string) ([]cpg_engine.Node, error) {
	return g.callers[functionID], nil
}
func (g *fakeGraph) GetCallees(string) ([]cpg_engine.Node, error) { panic("unused") }
func (g *fakeGraph) GetNeighboursAtDepth(string, int) ([]cpg_engine.Node, error) {
	panic("unused")
}
func (g *fakeGraph) TaintPaths([]cpg_engine.TaintSource, []cpg_engine.TaintSink) ([]cpg_engine.TaintPath, error) {
	panic("unused")
}
func (g *fakeGraph) ProjectWideTaintPaths([]string, string) ([]cpg_engine.TaintPath, error) {
	panic("unused")
}
func (g *fakeGraph) PreFlaggedSinks() ([]cpg_engine.TaintSink, error) { panic("unused") }

func TestResolveRoute_DirectlyAnnotatedMethod(t *testing.T) {
	root := t.TempDir()
	src := `package com.example;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping("/{id}")
    public User getUser(@PathVariable String id) {
        return repo.find(id);
    }
}
`
	writeSourceFile(t, root, "UserController.java", src)

	graph := &fakeGraph{
		nodesByFile: map[string][]cpg_engine.Node{
			"UserController.java": {
				{ID: "m1", File: "UserController.java", Line: 8, Name: "getUser"},
			},
		},
	}
	f := finding.Finding{Path: "UserController.java", LineRange: finding.LineRange{Start: 9, End: 9}}

	route, ok := resolveRoute(graph, root, f)
	if !ok {
		t.Fatal("resolveRoute() = false, want true")
	}
	if route.Method != "GET" || route.Path != "/api/users/{id}" {
		t.Fatalf("resolveRoute() = %+v, want GET /api/users/{id}", route)
	}
}

func TestResolveRoute_WalksCallerChain(t *testing.T) {
	root := t.TempDir()
	controllerSrc := `package com.example;

@RestController
public class OrderController {

    @PostMapping("/orders")
    public void createOrder(@RequestBody Order o) {
        service.process(o);
    }
}
`
	serviceSrc := `package com.example;

public class OrderService {

    public void process(Order o) {
        repo.save(o);
    }
}
`
	writeSourceFile(t, root, "OrderController.java", controllerSrc)
	writeSourceFile(t, root, "OrderService.java", serviceSrc)

	graph := &fakeGraph{
		nodesByFile: map[string][]cpg_engine.Node{
			// The finding sits in OrderService.process — no annotation there.
			"OrderService.java": {
				{ID: "svc1", File: "OrderService.java", Line: 5, Name: "process"},
			},
		},
		callers: map[string][]cpg_engine.Node{
			"svc1": {
				{ID: "ctrl1", File: "OrderController.java", Line: 7, Name: "createOrder"},
			},
		},
	}
	f := finding.Finding{Path: "OrderService.java", LineRange: finding.LineRange{Start: 6, End: 6}}

	route, ok := resolveRoute(graph, root, f)
	if !ok {
		t.Fatal("resolveRoute() = false, want true (should walk up to the controller)")
	}
	if route.Method != "POST" || route.Path != "/orders" {
		t.Fatalf("resolveRoute() = %+v, want POST /orders", route)
	}
}

func TestResolveRoute_NoEntryPointFound(t *testing.T) {
	root := t.TempDir()
	src := `package com.example;

public class Unrelated {
    public void doThing() {}
}
`
	writeSourceFile(t, root, "Unrelated.java", src)

	graph := &fakeGraph{
		nodesByFile: map[string][]cpg_engine.Node{
			"Unrelated.java": {{ID: "u1", File: "Unrelated.java", Line: 4, Name: "doThing"}},
		},
	}
	f := finding.Finding{Path: "Unrelated.java", LineRange: finding.LineRange{Start: 4, End: 4}}

	if _, ok := resolveRoute(graph, root, f); ok {
		t.Fatal("resolveRoute() = true, want false for an unreachable/unannotated method")
	}
}

func TestJavaMappingVerb(t *testing.T) {
	cases := []struct {
		annotation, args, want string
	}{
		{"Get", "", "GET"},
		{"Post", `"/x"`, "POST"},
		{"Request", `method = RequestMethod.PUT, value = "/x"`, "PUT"},
		{"Request", `"/x"`, "GET"}, // no RequestMethod given -> default GET
	}
	for _, c := range cases {
		if got := javaMappingVerb(c.annotation, c.args); got != c.want {
			t.Errorf("javaMappingVerb(%q, %q) = %q, want %q", c.annotation, c.args, got, c.want)
		}
	}
}

func TestPythonRouteFromMethodNode_FastAPI(t *testing.T) {
	root := t.TempDir()
	src := `from fastapi import FastAPI
app = FastAPI()

@app.get("/users/{id}")
def get_user(id: str):
    return db.find(id)
`
	writeSourceFile(t, root, "app.py", src)
	node := cpg_engine.Node{File: "app.py", Line: 5, Name: "get_user"}

	route, ok := pythonRouteFromMethodNode(root, node)
	if !ok {
		t.Fatal("pythonRouteFromMethodNode() = false, want true")
	}
	if route.Method != "GET" || route.Path != "/users/{id}" {
		t.Fatalf("pythonRouteFromMethodNode() = %+v, want GET /users/{id}", route)
	}
}

func TestPythonRouteFromMethodNode_FlaskWithMethods(t *testing.T) {
	root := t.TempDir()
	src := `from flask import Flask
app = Flask(__name__)

@app.route("/orders", methods=["POST"])
def create_order():
    return db.save(request.json)
`
	writeSourceFile(t, root, "app.py", src)
	node := cpg_engine.Node{File: "app.py", Line: 5, Name: "create_order"}

	route, ok := pythonRouteFromMethodNode(root, node)
	if !ok {
		t.Fatal("pythonRouteFromMethodNode() = false, want true")
	}
	if route.Method != "POST" || route.Path != "/orders" {
		t.Fatalf("pythonRouteFromMethodNode() = %+v, want POST /orders", route)
	}
}

func TestJSRouteFromMethodNode_Express(t *testing.T) {
	root := t.TempDir()
	src := `const express = require('express');
const app = express();

function getUser(req, res) {
    res.json(db.find(req.params.id));
}

app.get('/users/:id', getUser);
`
	writeSourceFile(t, root, "server.js", src)
	node := cpg_engine.Node{File: "server.js", Line: 3, Name: "getUser"}

	route, ok := jsRouteFromMethodNode(root, node)
	if !ok {
		t.Fatal("jsRouteFromMethodNode() = false, want true")
	}
	if route.Method != "GET" || route.Path != "/users/:id" {
		t.Fatalf("jsRouteFromMethodNode() = %+v, want GET /users/:id", route)
	}
}

func TestGoRouteFromMethodNode_NetHTTP(t *testing.T) {
	root := t.TempDir()
	src := `package main

func getUser(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(db.Find(r.URL.Query().Get("id")))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/users", getUser)
}
`
	writeSourceFile(t, root, "main.go", src)
	node := cpg_engine.Node{File: "main.go", Line: 3, Name: "getUser"}

	route, ok := goRouteFromMethodNode(root, node)
	if !ok {
		t.Fatal("goRouteFromMethodNode() = false, want true")
	}
	if route.Method != "GET" || route.Path != "/users" {
		t.Fatalf("goRouteFromMethodNode() = %+v, want GET /users", route)
	}
}

func TestGoRouteFromMethodNode_GinVerb(t *testing.T) {
	root := t.TempDir()
	src := `package main

func createOrder(c *gin.Context) {
	db.Save(c)
}

func main() {
	r := gin.Default()
	r.POST("/orders", createOrder)
}
`
	writeSourceFile(t, root, "main.go", src)
	node := cpg_engine.Node{File: "main.go", Line: 3, Name: "createOrder"}

	route, ok := goRouteFromMethodNode(root, node)
	if !ok {
		t.Fatal("goRouteFromMethodNode() = false, want true")
	}
	if route.Method != "POST" || route.Path != "/orders" {
		t.Fatalf("goRouteFromMethodNode() = %+v, want POST /orders", route)
	}
}

func TestJoinPath(t *testing.T) {
	cases := []struct{ prefix, path, want string }{
		{"/api/users", "/{id}", "/api/users/{id}"},
		{"/api/users/", "{id}", "/api/users/{id}"},
		{"/api", "", "/api"},
	}
	for _, c := range cases {
		if got := joinPath(c.prefix, c.path); got != c.want {
			t.Errorf("joinPath(%q, %q) = %q, want %q", c.prefix, c.path, got, c.want)
		}
	}
}

func writeSourceFile(t *testing.T, root, relPath, content string) {
	t.Helper()
	mustWrite(t, filepath.Join(root, relPath), content)
}
