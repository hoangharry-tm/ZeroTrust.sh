// Package joern wraps the Joern CPG engine HTTP API (Apache 2.0).
// Joern is pre-started at CLI launch (localhost:8080) to eliminate JVM cold-start
// latency. It builds the Universal Code Property Graph and serves taint queries;
// the CPG is shared with the semantic detection path (pkg/cpg.Graph interface).
package joern

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

const defaultServerURL = "http://localhost:8080"

// Client wraps the Joern HTTP server API.
type Client struct {
	serverURL string
}

// New returns a Client targeting the Joern server at serverURL.
// If serverURL is empty, localhost:8080 is used.
func New(serverURL string) *Client {
	if serverURL == "" {
		serverURL = defaultServerURL
	}
	return &Client{serverURL: serverURL}
}

// BuildCPG requests Joern to build a Code Property Graph from the given source paths.
func (c *Client) BuildCPG(ctx context.Context, paths []string) error {
	// implemented in G2.M2.3
	return nil
}

// Graph returns a cpg.Graph backed by this Joern server instance.
// The returned graph is safe to share across both detection paths.
func (c *Client) Graph() cpg.Graph {
	return &joernGraph{client: c}
}

// joernGraph implements cpg.Graph via Joern HTTP queries.
type joernGraph struct {
	client *Client
}

func (g *joernGraph) QueryNodes(nodeType cpg.NodeType) ([]cpg.Node, error) { return nil, nil }
func (g *joernGraph) QueryEdges(fromID, toID string) ([]cpg.Edge, error)   { return nil, nil }
func (g *joernGraph) GetCallGraph() (cpg.CallGraph, error)                 { return nil, nil }
func (g *joernGraph) GetCallers(functionID string) ([]cpg.Node, error)     { return nil, nil }
func (g *joernGraph) GetCallees(functionID string) ([]cpg.Node, error)     { return nil, nil }
