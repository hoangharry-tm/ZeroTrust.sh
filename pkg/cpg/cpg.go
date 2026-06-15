// Package cpg defines the shared Code Property Graph interface consumed by both
// the pattern and semantic detection paths. The Joern engine (internal/pattern/joern)
// is the sole implementor; both paths read from the same graph without re-parsing.
package cpg

// NodeType classifies a CPG vertex by its structural role.
type NodeType string

const (
	NodeMethod     NodeType = "METHOD"
	NodeCall       NodeType = "CALL"
	NodeIdentifier NodeType = "IDENTIFIER"
	NodeParameter  NodeType = "PARAMETER"
	NodeLiteral    NodeType = "LITERAL"
	NodeReturn     NodeType = "RETURN"
)

// Node is a single vertex in the Code Property Graph.
type Node struct {
	ID       string
	Type     NodeType
	Name     string
	File     string
	Line     int
	Language string
}

// Edge is a directed relationship between two CPG nodes.
type Edge struct {
	FromID string
	ToID   string
	Type   string // e.g. "CALL", "CFG", "PDG", "AST"
}

// CallGraph maps each function identifier to the identifiers of functions it calls.
type CallGraph map[string][]string

// Graph is the read interface shared by both detection paths.
type Graph interface {
	// QueryNodes returns all nodes of the given type.
	QueryNodes(nodeType NodeType) ([]Node, error)

	// QueryEdges returns edges between fromID and toID; pass "" to match any.
	QueryEdges(fromID, toID string) ([]Edge, error)

	// GetCallGraph returns the full inter-procedural call graph.
	GetCallGraph() (CallGraph, error)

	// GetCallers returns all functions that directly call functionID.
	GetCallers(functionID string) ([]Node, error)

	// GetCallees returns all functions directly called by functionID.
	GetCallees(functionID string) ([]Node, error)
}
