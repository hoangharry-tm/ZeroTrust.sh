// Package scs implements the Scan Security Context Store (Path B).
//
// The store accumulates LLM inferences across all analyzed surfaces within a single
// scan run and makes them available as accumulated context for subsequent surfaces.
// This enables cross-surface vulnerability detection — the class of bug where a
// flaw is only visible when correlating two separate code locations (e.g. a missing
// auth check in one function and an IDOR-exploitable sink in another).
//
// Design reference: RepoAudit (ICML 2025) for memoization; VULSOLVER (arXiv 2025)
// and LLMxCPG (USENIX 2025) for cross-surface correlation.
//
// The store is graph-backed: nodes are surfaces and edges are CPG-neighbour
// relationships. Context retrieval uses callee-first ordering so that downstream
// inferences about callees are available when a caller surface is processed.
//
// Concurrency: the store is goroutine-safe. LLM Semantic Scan iterates surfaces
// sequentially per callee-first ordering, but the store must tolerate concurrent
// reads from the Path A LLM Verifier running in parallel.
package scs

import (
	"context"
	"sync"
)

// InferenceKind classifies what the LLM learned about a surface.
type InferenceKind string

const (
	// InferenceTaintSink marks a surface as a confirmed taint sink.
	InferenceTaintSink InferenceKind = "taint_sink"
	// InferenceAuthMissing marks a surface where an authorization check is absent.
	InferenceAuthMissing InferenceKind = "auth_missing"
	// InferenceAuthPresent marks a surface where an authorization check was confirmed.
	InferenceAuthPresent InferenceKind = "auth_present"
	// InferenceIDORCandidate marks a surface handling an untrusted resource ID.
	InferenceIDORCandidate InferenceKind = "idor_candidate"
	// InferenceLogicFlaw marks a surface with a detected business-logic anomaly.
	InferenceLogicFlaw InferenceKind = "logic_flaw"
	// InferenceSafe marks a surface the LLM classified as not vulnerable.
	InferenceSafe InferenceKind = "safe"
)

// Inference is a single piece of knowledge about a surface stored after LLM analysis.
//
// Example:
//
//	Inference{
//	    SurfaceID: "com.example.UserService.getUser",
//	    Kind:      InferenceAuthMissing,
//	    Narrative: "No ownership check before DB lookup; resource ID from request path.",
//	    Confidence: 0.87,
//	}
type Inference struct {
	// SurfaceID is the function identifier of the analysed surface (matches targeting.Surface.ID).
	SurfaceID string
	// Kind classifies what was inferred.
	Kind InferenceKind
	// Narrative is the LLM's natural-language justification (1–3 sentences).
	// It is injected verbatim as prior context when analysing CPG neighbours.
	Narrative string
	// Confidence is the LLM's self-reported confidence score (0.0–1.0).
	Confidence float64
}

// Query describes what accumulated context to retrieve for a given surface.
type Query struct {
	// SurfaceID is the surface being analysed next.
	SurfaceID string
	// NeighbourIDs are the CPG neighbour function identifiers whose inferences
	// should be included (callee-first ordering is enforced by the caller).
	NeighbourIDs []string
	// MaxResults caps the number of inferences returned to avoid prompt bloat.
	// 0 means no cap.
	MaxResults int
}

// Result is the set of prior inferences relevant to a Query.
type Result struct {
	// Inferences are ordered by descending Confidence.
	Inferences []Inference
}

// Store is the per-scan in-memory graph of accumulated LLM inferences.
// It is created once per scan run and discarded when the scan completes.
//
// Usage:
//
//	store := scs.New()
//	// After analysing each surface:
//	store.Put(ctx, inference)
//	// Before analysing the next surface:
//	result, err := store.Get(ctx, query)
type Store struct {
	mu         sync.RWMutex
	byID       map[string][]Inference  // surfaceID → inferences
	neighbours map[string][]string     // surfaceID → CPG neighbour IDs
}

// New returns an empty Store ready for use within a single scan run.
func New() *Store {
	return &Store{
		byID:       make(map[string][]Inference),
		neighbours: make(map[string][]string),
	}
}

// Put stores an inference for future context retrieval.
// Multiple inferences for the same surface are accumulated, not replaced.
func (s *Store) Put(ctx context.Context, inf Inference) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[inf.SurfaceID] = append(s.byID[inf.SurfaceID], inf)
}

// RegisterNeighbours records the CPG neighbour relationships for a surface.
// This must be called before Get so the store can resolve callee inferences.
// Neighbours are CPG-adjacent functions in either call direction.
func (s *Store) RegisterNeighbours(surfaceID string, neighbourIDs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.neighbours[surfaceID] = neighbourIDs
}

// Get retrieves accumulated inferences relevant to the given query.
// Results include inferences for the surface itself and all registered neighbours.
// Inferences are ordered by descending Confidence; MaxResults is honoured if > 0.
func (s *Store) Get(ctx context.Context, q Query) (*Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_ = q
	// implemented in G3.M3.4
	return &Result{}, nil
}

// Snapshot returns a read-only copy of all inferences for debugging and test assertions.
// The returned map is keyed by surfaceID.
func (s *Store) Snapshot() map[string][]Inference {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]Inference, len(s.byID))
	for k, v := range s.byID {
		cp := make([]Inference, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}
