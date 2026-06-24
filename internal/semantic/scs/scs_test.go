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

package scs

import (
	"context"
	"testing"
)

func inf(surfaceID string, kind InferenceKind, conf float64) Inference {
	return Inference{SurfaceID: surfaceID, Kind: kind, Narrative: "test", Confidence: conf}
}

func TestGet_Empty(t *testing.T) {
	s := New()
	r, err := s.Get(context.Background(), Query{SurfaceID: "fn"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Inferences) != 0 {
		t.Errorf("want 0 inferences, got %d", len(r.Inferences))
	}
}

func TestGet_SurfaceInferences(t *testing.T) {
	s := New()
	s.Put(context.Background(), inf("fn", InferenceTaintSink, 0.9))
	s.Put(context.Background(), inf("fn", InferenceAuthMissing, 0.7))

	r, err := s.Get(context.Background(), Query{SurfaceID: "fn"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Inferences) != 2 {
		t.Fatalf("want 2 inferences, got %d", len(r.Inferences))
	}
	// descending confidence order
	if r.Inferences[0].Confidence < r.Inferences[1].Confidence {
		t.Errorf("inferences not sorted descending: %v %v", r.Inferences[0].Confidence, r.Inferences[1].Confidence)
	}
}

func TestGet_IncludesQueryNeighbours(t *testing.T) {
	s := New()
	s.Put(context.Background(), inf("caller", InferenceTaintSink, 0.85))
	s.Put(context.Background(), inf("callee", InferenceAuthMissing, 0.60))

	r, err := s.Get(context.Background(), Query{
		SurfaceID:    "surface",
		NeighbourIDs: []string{"caller", "callee"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Inferences) != 2 {
		t.Fatalf("want 2 inferences from neighbours, got %d", len(r.Inferences))
	}
	if r.Inferences[0].SurfaceID != "caller" {
		t.Errorf("highest-confidence first: want 'caller', got %q", r.Inferences[0].SurfaceID)
	}
}

func TestGet_UsesRegisteredNeighboursWhenQueryEmpty(t *testing.T) {
	s := New()
	s.RegisterNeighbours("surface", []string{"callee"})
	s.Put(context.Background(), inf("callee", InferenceIDORCandidate, 0.75))

	r, err := s.Get(context.Background(), Query{SurfaceID: "surface"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Inferences) != 1 {
		t.Fatalf("want 1 inference from registered neighbour, got %d", len(r.Inferences))
	}
	if r.Inferences[0].Kind != InferenceIDORCandidate {
		t.Errorf("want InferenceIDORCandidate, got %q", r.Inferences[0].Kind)
	}
}

func TestGet_MaxResultsCap(t *testing.T) {
	s := New()
	for i := range 5 {
		s.Put(context.Background(), inf("fn", InferenceTaintSink, float64(i)*0.1+0.5))
	}

	r, err := s.Get(context.Background(), Query{SurfaceID: "fn", MaxResults: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Inferences) != 3 {
		t.Errorf("want 3 (MaxResults cap), got %d", len(r.Inferences))
	}
	// must be the 3 highest-confidence ones
	if r.Inferences[0].Confidence < r.Inferences[2].Confidence {
		t.Error("not sorted descending after cap")
	}
}

func TestGet_SurfacePlusNeighboursCombined(t *testing.T) {
	s := New()
	s.Put(context.Background(), inf("fn", InferenceTaintSink, 0.80))
	s.Put(context.Background(), inf("callee", InferenceAuthMissing, 0.90))

	r, err := s.Get(context.Background(), Query{
		SurfaceID:    "fn",
		NeighbourIDs: []string{"callee"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Inferences) != 2 {
		t.Fatalf("want 2 (surface + neighbour), got %d", len(r.Inferences))
	}
	// callee (0.90) must come before fn (0.80)
	if r.Inferences[0].SurfaceID != "callee" {
		t.Errorf("want callee first (higher confidence), got %q", r.Inferences[0].SurfaceID)
	}
}

func TestPut_Accumulates(t *testing.T) {
	s := New()
	s.Put(context.Background(), inf("fn", InferenceTaintSink, 0.8))
	s.Put(context.Background(), inf("fn", InferenceAuthMissing, 0.6))

	snap := s.Snapshot()
	if len(snap["fn"]) != 2 {
		t.Errorf("want 2 accumulated inferences, got %d", len(snap["fn"]))
	}
}

func TestSnapshot_IsACopy(t *testing.T) {
	s := New()
	s.Put(context.Background(), inf("fn", InferenceSafe, 0.9))
	snap := s.Snapshot()
	// mutating the snapshot must not affect the store
	snap["fn"][0].Confidence = 0.0
	r, _ := s.Get(context.Background(), Query{SurfaceID: "fn"})
	if r.Inferences[0].Confidence == 0.0 {
		t.Error("Snapshot returned a reference, not a copy")
	}
}
