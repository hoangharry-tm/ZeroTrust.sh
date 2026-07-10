package enrichment

import (
	"testing"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

func TestSinkNodes_Deduplicated(t *testing.T) {
	paths := []cpg.TaintPath{
		{Sink: cpg.TaintSink{Name: "executeQuery"}},
		{Sink: cpg.TaintSink{Name: "executeQuery"}},
		{Sink: cpg.TaintSink{Name: "executeQuery"}},
	}
	sinkNodes := dedupSinks(paths)
	if len(sinkNodes) != 1 {
		t.Errorf("expected 1 unique sink, got %d: %v", len(sinkNodes), sinkNodes)
	}
	if sinkNodes[0] != "executeQuery" {
		t.Errorf("expected executeQuery, got %s", sinkNodes[0])
	}
}

func TestSinkNodes_MultipleUniqueSinksPreserved(t *testing.T) {
	paths := []cpg.TaintPath{
		{Sink: cpg.TaintSink{Name: "executeQuery"}},
		{Sink: cpg.TaintSink{Name: "executeUpdate"}},
		{Sink: cpg.TaintSink{Name: "executeQuery"}},
	}
	sinkNodes := dedupSinks(paths)
	if len(sinkNodes) != 2 {
		t.Errorf("expected 2 unique sinks, got %d: %v", len(sinkNodes), sinkNodes)
	}
}

func TestFilterSinksByCallPath_DropsUnconfirmed(t *testing.T) {
	sinks := []string{"executeQuery", "writeFile"}
	callPath := []string{"results", "getString", "writeFile"}
	got := filterSinksByCallPath(sinks, callPath)
	if len(got) != 1 || got[0] != "writeFile" {
		t.Errorf("expected [writeFile], got %v", got)
	}
}

func TestFilterSinksByCallPath_FallbackOnEmptyResult(t *testing.T) {
	sinks := []string{"executeQuery"}
	callPath := []string{"results", "getString"}
	got := filterSinksByCallPath(sinks, callPath)
	if len(got) != 1 || got[0] != "executeQuery" {
		t.Errorf("fallback should return original sinks, got %v", got)
	}
}

func TestFilterSinksByCallPath_EmptyCallPath_NoFilter(t *testing.T) {
	sinks := []string{"executeQuery", "exec"}
	got := filterSinksByCallPath(sinks, []string{})
	if len(got) != 2 {
		t.Errorf("empty call path must skip filtering, got %v", got)
	}
}
