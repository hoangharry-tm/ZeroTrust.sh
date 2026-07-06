package joern

import (
	"strings"
	"testing"
)

func TestQueryMethodsPaginated_ContainsSortBySkipTake(t *testing.T) {
	q := queryMethodsPaginated(500, 500)
	if !strings.Contains(q, ".sortBy(_.id)") {
		t.Error("expected .sortBy(_.id) in paginated query")
	}
	if !strings.Contains(q, ".drop(500)") {
		t.Error("expected .drop(500) in paginated query")
	}
	if !strings.Contains(q, ".take(500)") {
		t.Error("expected .take(500) in paginated query")
	}
	if !strings.Contains(q, `s"""{"id"`) {
		t.Error("expected JSON template in paginated query")
	}
}

func TestQueryMethodsPaginated_DifferentOffsets(t *testing.T) {
	q0 := queryMethodsPaginated(0, 500)
	if !strings.Contains(q0, ".drop(0)") {
		t.Error("expected .drop(0) for first page")
	}
	q1 := queryMethodsPaginated(500, 500)
	if !strings.Contains(q1, ".drop(500)") {
		t.Error("expected .drop(500) for second page")
	}
}

func TestQueryCallsPaginated_ContainsSortBySkipTake(t *testing.T) {
	q := queryCallsPaginated(0, 200)
	if !strings.Contains(q, ".sortBy(_.id)") {
		t.Error("expected .sortBy(_.id)")
	}
	if !strings.Contains(q, ".drop(0)") {
		t.Error("expected .drop(0)")
	}
	if !strings.Contains(q, ".take(200)") {
		t.Error("expected .take(200)")
	}
	if !strings.Contains(q, `s"""{"id"`) {
		t.Error("expected JSON template")
	}
}

func TestQueryAllEdgesPaginated_SortByBeforeFlatMap(t *testing.T) {
	q := queryAllEdgesPaginated(0, 500)
	if !strings.Contains(q, ".sortBy(_.id)") {
		t.Error("expected .sortBy(_.id)")
	}
	if !strings.Contains(q, ".drop(0)") {
		t.Error("expected .drop(0)")
	}
	if !strings.Contains(q, ".take(500)") {
		t.Error("expected .take(500)")
	}
	if !strings.Contains(q, "flatMap") {
		t.Error("expected flatMap in edge query")
	}
	// sortBy must appear before flatMap in the query.
	sortIdx := strings.Index(q, ".sortBy(_.id)")
	flatIdx := strings.Index(q, "flatMap")
	if sortIdx < 0 || flatIdx < 0 || sortIdx > flatIdx {
		t.Error(".sortBy(_.id) must appear before flatMap")
	}
}

func TestQueryMethodsPaginated_OffsetsAreIntegers(t *testing.T) {
	// Verify that the skip/take values are valid Go-int-formatted values
	// (no extra whitespace, no string interpolation issues).
	q := queryMethodsPaginated(123, 456)
	if !strings.Contains(q, ".drop(123)") {
		t.Errorf("expected .drop(123), got: %s", q)
	}
	if !strings.Contains(q, ".take(456)") {
		t.Errorf("expected .take(456), got: %s", q)
	}
}

func TestQueryMethods_UnpaginatedStillValid(t *testing.T) {
	q := queryMethods()
	if strings.Contains(q, ".sortBy") {
		t.Error("unpaginated queryMethods should not have .sortBy")
	}
	if strings.Contains(q, ".skip") {
		t.Error("unpaginated queryMethods should not have .skip")
	}
}

func TestQueryAllEdges_UnpaginatedStillValid(t *testing.T) {
	q := queryAllEdges()
	if strings.Contains(q, ".sortBy") {
		t.Error("unpaginated queryAllEdges should not have .sortBy")
	}
	if strings.Contains(q, ".skip") {
		t.Error("unpaginated queryAllEdges should not have .skip")
	}
}
