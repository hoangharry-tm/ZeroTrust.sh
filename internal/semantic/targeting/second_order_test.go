package targeting

import (
	"testing"

	cpg "github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
)

func TestDetectSecondOrder_SurfaceMetadataPopulated(t *testing.T) {
	cg := cpg.CallGraph{
		"source1":  {"storage1"},
		"storage1": {"sink1"},
		"sink1":    {},
	}

	methods := []cpg.Node{
		{ID: "source1", Type: cpg.NodeMethod, Name: "handleRequest", File: "/project/controllers/api.java", Line: 42},
		{ID: "storage1", Type: cpg.NodeMethod, Name: "loadFromDB", File: "/project/db/repository.java", Line: 100},
		{ID: "sink1", Type: cpg.NodeMethod, Name: "writeResponse", File: "/project/io/output.java", Line: 200},
	}

	fileClass := map[string]FileClass{
		"/project/controllers/api.java": {Path: "/project/controllers/api.java", Bound: BoundarySource},
		"/project/db/repository.java":   {Path: "/project/db/repository.java", Bound: BoundaryStorage},
		"/project/io/output.java":       {Path: "/project/io/output.java", Bound: BoundarySink},
	}

	sourceReachable := map[string]bool{"source1": true, "storage1": true, "sink1": true}
	backwardReachable := map[string]bool{"source1": true, "storage1": true, "sink1": true}

	surfaces := DetectSecondOrder(cg, methods, fileClass, sourceReachable, backwardReachable, "")
	if len(surfaces) == 0 {
		t.Fatal("expected at least one second-order surface")
	}
	for _, s := range surfaces {
		if s.IsSecondOrder {
			if s.File == "" {
				t.Errorf("surface %s: expected File to be populated", s.ID)
			}
			if s.FunctionName == "" {
				t.Errorf("surface %s: expected FunctionName to be populated", s.ID)
			}
			if s.Line == 0 {
				t.Errorf("surface %s: expected Line > 0", s.ID)
			}
		}
	}
}

// TestDetectSecondOrder_RelativeCPGPaths_MatchAgainstRoot is a regression
// test for a real bug: Joern CPG node File values are project-relative (the
// convention every real scan actually produces — see e.g. targeting.go's
// Run(), which joins with root before every fileClass lookup), but this
// function previously skipped any method whose File wasn't already
// absolute instead of resolving it against root. Since real File values are
// never pre-absolute, every method was silently excluded on every real
// scan — this function detected nothing in production, ever, and the only
// reason the test above passed was that its fixture used already-absolute
// paths, which never exercises the resolution path a real scan needs.
func TestDetectSecondOrder_RelativeCPGPaths_MatchAgainstRoot(t *testing.T) {
	const root = "/Users/dev/project"
	cg := cpg.CallGraph{
		"source1":  {"storage1"},
		"storage1": {"sink1"},
		"sink1":    {},
	}
	methods := []cpg.Node{
		{ID: "source1", Type: cpg.NodeMethod, Name: "handleRequest", File: "controllers/api.java", Line: 42},
		{ID: "storage1", Type: cpg.NodeMethod, Name: "loadFromDB", File: "db/repository.java", Line: 100},
		{ID: "sink1", Type: cpg.NodeMethod, Name: "writeResponse", File: "io/output.java", Line: 200},
	}
	fileClass := map[string]FileClass{
		root + "/controllers/api.java": {Path: root + "/controllers/api.java", Bound: BoundarySource},
		root + "/db/repository.java":   {Path: root + "/db/repository.java", Bound: BoundaryStorage},
		root + "/io/output.java":       {Path: root + "/io/output.java", Bound: BoundarySink},
	}
	sourceReachable := map[string]bool{"source1": true, "storage1": true, "sink1": true}
	backwardReachable := map[string]bool{"source1": true, "storage1": true, "sink1": true}

	surfaces := DetectSecondOrder(cg, methods, fileClass, sourceReachable, backwardReachable, root)
	if len(surfaces) == 0 {
		t.Fatal("expected at least one second-order surface with realistic relative CPG paths — " +
			"if this fails, the relative-to-root path resolution regressed")
	}
}
