package targeting

import (
	"testing"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
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

	surfaces := DetectSecondOrder(cg, methods, fileClass, sourceReachable, backwardReachable)
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
