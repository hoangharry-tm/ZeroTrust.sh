package targeting

import (
	"path/filepath"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// DetectSecondOrder finds surfaces where taint flows through a storage boundary.
// It identifies methods that both receive external input and write to storage,
// then traces data flows that read from storage back to sinks.
//
// Reference: second-order injection pattern per OWASP Testing Guide v4.2.
func DetectSecondOrder(
	cg cpg.CallGraph,
	methods []cpg.Node,
	fileClass map[string]FileClass,
	sourceReachable map[string]bool,
	backwardReachable map[string]bool,
) []Surface {
	// Collect storage-boundary methods: methods in files marked BoundaryStorage.
	storageMethodIDs := make(map[string]bool)
	for _, m := range methods {
		absFile := m.File
		// Normalize to absolute if needed (match Run()'s logic).
		if !filepath.IsAbs(absFile) {
			// Caller should pass absolute paths; if not, this method is skipped.
			continue
		}
		fc, ok := fileClass[absFile]
		if !ok || fc.Bound&BoundaryStorage == 0 {
			continue
		}
		storageMethodIDs[m.ID] = true
	}

	if len(storageMethodIDs) == 0 {
		return nil // No storage boundaries detected.
	}

	// Collect storage method IDs as seeds.
	var storageSeeds []string
	for id := range storageMethodIDs {
		storageSeeds = append(storageSeeds, id)
	}

	// Forward BFS from storage: all methods that call into storage.
	storageReachable := bfsForward(cg, storageSeeds)

	// Intersection: methods receiving external input AND writing to storage.
	// These are first-order storage-write entry points.
	storageWriters := make(map[string]bool)
	for id := range sourceReachable {
		if storageReachable[id] {
			storageWriters[id] = true
		}
	}

	// Reverse BFS from storage: methods that read from storage.
	reverseCG := buildReverseCG(cg)
	storageReaders := bfsForward(reverseCG, storageSeeds)

	// Second-order surfaces: readers that also reach sinks.
	out := make([]Surface, 0, len(storageReaders))
	seen := make(map[string]bool)

	for id := range storageReaders {
		if seen[id] || !backwardReachable[id] {
			continue
		}
		seen[id] = true
		out = append(out, Surface{
			ID:            id,
			Kind:          SurfaceExternalInput,
			IsSecondOrder: true,
		})
	}

	return out
}
