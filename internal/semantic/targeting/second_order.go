package targeting

import (
	"log/slog"
	"path/filepath"

	cpg "github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
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
	root string,
) []Surface {
	slog.Debug("detecting second-order injection surfaces",
		"total_methods", len(methods), "file_class_entries", len(fileClass))

	storageMethodIDs := make(map[string]bool)
	for _, m := range methods {
		// CPG node File values are project-relative (Joern's convention) — must
		// join with root before matching fileClass's absolute-path keys, the
		// same resolution targeting.go's Run() already does. Skipping instead
		// of resolving here meant every method was silently excluded on every
		// real scan (real File values are never already absolute), so this
		// function has never actually detected anything in production — only
		// the unit tests, which use pre-made absolute-path fixtures, exercised
		// the "match" branch at all.
		absFile := m.File
		if !filepath.IsAbs(absFile) {
			absFile = filepath.Join(root, m.File)
		}
		fc, ok := fileClass[absFile]
		if !ok || fc.Bound&BoundaryStorage == 0 {
			continue
		}
		storageMethodIDs[m.ID] = true
	}

	if len(storageMethodIDs) == 0 {
		slog.Debug("no storage boundary methods found, skipping second-order detection")
		return nil
	}
	slog.Debug("storage boundary methods found", "count", len(storageMethodIDs))

	var storageSeeds []string
	for id := range storageMethodIDs {
		storageSeeds = append(storageSeeds, id)
	}

	storageReachable := bfsForward(cg, storageSeeds)
	slog.Debug("forward BFS from storage completed",
		"storage_seeds", len(storageSeeds), "reachable", len(storageReachable))

	storageWriters := make(map[string]bool)
	for id := range sourceReachable {
		if storageReachable[id] {
			storageWriters[id] = true
		}
	}
	slog.Debug("storage writers identified", "count", len(storageWriters))

	reverseCG := buildReverseCG(cg)
	storageReaders := bfsForward(reverseCG, storageSeeds)
	slog.Debug("reverse BFS from storage completed",
		"storage_seeds", len(storageSeeds), "readers", len(storageReaders))

	nodeByID := make(map[string]cpg.Node, len(methods))
	for _, m := range methods {
		nodeByID[m.ID] = m
	}

	out := make([]Surface, 0, len(storageReaders))
	seen := make(map[string]bool)

	for id := range storageReaders {
		if seen[id] || !backwardReachable[id] {
			continue
		}
		seen[id] = true
		n := nodeByID[id]
		out = append(out, Surface{
			ID:            id,
			File:          n.File,
			FunctionName:  n.Name,
			Line:          n.Line,
			NodeType:      cpg.NodeMethod,
			Kind:          SurfaceExternalInput,
			IsSecondOrder: true,
		})
	}

	slog.Debug("second-order detection completed", "surfaces_found", len(out))
	return out
}
