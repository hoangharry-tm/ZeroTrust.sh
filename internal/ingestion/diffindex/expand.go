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

package diffindex

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
)

// ExpandWithCPG takes a ChangeSet and expands it by adding the files containing
// direct callers and callees (one hop) of every changed function in the CPG.
//
// This ensures that when a utility function changes, the analysis scope includes
// the functions that use it (callers) and the functions it calls (callees).
//
// If the CPG is unavailable or any query fails, the original ChangeSet is returned
// unchanged — expansion is best-effort and must not block the scan.
func ExpandWithCPG(ctx context.Context, cs *ChangeSet, g cpg.Graph) (*ChangeSet, error) {
	if cs == nil || len(cs.Changed) == 0 {
		return cs, nil
	}
	slog.Debug("expanding changeset with CPG one-hop neighbours", "component", "diffindex", "changed", len(cs.Changed))

	expanded := make(map[string]bool)
	for _, f := range cs.Changed {
		expanded[f] = true
	}

	for _, f := range cs.Changed {
		nodes, err := g.QueryNodesByFile(f, cpg.NodeMethod)
		if err != nil {
			continue
		}

		for _, n := range nodes {
			// Callers: functions that call this one.
			callers, err := g.GetCallers(n.ID)
			if err != nil {
				continue
			}
			for _, caller := range callers {
				if caller.File != "" && !expanded[caller.File] {
					expanded[caller.File] = true
				}
			}

			// Callees: functions this one calls.
			callees, err := g.GetCallees(n.ID)
			if err != nil {
				continue
			}
			for _, callee := range callees {
				if callee.File != "" && !expanded[callee.File] {
					expanded[callee.File] = true
				}
			}
		}
	}

	if len(expanded) == len(cs.Changed) {
		slog.Debug("CPG expansion added no new files", "component", "diffindex")
		return cs, nil
	}

	seen := make(map[string]bool, len(cs.Changed))
	result := make([]string, 0, len(expanded))
	for _, f := range cs.Changed {
		result = append(result, f)
		seen[f] = true
	}
	for f := range expanded {
		if !seen[f] {
			result = append(result, f)
		}
	}

	slog.Info("CPG expansion complete",
		"component", "diffindex",
		"original", len(cs.Changed),
		"expanded", len(result),
	)
	return &ChangeSet{
		Changed:   result,
		Removed:   cs.Removed,
		AllStates: cs.AllStates,
	}, nil
}

// ErrCPGUnavailable is returned by ExpandWithCPG when the CPG graph is nil.
var ErrCPGUnavailable = fmt.Errorf("CPG graph unavailable for expansion")
