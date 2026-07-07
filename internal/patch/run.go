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

package patch

import (
	"context"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// GenerateForFindings runs patch generation for the given findings and
// returns the findings slice with Patch and PatchStatus fields populated.
// It is intentionally separate from the scan pipeline — call it after
// Run() returns if patch suggestions are wanted.
func GenerateForFindings(ctx context.Context, projectRoot string, findings []finding.Finding) ([]finding.Finding, error) {
	if len(findings) == 0 {
		return findings, nil
	}

	g := New(projectRoot)
	patches, err := g.Generate(ctx, findings)
	if err != nil {
		return nil, err
	}

	patchByID := make(map[string]Patch, len(patches))
	for _, pp := range patches {
		patchByID[pp.FindingID] = pp
	}

	for i := range findings {
		if pp, ok := patchByID[findings[i].ID]; ok {
			findings[i].Patch = pp.UnifiedDiff
			findings[i].PatchStatus = string(pp.Status)
		}
	}

	return findings, nil
}
