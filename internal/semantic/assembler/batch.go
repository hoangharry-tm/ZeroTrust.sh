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

package assembler

import "github.com/hoangharry-tm/zerotrust/internal/tuning"

// BatchSize is the maximum number of surfaces per LLM prompt batch.
// Amortises model-load and context-window overhead; matches the summarizer's
// Python worker batch size.
const BatchSize = tuning.AssemblerBatchSize

// Batch splits contexts into groups of at most BatchSize for batch inference.
// Each group becomes one prompt payload sent to the Python worker. The last
// group may be smaller than BatchSize.
//
// The input slice is not copied — each sub-slice shares the backing array.
// Callers must not modify contexts concurrently with the returned batches.
func Batch(contexts []CallChainContext) [][]CallChainContext {
	if len(contexts) == 0 {
		return nil
	}
	batches := make([][]CallChainContext, 0, (len(contexts)+BatchSize-1)/BatchSize)
	for len(contexts) > 0 {
		n := min(BatchSize, len(contexts))
		batches = append(batches, contexts[:n])
		contexts = contexts[n:]
	}
	return batches
}
