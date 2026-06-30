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

// Package orchestrator runs all eligible Scanner implementations concurrently
// and aggregates their findings.
//
// This is the architectural framework for the Post-MVP Option 1 "Mason-style"
// local tool binary manager. Scanners declare what stacks they support;
// the Engine detects the project stack once and dispatches only the eligible
// scanners, making it trivial to add new tools without touching the pipeline.
package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/hoangharry-tm/zerotrust/internal/detector"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/scanner"
)

// Engine dispatches a set of Scanner implementations concurrently.
type Engine struct {
	scanners []scanner.Scanner
}

// New returns an Engine that will dispatch the provided scanners.
func New(scanners ...scanner.Scanner) *Engine {
	return &Engine{scanners: scanners}
}

// Run detects the target stack, filters eligible scanners via Supports,
// dispatches them concurrently, and returns the merged findings.
// A scanner error is logged and skipped — it does not abort the run.
// ctx should carry a deadline; all spawned goroutines respect it.
func (e *Engine) Run(ctx context.Context, target string) ([]finding.Finding, error) {
	stack, err := detector.Detect(target)
	if err != nil {
		return nil, fmt.Errorf("stack detection: %w", err)
	}

	var eligible []scanner.Scanner
	for _, s := range e.scanners {
		if s.Supports(stack) {
			eligible = append(eligible, s)
		}
	}
	if len(eligible) == 0 {
		return nil, nil
	}

	var (
		mu  sync.Mutex
		all []finding.Finding
		wg  sync.WaitGroup
	)

	for _, s := range eligible {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fs, err := s.Scan(ctx, target)
			if err != nil {
				slog.WarnContext(ctx, "scanner error", "scanner", s.Name(), "err", err)
				return
			}
			mu.Lock()
			all = append(all, fs...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return all, nil
}
