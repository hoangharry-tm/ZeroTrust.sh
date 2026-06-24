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

package main

// scan.go wires the full pipeline and drives a single scan run.
//
// Pipeline execution order:
//
//  1. INGEST  — MIV + DI run in parallel (ingestion.Ingester).
//  2. PATH A  — OpenGrep + ast-grep + Joern CPG run in parallel goroutines.
//     instrscan also runs here (AI agent config file scanner, no CPG dependency).
//     LLM Verifier filters false positives from pattern findings.
//  3. PATH B  — Sequential tier pipeline:
//     Heuristic Targeting → CVE Enrichment → UniXcoder Classifier →
//     Call Chain Assembler → Semantic Summarizer → Token Budget → LLM Scan.
//     Each tier feeds directly into the next.
//     Scan Security Context Store accumulates inferences across surfaces.
//  4. DEDUP   — Merged findings from both paths de-duplicated and SSVC-scored.
//  5. PATCH   — Patch suggestions generated and validated for BLOCK/HIGH findings.
//  6. REPORT  — Self-contained HTML report written to OutputPath.
//
// Both paths run concurrently (steps 2 and 3 overlap). Path B starts as soon as
// the CPG build in Path A reports ready; it does not wait for LLM Verifier output.

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/hoangharry-tm/zerotrust/internal/dedup"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion/diffindex"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion/miv"
	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/patch"
	"github.com/hoangharry-tm/zerotrust/internal/pattern/astgrep"
	"github.com/hoangharry-tm/zerotrust/internal/pattern/instrscan"
	"github.com/hoangharry-tm/zerotrust/internal/pattern/joern"
	"github.com/hoangharry-tm/zerotrust/internal/pattern/opengrep"
	"github.com/hoangharry-tm/zerotrust/internal/pattern/verifier"
	"github.com/hoangharry-tm/zerotrust/internal/report"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/assembler"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/budget"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/classifier"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/llmscan"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/scs"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/summarizer"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/internal/worker"
	"github.com/hoangharry-tm/zerotrust/pkg/cpg"
	"github.com/hoangharry-tm/zerotrust/pkg/ollama"
	"github.com/hoangharry-tm/zerotrust/pkg/sqlite"
)

// pipeline holds all constructed stage instances for a single scan.
// It is built by newPipeline and driven by run.
type pipeline struct {
	cfg     ScanConfig
	logger  *slog.Logger
	logFile *os.File
	runID   string // unique ID for this scan run; persisted to scan_runs

	// ingestion
	db       *sqlite.DB
	ingester *ingestion.Ingester

	// Ollama client — shared by backbone check and any direct Go-side LLM calls.
	// SetMIVBlocked() is called after ingestion when MIV returns StatusBlock.
	llm *ollama.Client

	// Path A
	opengrep *opengrep.Runner
	astgrep  *astgrep.Runner
	joern    *joern.Client
	instr    *instrscan.Scanner
	verif    *verifier.Verifier

	// Path B
	target *targeting.Targeter
	enrich *enrichment.Enricher
	clf    *classifier.Gate
	asm    *assembler.Assembler
	sum    *summarizer.Summarizer
	bud    *budget.Controller
	scan   *llmscan.Scanner
	store  *scs.Store

	// shared
	w   *worker.Manager
	dd  *dedup.Layer
	gen *patch.Generator
	rep *report.Generator

}

// newPipeline constructs the full pipeline from cfg.
// It opens the SQLite state cache, starts the Python worker, and instantiates
// every stage. Returns a ready-to-run pipeline or an error on setup failure.
//
// The caller is responsible for calling pipeline.close() after run() returns.
func newPipeline(ctx context.Context, cfg ScanConfig) (*pipeline, error) {
	cfg.defaults()

	absTarget, err := filepath.Abs(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	cfg.Target = absTarget

	// Structured logger — JSON lines written to build/zerotrust.log alongside the report.
	logDir := filepath.Dir(cfg.ReportPath)
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", logDir, err)
	}
	logFile, err := os.OpenFile(filepath.Join(logDir, "zerotrust.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// SQLite state cache at ~/.zerotrust/scans.db
	dbPath, err := stateDBPath()
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}
	db, err := sqlite.Open(dbPath)
	if err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("open state db: %w", err)
	}

	// Register project and open a scan run so findings can be persisted.
	runID := newRunID()
	if upsertErr := db.UpsertProject(ctx, sqlite.ProjectRow{
		ProjectID: cfg.ProjectID,
		RootPath:  cfg.Target,
	}); upsertErr != nil {
		logger.Warn("failed to upsert project record", "component", "scan", "err", upsertErr)
	}
	if createErr := db.CreateScanRun(ctx, sqlite.ScanRunRow{
		RunID:     runID,
		ProjectID: cfg.ProjectID,
		ScanMode:  strings.ToLower(cfg.ScanMode),
	}); createErr != nil {
		logger.Warn("failed to create scan_run record", "component", "scan", "err", createErr)
	}

	// Propagate model name to Python worker handlers (llm_verify, llm_scan).
	if cfg.ModelName != "" {
		_ = os.Setenv("ZEROTRUST_MODEL", cfg.ModelName)
	}
	// Python worker — started once, shared by verifier, classifier, summarizer, llmscan.
	wm, err := worker.Start(ctx, "worker/main.py", logger)
	if err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("start python worker: %w", err)
	}

	// Ingestion layer
	indexer := diffindex.New(db, logger)
	mivVer := miv.New("", "", logger)
	ingester := ingestion.New(indexer, mivVer)

	// Ollama client — model-agnostic; model name from config.
	llmClient := ollama.New(cfg.OllamaURL, cfg.ModelName)

	// Path A
	// rules/astgrep/ uses ast-grep YAML format; opengrep rejects it. Pass only compatible dirs.
	og := opengrep.NewMulti("opengrep", logger, "rules/java/", "rules/python/", "rules/generic/")
	ag := astgrep.New("ast-grep", "rules/astgrep/")
	joernOpts := []joern.Option{joern.WithServerURL(cfg.JoernURL)}
	if cfg.JoernBin != "" {
		joernOpts = append(joernOpts, joern.WithBinaryPath(cfg.JoernBin))
	}
	jc, err := joern.New(joernOpts...)
	if err != nil {
		return nil, fmt.Errorf("configure joern: %w", err)
	}
	is := instrscan.New(logger)
	vf := verifier.New(wm, logger)

	// Path B — graph shared from Joern after CPG build
	graph := jc.GraphWithContext(ctx)
	tgt := targeting.New(graph)
	enr := enrichment.New(graph, "trivy", cfg.Offline)
	clf := classifier.New(wm, logger)
	asm := assembler.New(graph, 3)
	sum := summarizer.New(wm)
	bud := budget.New(cfg.TokenCap, 0.4, 0.4, 0.2)
	sc := llmscan.New(wm)
	store := scs.New()

	// Output
	dd := dedup.NewWithRoot(cfg.Target)
	pg := patch.New(cfg.Target)
	rg := report.New(cfg.ReportPath)

	return &pipeline{
		cfg:      cfg,
		logger:   logger,
		logFile:  logFile,
		runID:    runID,
		db:       db,
		ingester: ingester,
		llm:      llmClient,
		opengrep: og,
		astgrep:  ag,
		joern:    jc,
		instr:    is,
		verif:    vf,
		target:   tgt,
		enrich:   enr,
		clf:      clf,
		asm:      asm,
		sum:      sum,
		bud:      bud,
		scan:     sc,
		store:    store,
		w:        wm,
		dd:       dd,
		gen:      pg,
		rep:      rg,
	}, nil
}

// run executes the full pipeline to completion and writes the HTML report.
// events receives stage notifications consumed by the active CLI renderer.
// The caller is responsible for closing events after run returns.
func (p *pipeline) run(ctx context.Context, events chan<- output.Event) error {
	start := time.Now()
	p.logger.Info("scan started",
		"component", "scan",
		"target", p.cfg.Target,
		"mode", p.cfg.ScanMode,
	)

	// ── 0. JOERN PRE-START ────────────────────────────────────────────────────
	// Spawn the Joern subprocess before ingestion so the JVM is warm by the
	// time Path A/B need it. Non-fatal: if Joern fails to start, taint analysis
	// is skipped; OpenGrep + ast-grep + instrscan continue regardless.
	if p.cfg.JoernBin != "" {
		if err := p.joern.Start(ctx); err != nil {
			output.Emit(events, output.Event{
				Kind: output.EventLog,
				Log:  fmt.Sprintf("warn: joern start: %v — taint analysis disabled for this scan", err),
			})
		}
	}

	// ── 1. INGEST ────────────────────────────────────────────────────────────
	output.Emit(events, output.Event{Kind: output.EventStageStart, Stage: "ingestion"})
	ingResult, err := p.ingester.Run(ctx, ingestion.Config{
		ProjectID:   p.cfg.ProjectID,
		ProjectRoot: p.cfg.Target,
		ModelPath:   "", // GGUF path resolved from cfg.ModelName in L0.3
	})
	if err != nil {
		return fmt.Errorf("ingestion: %w", err)
	}
	// Gate all Go-side LLM calls when MIV detected a known model with a bad hash.
	// CPG build and pattern matching proceed regardless.
	if ingResult.BlockLLM {
		p.llm.SetMIVBlocked()
	}

	changedCount := 0
	if ingResult.ChangeSet != nil {
		changedCount = len(ingResult.ChangeSet.Changed)
	}
	output.Emit(events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "ingestion",
		Summary: &output.StageSummary{
			Stage:  "ingestion",
			Detail: fmt.Sprintf("%d files changed", changedCount),
		},
	})

	// ── 1.5. CPG BUILD / LOAD ──────────────────────────────────────────────────
	// Build or load the CPG from the scope files. On first scan this is a full
	// build; on repeat scans it loads a snapshot and applies incremental patches.
	// Non-fatal: if the CPG cannot be built, taint analysis is skipped but
	// OpenGrep + ast-grep + instrscan continue.
	var scopeFiles []string
	if ingResult.ChangeSet != nil && len(ingResult.ChangeSet.Changed) > 0 {
		changed := ingResult.ChangeSet.Changed

		// Detect working modules and determine scope.
		modules := joern.DetectWorkingModules(changed)
		if p.joern != nil {
			graph := p.joern.GraphWithContext(ctx)

			// Pre-flag dangerous sinks in the changed files so they are always
			// in scope regardless of module segmentation mode. Best-effort:
			// failures just mean no pre-flagged sinks for this scan.
			if preFlagErr := p.joern.PreFlagSinks(ctx, changed); preFlagErr != nil {
				p.logger.Warn("sink pre-flagging failed, continuing without pre-flagged sinks",
					"component", "scan",
					"err", preFlagErr,
				)
			} else {
				p.logger.Info("sink pre-flagging complete",
					"component", "scan",
					"sinks", len(p.joern.PreFlaggedSinks()),
				)
			}

			// Attempt CPG build or load + incremental patch.
			cpgPath := cpgSnapshotPath(p.cfg.ProjectID)
			buildErr := p.buildOrLoadCPG(ctx, cpgPath, changed, events)
			if buildErr == nil {
				// CPG ready — expand scope via modules.
				depth := moduleDepthForMode(p.cfg.ScanMode)
				if depth > 0 {
					// First expand change set with one-hop CPG neighbours.
					expanded, expandErr := diffindex.ExpandWithCPG(ctx, ingResult.ChangeSet, graph)
					if expandErr != nil {
						p.logger.Error("cpg scope expansion failed, using pre-expansion modules",
							"component", "scan",
							"err", expandErr,
						)
					} else {
						modules = joern.DetectWorkingModules(expanded.Changed)
					}
					joern.ExpandModuleScope(modules, graph, depth)
				}
				scopeFiles = joern.FilterScopeByLanguage(joern.FlattenScope(modules))
			} else {
				output.Emit(events, output.Event{
					Kind: output.EventLog,
					Log:  fmt.Sprintf("warn: cpg build: %v — taint analysis disabled", buildErr),
				})
				scopeFiles = joern.FilterScopeByLanguage(changed)
			}
		} else {
			scopeFiles = changed
		}
	}

	output.Emit(events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "cpg",
		Summary: &output.StageSummary{
			Stage:  "cpg",
			Detail: fmt.Sprintf("%d files in scope after expansion", len(scopeFiles)),
		},
	})

	// ── 2 + 3. PATH A ∥ PATH B ───────────────────────────────────────────────
	// Both paths write findings to a shared buffered channel; results are
	// collected by the drain goroutine below. Neither path gates the other.
	findCh := make(finding.Channel, 256)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer func() { /* Path A done; Path B may still be running */ }()
		return p.runPathA(gctx, ingResult, scopeFiles, findCh, events)
	})
	g.Go(func() error {
		return p.runPathB(gctx, ingResult, findCh, events)
	})

	// Close findCh once both paths finish so the drain loop can exit.
	var closeOnce sync.Once
	go func() {
		_ = g.Wait() // errors surfaced below via the second g.Wait()
		closeOnce.Do(func() { close(findCh) })
	}()

	// Drain findings; emit each one to the renderer.
	var allFindings []finding.Finding
	for f := range findCh {
		fc := f
		allFindings = append(allFindings, fc)
		output.Emit(events, output.Event{Kind: output.EventFinding, Finding: &fc})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("detection paths: %w", err)
	}

	// ── 4. DEDUP ──────────────────────────────────────────────────────────────
	output.Emit(events, output.Event{Kind: output.EventStageStart, Stage: "dedup"})
	scored, err := p.dd.Process(ctx, allFindings)
	if err != nil {
		return fmt.Errorf("dedup: %w", err)
	}
	output.Emit(events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "dedup",
		Summary: &output.StageSummary{
			Stage:  "dedup",
			Detail: fmt.Sprintf("%d findings after dedup", len(scored)),
		},
	})

	// ── 4a. PERSIST FINDINGS ─────────────────────────────────────────────────
	if p.db != nil && p.runID != "" {
		now := time.Now().Unix()
		for i := range scored {
			f := &scored[i]
			row := sqlite.FindingRow{
				FindingID:      f.ID,
				ProjectID:      ingResult.ProjectID,
				RunID:          p.runID,
				FilePath:       f.Path,
				LineStart:      f.LineRange.Start,
				LineEnd:        f.LineRange.End,
				CWE:            f.CWE,
				Severity:       string(f.SeverityLabel),
				Confidence:     f.Confidence,
				SourcePath:     string(f.SourcePath),
				RuleID:         f.RuleID,
				MatchedCode:    f.MatchedCode,
				Justification:  f.Justification,
				SuppressReason: string(f.SuppressReason),
				FirstSeenAt:    now,
				LastSeenAt:     now,
			}
			if upsertErr := p.db.UpsertFinding(ctx, row); upsertErr != nil {
				p.logger.Warn("failed to persist finding",
					"component", "scan",
					"finding_id", f.ID,
					"err", upsertErr,
				)
			}
		}
	}

	// ── 5. PATCH ──────────────────────────────────────────────────────────────
	patches, err := p.gen.Generate(ctx, scored)
	if err != nil {
		return fmt.Errorf("patch generation: %w", err)
	}
	patchByID := make(map[string]patch.Patch, len(patches))
	for _, pp := range patches {
		patchByID[pp.FindingID] = pp
	}
	for i := range scored {
		if pp, ok := patchByID[scored[i].ID]; ok {
			scored[i].Patch       = pp.UnifiedDiff
			scored[i].PatchStatus = string(pp.Status)
		}
	}

	// ── 6. REPORT ─────────────────────────────────────────────────────────────
	if err := os.MkdirAll(filepath.Dir(p.cfg.ReportPath), 0o750); err != nil {
		return fmt.Errorf("mkdir report dir: %w", err)
	}
	f, err := os.Create(p.cfg.ReportPath)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer f.Close() //nolint:errcheck

	info := report.ScanInfo{
		ProjectName:  filepath.Base(p.cfg.Target),
		ScannedAt:    start.UTC().Format("2006-01-02 15:04 UTC"),
		ScanMode:     p.cfg.ScanMode,
		ScanDuration: time.Since(start).Round(time.Millisecond).String(),
	}
	if err := p.rep.Render(f, info, scored); err != nil {
		return fmt.Errorf("render report: %w", err)
	}

	// Advance the differential-index baseline so the next run only re-scans changes.
	// Non-fatal: a commit failure just means the next scan is a full scan.
	if err := p.ingester.CommitScan(ctx, ingResult.ProjectID, ingResult.ChangeSet); err != nil {
		output.Emit(events, output.Event{
			Kind: output.EventLog,
			Log:  fmt.Sprintf("warn: commit scan state: %v", err),
		})
	}

	// Build per-severity counts for the done summary.
	bySeverity := make(map[finding.SeverityLabel]int, 5)
	for _, s := range scored {
		bySeverity[s.SeverityLabel]++
	}
	elapsed := time.Since(start)
	p.logger.Info("scan complete",
		"component", "scan",
		"findings", len(scored),
		"elapsed", elapsed,
		"report", p.cfg.ReportPath,
	)
	if p.db != nil && p.runID != "" {
		if finalErr := p.db.FinalizeScanRun(ctx, p.runID, time.Now().Unix(), changedCount, len(scored)); finalErr != nil {
			p.logger.Warn("failed to finalize scan_run", "component", "scan", "err", finalErr)
		}
	}

	output.Emit(events, output.Event{
		Kind: output.EventDone,
		Done: &output.ScanSummary{
			Elapsed:       elapsed,
			TotalFindings: len(scored),
			BySeverity:    bySeverity,
			ReportPath:    p.cfg.ReportPath,
		},
	})
	return nil
}

// runPathA executes all Path A detectors concurrently, then runs the LLM Verifier
// on the collected findings before writing to ch.
//
// Four goroutines collect into a buffer in parallel:
//  0. Joern CPG taint analysis — inter-procedural dataflow on scope files.
//  1. OpenGrep — structural pattern matching for Python/Java/JS/Go/Ruby/PHP.
//  2. ast-grep — pattern matching for Rust/Dart/Swift/Kotlin/C#.
//  3. instrscan — AI agent instruction file and MCP config injection scan
//     (skipped when no instruction files appear in the changeset).
//
// High-confidence bypass: findings with Confidence >= verifier.HighConfidenceThreshold
// (0.90) come from deterministic rules with near-zero FP rates and go straight to ch.
// The remainder go through the LLM Verifier (CoD + SCoT + ASC) before emission.
// Verifier failures degrade gracefully: unverified findings are emitted rather than
// silently dropped.
func (p *pipeline) runPathA(ctx context.Context, res *ingestion.Result, scopeFiles []string, ch finding.Channel, events chan<- output.Event) error {
	output.Emit(events, output.Event{Kind: output.EventStageStart, Stage: "path a"})

	// DiffIndex returns paths relative to the project root; make them absolute
	// so subprocess scanners (opengrep, ast-grep) can find them from any CWD.
	var changed []string
	if res.ChangeSet != nil {
		for _, rel := range res.ChangeSet.Changed {
			changed = append(changed, filepath.Join(p.cfg.Target, rel))
		}
	}

	// rawBuf collects findings from all detectors; protected by mu.
	var (
		mu     sync.Mutex
		rawBuf []finding.Finding
	)

	collect := func(fs []finding.Finding) {
		mu.Lock()
		rawBuf = append(rawBuf, fs...)
		mu.Unlock()
	}

	g, gctx := errgroup.WithContext(ctx)

	// 0. Joern CPG taint analysis — inter-procedural dataflow on scope files.
	g.Go(func() error {
		if len(scopeFiles) == 0 || p.joern == nil {
			return nil
		}
		graph := p.joern.GraphWithContext(ctx)
		findings, err := runJoernTaint(gctx, graph, scopeFiles)
		if err != nil {
			output.Emit(events, output.Event{
				Kind: output.EventLog,
				Log:  fmt.Sprintf("warn: joern taint: %v", err),
			})
			return nil
		}
		collect(findings)
		return nil
	})

	// 1. OpenGrep — owns Python/Java/JS/TS/Go/Ruby/PHP
	g.Go(func() error {
		findings, err := p.opengrep.Scan(gctx, changed)
		if err != nil {
			output.Emit(events, output.Event{
				Kind: output.EventLog,
				Log:  fmt.Sprintf("warn: opengrep: %v", err),
			})
			return nil
		}
		collect(findings)
		return nil
	})

	// 2. ast-grep — owns Rust/Dart/Swift/Kotlin/C#
	g.Go(func() error {
		agFiles := astgrep.FilterFiles(changed)
		findings, err := p.astgrep.Scan(gctx, agFiles)
		if err != nil {
			output.Emit(events, output.Event{
				Kind: output.EventLog,
				Log:  fmt.Sprintf("warn: ast-grep: %v", err),
			})
			return nil
		}
		collect(findings)
		return nil
	})

	// 3. instrscan — AI agent instruction file and MCP config injection.
	g.Go(func() error {
		if !instrscan.ContainsInstructionFile(changed) {
			return nil
		}
		fsys := os.DirFS(p.cfg.Target)
		instrFindings, err := p.instr.Scan(fsys)
		if err != nil {
			output.Emit(events, output.Event{
				Kind: output.EventLog,
				Log:  fmt.Sprintf("warn: instrscan: %v", err),
			})
			return nil
		}
		fs := make([]finding.Finding, len(instrFindings))
		for i, instr := range instrFindings {
			fs[i] = instrFindingToFinding(instr)
		}
		collect(fs)
		return nil
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("path a: %w", err)
	}

	// Partition into high-confidence bypass and LLM-verify candidates.
	var bypass, needsVerify []finding.Finding
	for _, f := range rawBuf {
		if f.Confidence >= verifier.HighConfidenceThreshold {
			bypass = append(bypass, f)
		} else {
			needsVerify = append(needsVerify, f)
		}
	}

	// Send bypass findings directly to channel; drain loop emits EventFinding.
	for _, f := range bypass {
		ch <- f
	}

	// Verify the remainder; degrade gracefully on worker failure.
	if len(needsVerify) > 0 {
		verifyStart := time.Now()
		results, err := p.verif.Verify(ctx, needsVerify)
		verifyElapsed := time.Since(verifyStart)
		if err != nil {
			output.Emit(events, output.Event{
				Kind: output.EventLog,
				Log:  fmt.Sprintf("warn: llm verifier: %v — emitting unverified findings", err),
			})
			for _, f := range needsVerify {
				ch <- f
			}
		} else {
			verified := verifier.ApplyResults(needsVerify, results)
			// ponytail: batch latency divided by count; per-finding p50/p95 needs the benchmark harness
			perFindingMs := verifyElapsed.Milliseconds()
			if len(needsVerify) > 0 {
				perFindingMs = verifyElapsed.Milliseconds() / int64(len(needsVerify))
			}
			for _, f := range verified {
				p.logger.Info("verifier latency", "finding_id", f.ID, "ms", perFindingMs)
				ch <- f
			}
		}
	}

	output.Emit(events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "path a",
		Summary: &output.StageSummary{
			Stage: "path a",
			Detail: fmt.Sprintf("%d findings (%d bypass, %d verified)",
				len(rawBuf), len(bypass), len(needsVerify)),
		},
	})
	return nil
}

// instrFindingToFinding converts an instrscan.Finding to a canonical finding.Finding.
// CWE-1035 (OWASP: Prompt Injection) is used for instruction-file injection signals.
func instrFindingToFinding(f instrscan.Finding) finding.Finding {
	var confidence float64
	switch f.Signal {
	case instrscan.SignalMCPSchemaViolation:
		confidence = 0.90 // deterministic schema check — high confidence
	case instrscan.SignalKeywordMatch:
		confidence = 0.65
	default: // SignalUnicodeObfuscation
		confidence = 0.75
	}
	return finding.Finding{
		ID:            finding.ComputeID("CWE-1035", f.File, ""),
		Path:          f.File,
		LineRange:     finding.LineRange{Start: f.Line, End: f.Line},
		CWE:           "CWE-1035",
		Confidence:    confidence,
		SeverityLabel: finding.SeverityFromConfidence(confidence),
		SourcePath:    finding.SourcePattern,
		Justification: string(f.Signal) + ": " + f.Detail,
		RuleID:        "INSTR-" + string(f.Signal),
	}
}

// runPathB executes the Path B semantic detection tier pipeline and writes
// findings to ch. Returns nil when Joern CPG is unavailable (0 surfaces selected).
func (p *pipeline) runPathB(ctx context.Context, _ *ingestion.Result, ch finding.Channel, events chan<- output.Event) error {
	output.Emit(events, output.Event{Kind: output.EventStageStart, Stage: "path b"})

	// B1: Heuristic Targeting — requires a populated Joern CPG.
	// Joern connectivity failures are non-fatal: emit a warning and skip Path B.
	surfaces, err := p.target.SelectSurfaces(ctx)
	if err != nil {
		p.logger.Warn("path b targeting failed — CPG unavailable", "err", err)
		output.Emit(events, output.Event{
			Kind:    output.EventStageEnd,
			Stage:   "path b",
			Summary: &output.StageSummary{Stage: "path b", Detail: "skipped: CPG unavailable"},
		})
		return nil
	}
	if len(surfaces) == 0 {
		output.Emit(events, output.Event{
			Kind:    output.EventStageEnd,
			Stage:   "path b",
			Summary: &output.StageSummary{Stage: "path b", Detail: "no surfaces selected (CPG unavailable or no external-input nodes found)"},
		})
		return nil
	}

	// B2: CVE Enrichment.
	enriched, err := p.enrich.Enrich(ctx, surfaces, p.cfg.Target)
	if err != nil {
		return fmt.Errorf("path b enrichment: %w", err)
	}

	// B3: UniXcoder Classifier — filter to surfaces that must escalate to LLM.
	classified, err := p.clf.Classify(ctx, enriched)
	if err != nil {
		return fmt.Errorf("path b classifier: %w", err)
	}
	escalated, clfByID := filterEscalated(enriched, classified)
	if len(escalated) == 0 {
		output.Emit(events, output.Event{
			Kind:    output.EventStageEnd,
			Stage:   "path b",
			Summary: &output.StageSummary{Stage: "path b", Detail: "classifier suppressed all surfaces"},
		})
		return nil
	}

	// Build surface lookup for budget.Input construction.
	surfaceByID := make(map[string]targeting.Surface, len(surfaces))
	for _, s := range surfaces {
		surfaceByID[s.ID] = s
	}

	// B4: Call Chain Assembler.
	chains, err := p.asm.Assemble(ctx, escalated)
	if err != nil {
		return fmt.Errorf("path b assembler: %w", err)
	}

	// B5: Semantic Summarizer.
	summaries, err := p.sum.Summarize(ctx, chains)
	if err != nil {
		return fmt.Errorf("path b summarizer: %w", err)
	}

	// B6: Token Budget — rank surfaces by priority within the token cap.
	inputs := buildBudgetInputs(summaries, enriched, clfByID, surfaceByID)
	ranked, exhausted, budStats := p.bud.RankWithStats(inputs)

	// Emit SUPPRESSED findings for surfaces that exceeded the token cap.
	for _, ex := range exhausted {
		s := surfaceByID[ex.Summary.SurfaceID]
		f := finding.Finding{
			SeverityLabel:  finding.SeveritySuppressed,
			Path:           s.File,
			Justification:  "token budget exhausted for " + s.FunctionName + "; increase --token-cap to scan",
			SuppressReason: finding.SuppressReasonBudgetExhausted,
			SourcePath:     finding.SourceSemantic,
		}
		select {
		case ch <- f:
		default:
		}
	}

	// B7: LLM Semantic Scan.
	llmFindings, err := p.scan.WithStore(p.store).Scan(ctx, ranked)
	if err != nil {
		return fmt.Errorf("path b llm scan: %w", err)
	}
	for _, f := range llmFindings {
		select {
		case ch <- f:
		default:
		}
	}

	output.Emit(events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "path b",
		Summary: &output.StageSummary{
			Stage:    "path b",
			Detail:   fmt.Sprintf("%d findings; %d surfaces ranked; %d exhausted", len(llmFindings), budStats.Ranked, budStats.Exhausted),
			Findings: len(llmFindings),
		},
	})
	return nil
}

// filterEscalated returns the subset of enriched surfaces whose classifier
// result has Escalate==true, plus a map from surfaceID to classifier.Result.
func filterEscalated(enriched []enrichment.EnrichedSurface, results []classifier.Result) ([]enrichment.EnrichedSurface, map[string]classifier.Result) {
	byID := make(map[string]classifier.Result, len(results))
	for _, r := range results {
		byID[r.SurfaceID] = r
	}
	var out []enrichment.EnrichedSurface
	for _, e := range enriched {
		if r, ok := byID[e.ID]; ok && r.Escalate {
			out = append(out, e)
		}
	}
	return out, byID
}

// buildBudgetInputs constructs the budget.Input slice from summarizer output,
// correlating CVSS, classifier confidence, and call-graph depth by SurfaceID.
func buildBudgetInputs(
	summaries []summarizer.Summary,
	enriched []enrichment.EnrichedSurface,
	clfByID map[string]classifier.Result,
	surfaceByID map[string]targeting.Surface,
) []budget.Input {
	// Build enriched surface lookup for CVSS extraction.
	enrichByID := make(map[string]enrichment.EnrichedSurface, len(enriched))
	for _, e := range enriched {
		enrichByID[e.ID] = e
	}

	inputs := make([]budget.Input, 0, len(summaries))
	for _, sum := range summaries {
		inp := budget.Input{Summary: sum}
		if e, ok := enrichByID[sum.SurfaceID]; ok {
			inp.CVSSScore = maxCVSS(e.CVEMatches)
		}
		if r, ok := clfByID[sum.SurfaceID]; ok {
			inp.ClassifierConfidence = r.Confidence
		}
		if s, ok := surfaceByID[sum.SurfaceID]; ok {
			inp.CallGraphDepth = s.CallGraphDepth
		}
		inputs = append(inputs, inp)
	}
	return inputs
}

// maxCVSS returns the highest CVSS score in matches, or 0.0 if empty.
func maxCVSS(matches []enrichment.CVEMatch) float64 {
	var max float64
	for _, m := range matches {
		if m.CVSS > max {
			max = m.CVSS
		}
	}
	return max
}

// close shuts down all managed subprocesses and releases held resources.
// Always called after run() returns, even on error.
func (p *pipeline) close() error {
	// Stop Joern subprocess if we spawned it. Use a fixed timeout — this runs
	// after the scan; we don't want it to block indefinitely on cleanup.
	if p.cfg.JoernBin != "" && p.joern != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = p.joern.Stop(stopCtx) //nolint:errcheck // best-effort cleanup
	}

	var workerErr error
	if p.w != nil {
		workerErr = p.w.Stop()
	}
	if p.db != nil {
		_ = p.db.Close() //nolint:errcheck // best-effort; SQLite WAL checkpoint on close
	}
	if p.logFile != nil {
		_ = p.logFile.Close() //nolint:errcheck // best-effort log file close on scan end
	}
	return workerErr
}

// stateDBPath returns the path to the SQLite state file, creating the directory
// if needed. The file lives at ~/.zerotrust/scans.db.
func stateDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(home, ".zerotrust")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir ~/.zerotrust: %w", err)
	}
	return filepath.Join(dir, "scans.db"), nil
}

// ── CPG build helpers ─────────────────────────────────────────────────────────

// maxScopeLOC is the maximum total lines-of-code allowed in the CPG build scope
// before the build is skipped. This keeps build times under the 60 s target.
// If the scope exceeds this limit, a warning is logged and taint analysis is
// skipped for this scan (OpenGrep / ast-grep / instrscan continue unaffected).
const maxScopeLOC = 5_000

// countLOC returns the total line count across all given files.
// Files that cannot be read or opened are silently skipped.
func countLOC(files []string) (int, error) {
	var total int
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		total += bytes.Count(content, []byte{'\n'})
	}
	return total, nil
}

// buildOrLoadCPG builds a fresh CPG or loads an existing snapshot and applies
// incremental patches. Returns nil on success or an error if the CPG cannot be
// prepared (non-fatal — callers proceed without taint analysis).
func (p *pipeline) buildOrLoadCPG(ctx context.Context, cpgPath string, changedFiles []string, events chan<- output.Event) error {
	if p.joern == nil {
		return fmt.Errorf("joern client not initialized")
	}

	// Query the current Joern version for snapshot invalidation.
	currentVersion, verErr := p.joern.Version(ctx)
	if verErr != nil {
		p.logger.Warn("could not determine Joern version, proceeding without version check",
			"component", "cpg",
			"err", verErr,
		)
		currentVersion = "unknown"
	}

	// Check if a prior CPG snapshot exists.
	versionPath := joern.VersionSnapshotPath(p.cfg.ProjectID)
	snapshotExists := false
	if _, err := os.Stat(cpgPath); err == nil {
		// Version mismatch check: if the stored version differs from the current
		// Joern version, invalidate the snapshot and force a full rebuild.
		if storedVersion, readErr := os.ReadFile(versionPath); readErr == nil {
			stored := strings.TrimSpace(string(storedVersion))
			if stored != "" && stored != currentVersion {
				output.Emit(events, output.Event{
					Kind:  output.EventLog,
					Stage: "cpg",
					Log:   fmt.Sprintf("Joern version changed from %s to %s — invalidating CPG snapshot", stored, currentVersion),
				})
				_ = os.Remove(cpgPath)
				_ = os.Remove(versionPath)
				snapshotExists = false
			} else {
				snapshotExists = true
			}
		} else {
			// No version file — treat as fresh snapshot.
			snapshotExists = true
		}
	}

	if snapshotExists {
		output.Emit(events, output.Event{
			Kind:  output.EventLog,
			Stage: "cpg",
			Log:   "loading prior CPG snapshot for incremental update",
		})

		// Load the prior CPG.
		if err := p.joern.LoadCPG(ctx, cpgPath); err != nil {
			return fmt.Errorf("load cpg: %w", err)
		}

		// Build the incremental config from changed files.
		// Map changed files to function names via CPG queries.
		graph := p.joern.GraphWithContext(ctx)
		var changedFunctions []string
		for _, f := range changedFiles {
			nodes, err := graph.QueryNodesByFile(f, cpg.NodeMethod)
			if err != nil || len(nodes) == 0 {
				// If the file is new, we need a full rebuild.
				output.Emit(events, output.Event{
					Kind:  output.EventLog,
					Stage: "cpg",
					Log:   fmt.Sprintf("no prior CPG nodes for %s — falling back to full build", f),
				})
				return p.buildFullCPG(ctx, cpgPath, changedFiles)
			}
			for _, n := range nodes {
				changedFunctions = append(changedFunctions, n.ID)
			}
		}

		if len(changedFunctions) == 0 {
			// No functions changed — CPG is already up to date.
			return nil
		}

		// Apply incremental patch.
		err := p.joern.IncrementalPatch(ctx, joern.IncrementalPatchConfig{
			ChangedFunctions: changedFunctions,
			RemovedFiles:     nil, // removed not tracked here
			MaxDepth:         5,
			HubCallerThreshold: 50,
			SerializedCPGPath: cpgPath,
		})
		if err != nil {
			// Hub module detected or patch failed — fall back to full rebuild.
			output.Emit(events, output.Event{
				Kind:  output.EventLog,
				Stage: "cpg",
				Log:   fmt.Sprintf("incremental patch aborted (%v) — full rebuild", err),
			})
			return p.buildFullCPG(ctx, cpgPath, changedFiles)
		}

		return nil
	}

	// No prior snapshot — full build.
	return p.buildFullCPG(ctx, cpgPath, changedFiles)
}

// buildFullCPG builds a complete CPG from the given files and saves the snapshot.
// Returns nil on success or an error the caller should handle as non-fatal.
func (p *pipeline) buildFullCPG(ctx context.Context, cpgPath string, scopeFiles []string) error {
	if len(scopeFiles) == 0 {
		return fmt.Errorf("no files in scope for CPG build")
	}

	// Enforce the ≤5K LOC gate to keep build times under the 60 s target.
	loc, err := countLOC(scopeFiles)
	if err != nil {
		return fmt.Errorf("count loc: %w", err)
	}
	if loc > maxScopeLOC {
		return fmt.Errorf("scope exceeds %d LOC (%d) — CPG build skipped; taint analysis disabled",
			maxScopeLOC, loc)
	}

	p.logger.Info("building CPG",
		"component", "cpg",
		"files", len(scopeFiles),
		"loc", loc,
		"target_build_time_seconds", 60,
	)

	buildStart := time.Now()
	err = p.joern.BuildCPG(ctx, joern.BuildConfig{
		Paths:             scopeFiles,
		Language:          "", // auto-detect
		SerializedCPGPath: cpgPath,
	})
	buildElapsed := time.Since(buildStart)
	if err != nil {
		p.logger.Error("CPG build failed",
			"component", "cpg",
			"elapsed", buildElapsed,
			"err", err,
		)
		return fmt.Errorf("build cpg: %w", err)
	}

	p.logger.Info("CPG build complete",
		"component", "cpg",
		"elapsed", buildElapsed,
		"files", len(scopeFiles),
		"loc", loc,
	)

	// Persist the Joern version alongside the snapshot for invalidation on
	// repeat scans. Non-fatal: a write failure just means the next scan may
	// rebuild unnecessarily.
	versionPath := joern.VersionSnapshotPath(p.cfg.ProjectID)
	if version, verErr := p.joern.Version(ctx); verErr == nil {
		if writeErr := os.WriteFile(versionPath, []byte(version+"\n"), 0o644); writeErr != nil {
			p.logger.Warn("failed to persist Joern version snapshot",
				"component", "cpg",
				"err", writeErr,
			)
		}
	}
	return nil
}

// cpgSnapshotPath returns the path to the serialized CPG snapshot for the given
// project ID. The snapshot lives at ~/.zerotrust/{projectID}.cpg.
func cpgSnapshotPath(projectID string) string {
	if projectID == "" {
		projectID = "default"
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		return filepath.Join(".zerotrust", projectID+".cpg")
	}
	return filepath.Join(home, ".zerotrust", projectID+".cpg")
}

// moduleDepthForMode returns the neighbour-expansion depth for the given scan mode.
func moduleDepthForMode(mode string) int {
	switch mode {
	case "Thorough":
		return 3
	case "Full":
		return 0 // 0 means no expansion needed — entire codebase is in scope
	default: // Default
		return 2
	}
}

// ── Joern taint analysis ──────────────────────────────────────────────────────

// runJoernTaint performs inter-procedural taint analysis on scopeFiles using
// the Joern CPG graph. Returns normalised Finding structs.
func runJoernTaint(ctx context.Context, graph cpg.Graph, scopeFiles []string) ([]finding.Finding, error) {
	// Detect the primary language from scope files.
	lang, ok := joern.DetectLanguageFromFiles(scopeFiles)
	if !ok {
		return nil, nil
	}
	// Ensure the language has a taint config.
	if _, hasConfig := joern.TaintConfigs[lang]; !hasConfig {
		return nil, nil
	}

	// Build source and sink lists from CPG nodes matching our taxonomy.
	var sources []cpg.TaintSource
	var sinks []cpg.TaintSink

	for _, f := range scopeFiles {
		calls, err := graph.QueryNodesByFile(f, cpg.NodeCall)
		if err != nil {
			continue
		}
		for _, c := range calls {
			// Match against source definitions — use the taxonomy Kind.
			if sd, ok := joern.SourceDefForCall(lang, c.Name); ok {
				sources = append(sources, cpg.TaintSource{
					NodeID: c.ID,
					Kind:   sd.Kind,
					File:   c.File,
					Line:   c.Line,
				})
			}
			// Match against sink definitions — use the taxonomy Kind.
			if sd, ok := joern.SinkDefForCall(lang, c.Name); ok {
				sinks = append(sinks, cpg.TaintSink{
					NodeID: c.ID,
					Kind:   sd.Kind,
					File:   c.File,
					Line:   c.Line,
				})
			}
		}
	}

	if len(sources) == 0 || len(sinks) == 0 {
		return nil, nil
	}

	// Run the taint analysis.
	paths, err := graph.TaintPaths(sources, sinks)
	if err != nil {
		return nil, fmt.Errorf("taint paths: %w", err)
	}

	// Normalise to Finding structs.
	return joern.TaintPathsToFindings(paths, lang), nil
}

// newRunID generates a random 16-character hex string to uniquely identify a scan run.
// crypto/rand.Read never returns an error on supported platforms.
func newRunID() string {
	var b [8]byte
	_, _ = rand.Read(b[:]) //nolint:errcheck
	return fmt.Sprintf("%x", b)
}
