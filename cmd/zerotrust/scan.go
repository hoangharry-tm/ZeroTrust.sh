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
//     LLM Verifier filters false positives from pattern findings.
//  3. PATH B  — Sequential tier pipeline:
//     Heuristic Targeting → CVE Enrichment → CodeT5+ Classifier →
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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/hoangharry-tm/zerotrust/internal/dedup"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion/diffindex"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion/miv"
	"github.com/hoangharry-tm/zerotrust/internal/orchestrator"
	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/patch"
	"github.com/hoangharry-tm/zerotrust/internal/scanner"
	"github.com/hoangharry-tm/zerotrust/internal/scanner/joern"
	"github.com/hoangharry-tm/zerotrust/internal/scanner/opengrep"
	"github.com/hoangharry-tm/zerotrust/internal/report"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/assembler"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/budget"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/classifier"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/llmscan"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/scs"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/summarizer"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/internal/tuning"
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

	// Path A — legacy incremental flow
	opengrep *opengrep.Runner
	joern    *joern.Client
	// orch runs the dynamic tool dispatcher concurrently with Joern CPG init.
	orch *orchestrator.Engine

	// Path B
	target *targeting.Targeter
	enrich *enrichment.Enricher
	clf    *classifier.Gate
	asm    *assembler.Assembler
	sum    *summarizer.Summarizer
	bud    *budget.Controller
	scan   *llmscan.Scanner
	store  *scs.Store

	// degradation alerts surfaced in the HTML report header
	alerts []string

	// shared
	w   *worker.Manager
	dd  *dedup.Layer
	gen *patch.Generator
	rep *report.Generator
}

// teeHandler writes every log record to two separate handlers.
// Used when --verbose is set to send Debug+ logs to both the JSON log file
// and the terminal (text format on stderr).
type teeHandler struct {
	json slog.Handler
	text slog.Handler
}

func (h *teeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.json.Enabled(ctx, level) || h.text.Enabled(ctx, level)
}

func (h *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	if err := h.json.Handle(ctx, r); err != nil {
		return err
	}
	return h.text.Handle(ctx, r)
}

func (h *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &teeHandler{json: h.json.WithAttrs(attrs), text: h.text.WithAttrs(attrs)}
}

func (h *teeHandler) WithGroup(name string) slog.Handler {
	return &teeHandler{json: h.json.WithGroup(name), text: h.text.WithGroup(name)}
}

// eventsHandler wraps a slog.Handler and also sends Info+ records to the
// pipeline events channel so they appear in the SSE dialog's console panel.
type eventsHandler struct {
	next   slog.Handler
	events chan<- output.Event
}

func (h *eventsHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *eventsHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelDebug && h.events != nil {
		msg := fmt.Sprintf("%s  %s", r.Level, r.Message)
		r.Attrs(func(a slog.Attr) bool {
			if a.Value.Kind() == slog.KindString {
				msg += " " + a.Key + "=" + a.Value.String()
			}
			return true
		})
		output.Emit(h.events, output.Event{Kind: output.EventLog, Log: msg})
	}
	return h.next.Handle(ctx, r)
}

func (h *eventsHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &eventsHandler{next: h.next.WithAttrs(attrs), events: h.events}
}

func (h *eventsHandler) WithGroup(name string) slog.Handler {
	return &eventsHandler{next: h.next.WithGroup(name), events: h.events}
}

// newPipeline constructs the full pipeline from cfg.
// It opens the SQLite state cache, starts the Python worker, and instantiates
// every stage. Returns a ready-to-run pipeline or an error on setup failure.
//
// The caller is responsible for calling pipeline.close() after run() returns.
func newPipeline(ctx context.Context, cfg ScanConfig) (*pipeline, error) {
	cfg.defaults()

	cal, err := tuning.LoadCalibration(cfg.CalibrationPath)
	if err != nil {
		return nil, fmt.Errorf("load calibration: %w", err)
	}
	if cfg.CalibrationPath != "" {
		// ponytail: parent env inherits to exec.Command subprocess
		_ = os.Setenv("ZT_CALIBRATION", cfg.CalibrationPath)
	}

	absTarget, err := filepath.Abs(cfg.Target)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	cfg.Target = absTarget

	// Structured logger — JSON lines written to build/zerotrust.log alongside the report.
	// Also set as slog.Default so all slog.* calls in every package flow to the log file
	// (and optionally to stderr when --verbose is active).
	logDir := filepath.Dir(cfg.ReportPath)
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", logDir, err)
	}
	logFile, err := os.OpenFile(filepath.Join(logDir, "zerotrust.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	jsonHandler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: slog.LevelDebug})
	var defaultHandler slog.Handler = jsonHandler
	if cfg.Verbose {
		defaultHandler = &teeHandler{
			json: jsonHandler,
			text: slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}),
		}
	}
	logger := slog.New(defaultHandler)
	slog.SetDefault(logger)

	// SQLite state cache at <target>/.zerotrust/scans.db
	dbPath, err := stateDBPath(cfg.Target)
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}
	db, err := sqlite.Open(dbPath)
	if err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("open state db: %w", err)
	}

	// runID is assigned here; project/scan_run rows are registered after ingestion
	// so we use the resolved ProjectID (ingester may derive one from the target path).
	runID := newRunID()

	// Propagate model name and verbosity to Python worker handlers.
	if cfg.ModelName != "" {
		_ = os.Setenv("ZEROTRUST_MODEL", cfg.ModelName)
	}
	if cfg.Verbose {
		_ = os.Setenv("ZEROTRUST_VERBOSE", "1")
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
	og := opengrep.NewMulti(scanner.BinarySpec{Name: "opengrep"}, logger)
	orch := orchestrator.New(
		og,
		scanner.NewGitleaks(scanner.BinarySpec{Name: "gitleaks"}),
		scanner.NewOSV(scanner.BinarySpec{Name: "osv-scanner"}),
	)
	joernOpts := []joern.Option{joern.WithServerURL(cfg.JoernURL)}
	if cfg.JoernBin != "" {
		joernOpts = append(joernOpts, joern.WithBinaryPath(cfg.JoernBin))
	}
	jc, err := joern.New(joernOpts...)
	if err != nil {
		return nil, fmt.Errorf("configure joern: %w", err)
	}

	// Path B — graph shared from Joern after CPG build
	graph := jc.GraphWithContext(ctx)
	tgt := targeting.New(graph)
	enr := enrichment.New(graph, "trivy", cfg.Offline)
	clf := classifier.New(wm, logger)
	asm := assembler.New(graph, tuning.AssemblerMaxDepth)
	sum := summarizer.New(wm)
	bud := budget.New(cfg.TokenCap, cal.BudgetWeightCVSS, cal.BudgetWeightUncert, cal.BudgetWeightDepth)
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
		joern:    jc,
		orch:     orch,
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

	p.logger = slog.New(&eventsHandler{next: p.logger.Handler(), events: events})
	slog.SetDefault(p.logger)

	p.logger.Info("scan started",
		"component", "scan", "target", p.cfg.Target, "mode", p.cfg.ScanMode)

	// Step 0: Joern pre-start
	p.startJoern(ctx, events)

	// Step 1: Ingestion
	ingResult, err := p.runIngestion(ctx, events)
	if err != nil {
		return err
	}
	changedCount := 0
	if ingResult.ChangeSet != nil {
		changedCount = len(ingResult.ChangeSet.Changed)
	}

	// Register project and scan run
	p.registerRun(ctx, ingResult)

	// Step 1.5: CPG build/load + scope resolution
	scopeFiles := p.resolveScope(ctx, ingResult, events)

	// Steps 2+3: Path A ∥ Path B ∥ Orchestrator (parallel detection)
	findCh := make(finding.Channel, 256)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return p.runPathA(gctx, ingResult, scopeFiles, findCh, events) })
	g.Go(func() error { return p.runPathB(gctx, ingResult, findCh, events) })
	g.Go(func() error {
		fs, err := p.orch.Run(gctx, p.cfg.Target)
		if err != nil {
			p.logger.Warn("orchestrator error", "err", err)
			return nil
		}
		for _, f := range fs {
			findCh <- f
		}
		return nil
	})
	var closeOnce sync.Once
	go func() {
		_ = g.Wait()
		closeOnce.Do(func() { close(findCh) })
	}()
	var allFindings []finding.Finding
	for f := range findCh {
		fc := f
		allFindings = append(allFindings, fc)
		output.Emit(events, output.Event{Kind: output.EventFinding, Finding: &fc})
	}
	if err := g.Wait(); err != nil {
		return fmt.Errorf("detection paths: %w", err)
	}

	// Step 4: Dedup + SSVC
	scored, err := p.runDedup(ctx, allFindings, events)
	if err != nil {
		return err
	}

	// Step 4a: Persist findings
	p.persistFindings(ctx, ingResult, scored)

	// Step 5: Patch generation
	if err := p.generatePatches(ctx, scored); err != nil {
		return err
	}

	// Step 6: Report
	p.generateReport(start, scored, events)

	// Commit scan state + finalize
	p.finalize(ctx, ingResult, start, changedCount, scored, events)
	return nil
}

// startJoern spawns the Joern subprocess before ingestion so the JVM is warm.
// Non-fatal: failures disable taint analysis but pattern matching continues.
func (p *pipeline) startJoern(ctx context.Context, events chan<- output.Event) {
	if p.cfg.JoernBin == "" {
		return
	}
	if err := p.joern.Start(ctx); err != nil {
		if errors.Is(err, joern.ErrPortInUse) {
			p.resolvePortConflict(ctx, events)
		} else {
			output.Emit(events, output.Event{
				Kind: output.EventLog,
				Log:  fmt.Sprintf("warn: joern start: %v — taint analysis disabled for this scan", err),
			})
		}
	}
}

// runIngestion runs the ingestion stage and gates LLM calls on MIV block.
func (p *pipeline) runIngestion(ctx context.Context, events chan<- output.Event) (*ingestion.Result, error) {
	output.Emit(events, output.Event{Kind: output.EventStageStart, Stage: "ingestion"})
	ingResult, err := p.ingester.Run(ctx, ingestion.Config{
		ProjectID:   p.cfg.ProjectID,
		ProjectRoot: p.cfg.Target,
		ModelPath:   "",
	})
	if err != nil {
		return nil, fmt.Errorf("ingestion: %w", err)
	}
	if ingResult.BlockLLM {
		p.llm.SetMIVBlocked()
		p.alerts = append(p.alerts, "MIV blocked LLM: analysis degraded to pattern-only path")
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
	return ingResult, nil
}

// registerRun upserts the project record and creates a scan run in SQLite.
func (p *pipeline) registerRun(ctx context.Context, ingResult *ingestion.Result) {
	if p.db == nil {
		return
	}
	if upsertErr := p.db.UpsertProject(ctx, sqlite.ProjectRow{
		ProjectID: ingResult.ProjectID,
		RootPath:  p.cfg.Target,
	}); upsertErr != nil {
		p.logger.Warn("failed to upsert project record", "err", upsertErr)
	}
	if createErr := p.db.CreateScanRun(ctx, sqlite.ScanRunRow{
		RunID:     p.runID,
		ProjectID: ingResult.ProjectID,
		ScanMode:  strings.ToLower(p.cfg.ScanMode),
	}); createErr != nil {
		p.logger.Warn("failed to create scan_run record", "err", createErr)
	}
}

// resolveScope builds or loads the CPG and returns the scope file list.
// Non-fatal: if the CPG cannot be built, scope falls back to the raw changeset
// and taint analysis is disabled.
func (p *pipeline) resolveScope(ctx context.Context, ingResult *ingestion.Result, events chan<- output.Event) []string {
	// Load cached CPG on no-change scans.
	if p.cfg.JoernBin != "" && (ingResult.ChangeSet == nil || len(ingResult.ChangeSet.Changed) == 0) {
		p.loadCachedCPG(ctx, ingResult, events)
	}

	var scopeFiles []string
	if ingResult.ChangeSet != nil && len(ingResult.ChangeSet.Changed) > 0 {
		scopeFiles = p.buildScopeFromChanges(ctx, ingResult, events)
	}

	output.Emit(events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "cpg",
		Summary: &output.StageSummary{
			Stage:  "cpg",
			Detail: fmt.Sprintf("%d files in scope after expansion", len(scopeFiles)),
		},
	})
	return scopeFiles
}

// loadCachedCPG attempts to load a serialized CPG snapshot for no-change scans.
func (p *pipeline) loadCachedCPG(ctx context.Context, ingResult *ingestion.Result, events chan<- output.Event) {
	cpgPath := cpgSnapshotPath(p.cfg.ProjectID)
	if _, statErr := os.Stat(cpgPath); statErr == nil {
		if loadErr := p.joern.LoadCPG(ctx, cpgPath); loadErr != nil {
			p.logger.Warn("joern: failed to load cached CPG on no-change scan", "err", loadErr)
		} else {
			p.logger.Info("joern: loaded cached CPG for no-change scan", "path", cpgPath)
		}
	} else if ingResult.ChangeSet != nil && len(ingResult.ChangeSet.AllStates) > 0 {
		allFiles := make([]string, 0, len(ingResult.ChangeSet.AllStates))
		for _, s := range ingResult.ChangeSet.AllStates {
			allFiles = append(allFiles, s.FilePath)
		}
		p.logger.Info("joern: cached CPG not found — building fresh CPG from all project files",
			"files", len(allFiles))
		if buildErr := p.buildOrLoadCPG(ctx, cpgPath, allFiles, events); buildErr != nil {
			p.logger.Warn("joern: fresh CPG build failed on no-change scan", "err", buildErr)
		}
	}
}

// buildScopeFromChanges builds the CPG for changed files and expands scope via modules.
func (p *pipeline) buildScopeFromChanges(ctx context.Context, ingResult *ingestion.Result, events chan<- output.Event) []string {
	changed := ingResult.ChangeSet.Changed
	modules := joern.DetectWorkingModules(changed)

	if p.cfg.JoernBin == "" {
		return joern.FilterScopeByLanguage(changed)
	}

	graph := p.joern.GraphWithContext(ctx)

	// Pre-flag dangerous sinks in changed files.
	if preFlagErr := p.joern.PreFlagSinks(ctx, changed); preFlagErr != nil {
		p.logger.Warn("sink pre-flagging failed, continuing without pre-flagged sinks",
			"component", "scan", "err", preFlagErr)
	} else {
		p.logger.Info("sink pre-flagging complete",
			"component", "scan", "sinks", len(p.joern.PreFlaggedSinks()))
	}

	cpgPath := cpgSnapshotPath(p.cfg.ProjectID)
	buildErr := p.buildOrLoadCPG(ctx, cpgPath, changed, events)
	if buildErr != nil {
		output.Emit(events, output.Event{
			Kind: output.EventLog,
			Log:  fmt.Sprintf("warn: cpg build: %v — taint analysis disabled", buildErr),
		})
		p.alerts = append(p.alerts, fmt.Sprintf("CPG build failed (%v): taint analysis disabled, pattern-only path active", buildErr))
		return joern.FilterScopeByLanguage(changed)
	}

	depth := moduleDepthForMode(p.cfg.ScanMode)
	if depth > 0 {
		expanded, expandErr := diffindex.ExpandWithCPG(ctx, ingResult.ChangeSet, graph)
		if expandErr != nil {
			p.logger.Error("cpg scope expansion failed, using pre-expansion modules",
				"component", "scan", "err", expandErr)
		} else {
			modules = joern.DetectWorkingModules(expanded.Changed)
		}
		joern.ExpandModuleScope(modules, graph, depth)
	}
	return joern.FilterScopeByLanguage(joern.FlattenScope(modules))
}

// runDedup applies Gate 1-4 dedup and SSVC scoring, emitting stage events.
func (p *pipeline) runDedup(ctx context.Context, allFindings []finding.Finding, events chan<- output.Event) ([]finding.Finding, error) {
	output.Emit(events, output.Event{Kind: output.EventStageStart, Stage: "dedup"})
	scored, err := p.dd.Process(ctx, allFindings)
	if err != nil {
		return nil, fmt.Errorf("dedup: %w", err)
	}
	output.Emit(events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "dedup",
		Summary: &output.StageSummary{
			Stage:  "dedup",
			Detail: fmt.Sprintf("%d findings after dedup", len(scored)),
		},
	})
	return scored, nil
}

// persistFindings writes deduped findings to the SQLite store.
func (p *pipeline) persistFindings(ctx context.Context, ingResult *ingestion.Result, scored []finding.Finding) {
	if p.db == nil || p.runID == "" {
		return
	}
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
				"component", "scan", "finding_id", f.ID, "err", upsertErr)
		}
	}
}

// generatePatches runs patch generation for all scored findings.
func (p *pipeline) generatePatches(ctx context.Context, scored []finding.Finding) error {
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
			scored[i].Patch = pp.UnifiedDiff
			scored[i].PatchStatus = string(pp.Status)
		}
	}
	return nil
}

// generateReport creates the HTML report file from scored findings.
func (p *pipeline) generateReport(start time.Time, scored []finding.Finding, events chan<- output.Event) {
	if err := os.MkdirAll(filepath.Dir(p.cfg.ReportPath), 0o750); err != nil {
		p.logger.Error("failed to create report directory", "err", err)
		return
	}
	f, err := os.Create(p.cfg.ReportPath)
	if err != nil {
		p.logger.Error("failed to create report file", "err", err)
		return
	}
	defer f.Close()

	info := report.ScanInfo{
		ProjectName:  filepath.Base(p.cfg.Target),
		ScannedAt:    start.UTC().Format("2006-01-02 15:04 UTC"),
		ScanMode:     p.cfg.ScanMode,
		ScanDuration: time.Since(start).Round(time.Millisecond).String(),
		Alerts:       p.alerts,
	}
	if err := p.rep.Render(f, info, scored); err != nil {
		p.logger.Error("failed to render report", "err", err)
	}
}

// finalize commits scan state, logs completion stats, and emits EventDone.
func (p *pipeline) finalize(ctx context.Context, ingResult *ingestion.Result, start time.Time, changedCount int, scored []finding.Finding, events chan<- output.Event) {
	if err := p.ingester.CommitScan(ctx, ingResult.ProjectID, ingResult.ChangeSet); err != nil {
		output.Emit(events, output.Event{
			Kind: output.EventLog,
			Log:  fmt.Sprintf("warn: commit scan state: %v", err),
		})
	}

	bySeverity := make(map[finding.SeverityLabel]int, 5)
	for _, s := range scored {
		bySeverity[s.SeverityLabel]++
	}
	elapsed := time.Since(start)
	p.logger.Info("scan complete",
		"component", "scan", "findings", len(scored),
		"elapsed", elapsed, "report", p.cfg.ReportPath)

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
		findings, err := p.opengrep.ScanFiles(gctx, changed)
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

	if err := g.Wait(); err != nil {
		return fmt.Errorf("path a: %w", err)
	}

	for _, f := range rawBuf {
		ch <- f
	}

	output.Emit(events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "path a",
		Summary: &output.StageSummary{
			Stage: "path a",
			Detail: fmt.Sprintf("%d findings", len(rawBuf)),
		},
	})
	return nil
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

	// B3: CodeT5+ Classifier — filter to surfaces that must escalate to LLM.
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

	// B6: Token Budget — now an observer, not a gate.
	// Logs/warns about cost but never suppresses analysis.
	// All surfaces below and above the cap are passed to the LLM scan.
	inputs := buildBudgetInputs(summaries, enriched, clfByID, surfaceByID)
	ranked, exhausted, budStats := p.bud.RankWithStats(inputs)
	if len(exhausted) > 0 {
		slog.Warn(
			"budget: surfaces exceed token cap — scanning all surfaces anyway",
			"exhausted", len(exhausted), "total", budStats.Total,
			"tokens_used_est", budStats.TokensUsed+len(exhausted)*200,
		)
	}
	allSurfaces := append(ranked, p.bud.ExhaustedToRanked(exhausted)...)

	// B7: LLM Semantic Scan.
	llmFindings, err := p.scan.WithStore(p.store).Scan(ctx, allSurfaces)
	if err != nil {
		return fmt.Errorf("path b llm scan: %w", err)
	}
	for _, f := range llmFindings {
		ch <- f
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
			inp.File = s.File
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

// resolvePortConflict handles a Joern ErrPortInUse by attempting to identify
// and optionally kill the process holding the port. If stdin is a terminal
// and the user confirms with 'y', the process is killed and Joern is retried
// once. Otherwise the scan degrades gracefully with a warning.
func (p *pipeline) resolvePortConflict(ctx context.Context, events chan<- output.Event) {
	port := joernPortFromURL(p.cfg.JoernURL)
	if port <= 0 {
		port = 8080
	}

	pid, name, lsofErr := findProcessOnPort(port)
	if lsofErr != nil || pid == 0 {
		output.Emit(events, output.Event{
			Kind: output.EventLog,
			Log:  fmt.Sprintf("warn: joern port %d in use — cannot identify process: %v — taint analysis disabled", port, lsofErr),
		})
		return
	}

	fmt.Fprintf(os.Stderr, "\nJoern port %d is in use by PID %d (%s)\n", port, pid, name)
	fmt.Fprintf(os.Stderr, "Kill it and retry? [y/N] ")

	var buf [1]byte
	var interactive bool
	if stat, statErr := os.Stdin.Stat(); statErr == nil && stat.Mode()&os.ModeCharDevice != 0 {
		_, err := io.ReadFull(os.Stdin, buf[:1])
		interactive = err == nil
	}

	if !interactive || (buf[0] != 'y' && buf[0] != 'Y') {
		fmt.Fprintln(os.Stderr)
		output.Emit(events, output.Event{
			Kind: output.EventLog,
			Log:  fmt.Sprintf("warn: joern port %d in use by PID %d (%s) — taint analysis disabled", port, pid, name),
		})
		return
	}

	if killErr := syscall.Kill(pid, syscall.SIGTERM); killErr != nil {
		output.Emit(events, output.Event{
			Kind: output.EventLog,
			Log:  fmt.Sprintf("warn: failed to kill PID %d on port %d: %v — taint analysis disabled", pid, port, killErr),
		})
		return
	}

	// ponytail: poll until port is free — JVMs take 2–10s to release after SIGTERM
	portAddr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		c, dialErr := net.DialTimeout("tcp", portAddr, 100*time.Millisecond)
		if dialErr != nil {
			break // port is free
		}
		c.Close()
	}

	if retryErr := p.joern.Start(ctx); retryErr != nil {
		output.Emit(events, output.Event{
			Kind: output.EventLog,
			Log:  fmt.Sprintf("warn: joern retry after killing port %d failed: %v — taint analysis disabled", port, retryErr),
		})
	}
}

// joernPortFromURL extracts the TCP port from a Joern URL string.
// Returns 0 if the URL cannot be parsed.
func joernPortFromURL(rawURL string) int {
	if !strings.Contains(rawURL, ":") {
		return 0
	}
	// Strip scheme prefix if present.
	hostPort := rawURL
	if strings.HasPrefix(hostPort, "http://") {
		hostPort = hostPort[7:]
	} else if strings.HasPrefix(hostPort, "https://") {
		hostPort = hostPort[8:]
	}
	// hostPort is now "host:port/path" or "host:port".
	if idx := strings.IndexByte(hostPort, ':'); idx >= 0 {
		rest := hostPort[idx+1:]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			rest = rest[:slash]
		}
		if p, err := strconv.Atoi(rest); err == nil {
			return p
		}
	}
	return 0
}

// findProcessOnPort returns the PID and process name of the process bound to
// the given TCP port. Returns (0, "", error) if the process cannot be identified.
func findProcessOnPort(port int) (int, string, error) {
	if _, err := exec.LookPath("lsof"); err != nil {
		return 0, "", fmt.Errorf("lsof not found: %w", err)
	}
	cmd := exec.Command("lsof", "-ti", "tcp:"+strconv.Itoa(port))
	pidOut, err := cmd.Output()
	if err != nil || len(pidOut) == 0 {
		return 0, "", fmt.Errorf("lsof: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidOut)))
	if err != nil || pid == 0 {
		return 0, "", fmt.Errorf("parse pid from lsof: %w", err)
	}

	nameOut, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return pid, "unknown", nil
	}

	return pid, strings.TrimSpace(string(nameOut)), nil
}

// close shuts down all managed subprocesses and releases held resources.
// Always called after run() returns, even on error.
func (p *pipeline) close() error {
	p.logger.Debug("closing pipeline", "component", "scan", "run_id", p.runID)
	// Stop Joern subprocess if we spawned it. Use a fixed timeout — this runs
	// after the scan; we don't want it to block indefinitely on cleanup.
	if p.cfg.JoernBin != "" && p.joern != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), tuning.JoernScanStopTimeout)
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

// stateDBPath returns the path to the SQLite state file inside the target
// project directory at <target>/.zerotrust/scans.db, creating the directory
// and a .gitignore guard if needed.
func stateDBPath(target string) (string, error) {
	dir := filepath.Join(target, ".zerotrust")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir .zerotrust: %w", err)
	}
	// Ensure scans.db is never accidentally committed.
	giPath := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(giPath); os.IsNotExist(err) {
		_ = os.WriteFile(giPath, []byte("scans.db\nscan_state.db\n"), 0o600)
	}
	return filepath.Join(dir, "scans.db"), nil
}

// ── CPG build helpers ─────────────────────────────────────────────────────────

// maxScopeLOC is the maximum total lines-of-code allowed in the CPG build scope
// before the build is skipped. This keeps build times under the 60 s target.
// If the scope exceeds this limit, a warning is logged and taint analysis is
// skipped for this scan (OpenGrep / ast-grep / instrscan continue unaffected).
const maxScopeLOC = tuning.CPGMaxScopeLOC

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
		p.logger.Warn(
			"could not determine Joern version, proceeding without version check",
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
			ChangedFunctions:   changedFunctions,
			RemovedFiles:       nil, // removed not tracked here
			MaxDepth:           tuning.CPGDefaultMaxDepth,
			HubCallerThreshold: tuning.CPGHubCallerThreshold,
			SerializedCPGPath:  cpgPath,
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

	p.logger.Info(
		"building CPG",
		"component", "cpg",
		"files", len(scopeFiles),
		"loc", loc,
		"target_build_time_seconds", 60,
	)

	buildStart := time.Now()
	// Pre-detect language from file extensions so Joern skips irrelevant
	// frontends (e.g. pysrc2cpg on Java repos breaks on Java 21+).
	detectedLang := joern.DetectProjectLanguage(scopeFiles)
	err = p.joern.BuildCPG(ctx, joern.BuildConfig{
		Paths:             scopeFiles,
		ProjectRoot:       p.cfg.Target,
		Language:          detectedLang,
		SerializedCPGPath: cpgPath,
	})
	buildElapsed := time.Since(buildStart)
	if err != nil {
		p.logger.Error(
			"CPG build failed",
			"component", "cpg",
			"elapsed", buildElapsed,
			"err", err,
		)
		return fmt.Errorf("build cpg: %w", err)
	}

	p.logger.Info(
		"CPG build complete",
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
			p.logger.Warn(
				"failed to persist Joern version snapshot",
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
		return tuning.ModuleDepthThorough
	case "Full":
		return 0 // 0 means no expansion needed — entire codebase is in scope
	default: // Default
		return tuning.ModuleDepthDefault
	}
}

// ── Joern taint analysis ──────────────────────────────────────────────────────

// runJoernTaint performs inter-procedural taint analysis on scopeFiles using
// the Joern CPG graph. Returns normalised Finding structs.
func runJoernTaint(_ context.Context, graph cpg.Graph, scopeFiles []string) ([]finding.Finding, error) {
	slog.Debug("joern taint analysis started", "component", "joern", "scope_files", len(scopeFiles))
	// Detect the primary language from scope files.
	lang, ok := joern.DetectLanguageFromFiles(scopeFiles)
	if !ok {
		slog.Debug("joern taint: no recognisable language detected, skipping", "component", "joern")
		return nil, nil
	}
	// Ensure the language has a taint config.
	if _, hasConfig := joern.TaintConfigs[lang]; !hasConfig {
		slog.Debug("joern taint: no taint config for language, skipping", "component", "joern", "lang", lang)
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
		slog.Debug(
			"joern taint: no sources or sinks found, skipping",
			"component", "joern",
			"sources", len(sources),
			"sinks", len(sinks),
		)
		return nil, nil
	}

	slog.Info(
		"running joern taint analysis",
		"component", "joern",
		"lang", lang,
		"sources", len(sources),
		"sinks", len(sinks),
	)
	// Run the taint analysis.
	paths, err := graph.TaintPaths(sources, sinks)
	if err != nil {
		slog.Error("joern taint paths failed", "component", "joern", "err", err)
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
