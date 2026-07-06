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

package pipeline

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
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/hoangharry-tm/zerotrust/internal/config"
	"github.com/hoangharry-tm/zerotrust/internal/dedup"
	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion/diffindex"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion/miv"
	"github.com/hoangharry-tm/zerotrust/internal/orchestrator"
	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/patch"
	"github.com/hoangharry-tm/zerotrust/internal/report"
	"github.com/hoangharry-tm/zerotrust/internal/scanner"
	"github.com/hoangharry-tm/zerotrust/internal/scanner/joern"
	"github.com/hoangharry-tm/zerotrust/internal/scanner/opengrep"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/llmscan"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/internal/tuning"
	"github.com/hoangharry-tm/zerotrust/pkg/ollama"
	"github.com/hoangharry-tm/zerotrust/pkg/sqlite"
)

// pipeline holds all constructed stage instances for a single scan.
// It is built by newPipeline and driven by run.
type Pipeline struct {
	cfg     Config
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
	scan   *llmscan.Scanner

	// degradation alerts surfaced in the HTML report header
	alerts []string

	// shared
	dd     *dedup.Layer
	gen    *patch.Generator
	rep    *report.Generator
	events chan<- output.Event
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
	if r.Level >= slog.LevelInfo && h.events != nil {
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
func New(ctx context.Context, cfg Config) (*Pipeline, error) {
	cfg.defaults()

	ztCfg, err := config.Load(cfg.CalibrationPath)
	if err != nil {
		return nil, fmt.Errorf("load calibration: %w", err)
	}
	config.Set(ztCfg)
	if cfg.CalibrationPath != "" {
		// ponytail: parent env inherits to exec.Command subprocess
		_ = os.Setenv("ZT_CONFIG_PATH", cfg.CalibrationPath)
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
	if secs := ztCfg.JoernQueryTimeoutSeconds; secs > 0 {
		joernOpts = append(joernOpts, joern.WithQueryTimeout(time.Duration(secs)*time.Second))
	}
	jc, err := joern.New(joernOpts...)
	if err != nil {
		return nil, fmt.Errorf("configure joern: %w", err)
	}

	// Path B — graph shared from Joern after CPG build
	graph := jc.GraphWithContext(ctx)
	tgt := targeting.New(graph, cfg.Target)
	enr := enrichment.New(graph, "trivy", cfg.Offline)
	sc := llmscan.New(llmClient)

	// Output — cross-scan dedup DB is wired after ingestion when projectID is resolved
	dd := dedup.New(cfg.Target)
	pg := patch.New(cfg.Target)
	rg := report.New(cfg.ReportPath)

	return &Pipeline{
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
		scan:     sc,
		dd:       dd,
		gen:      pg,
		rep:      rg,
	}, nil
}

// run executes the full pipeline to completion and writes the HTML report.
// events receives stage notifications consumed by the active CLI renderer.
// The caller is responsible for closing events after run returns.
func (p *Pipeline) Run(ctx context.Context, events chan<- output.Event) error {
	p.events = events
	start := time.Now()

	p.logger = slog.New(&eventsHandler{next: p.logger.Handler(), events: events})
	slog.SetDefault(p.logger)

	p.logger.Info("scan started",
		"component", "scan", "target", p.cfg.Target, "mode", p.cfg.ScanMode)

	// Step 0: Joern pre-start
	p.startJoern(ctx)

	// Step 1: Ingestion
	ingResult, err := p.runIngestion(ctx)
	if err != nil {
		return err
	}
	changedCount := 0
	if ingResult.ChangeSet != nil {
		changedCount = len(ingResult.ChangeSet.Changed)
	}

	// Register project and scan run
	p.registerRun(ctx, ingResult)

	// Wire cross-scan dedup now that projectID is resolved.
	// This enables the dedup layer to skip findings already persisted
	// from prior scans using a lightweight SQLite query.
	if p.db != nil {
		p.dd.SetDB(p.db, ingResult.ProjectID)
	}

	// Step 1.5: CPG build/load + scope resolution
	scopeFiles := p.resolveScope(ctx, ingResult)

	// Steps 2+3: Path A ∥ Path B ∥ Orchestrator (parallel detection)
	findCh := make(finding.Channel, 256)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return p.runPathA(gctx, ingResult, scopeFiles, findCh) })
	g.Go(func() error { return p.runPathB(gctx, ingResult, findCh) })
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
		output.Emit(p.events, output.Event{Kind: output.EventFinding, Finding: &fc})
	}
	if err := g.Wait(); err != nil {
		return fmt.Errorf("detection paths: %w", err)
	}

	// Step 4: Dedup + SSVC
	scored, err := p.runDedup(ctx, allFindings)
	if err != nil {
		return err
	}

	// Step 4a: Persist findings
	p.persistFindings(ctx, ingResult, scored)

	// Step 5: Patch generation
	if err := p.generatePatches(ctx, scored); err != nil {
		return err
	}
	p.persistPatches(ctx, scored)

	// Step 6: Report
	p.generateReport(start, scored)

	// Commit scan state + finalize
	p.finalize(ctx, ingResult, start, changedCount, scored)
	return nil
}

// startJoern spawns the Joern subprocess before ingestion so the JVM is warm.
// Non-fatal: failures disable taint analysis but pattern matching continues.
func (p *Pipeline) startJoern(ctx context.Context) {
	if p.cfg.JoernBin == "" {
		return
	}
	if err := p.joern.Start(ctx); err != nil {
		if errors.Is(err, joern.ErrPortInUse) {
			p.resolvePortConflict(ctx)
		} else {
			output.Emit(p.events, output.Event{
				Kind: output.EventLog,
				Log:  fmt.Sprintf("warn: joern start: %v — taint analysis disabled for this scan", err),
			})
		}
	}
}

// runIngestion runs the ingestion stage and gates LLM calls on MIV block.
func (p *Pipeline) runIngestion(ctx context.Context) (*ingestion.Result, error) {
	output.Emit(p.events, output.Event{Kind: output.EventStageStart, Stage: "ingestion"})
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
	output.Emit(p.events, output.Event{
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
// ingResult.ProjectID may be updated to the reconciled project_id when an
// existing project row for the same root_path uses a different identifier.
func (p *Pipeline) registerRun(ctx context.Context, ingResult *ingestion.Result) {
	if p.db == nil {
		return
	}
	effectiveID, upsertErr := p.db.UpsertProject(ctx, sqlite.ProjectRow{
		ProjectID: ingResult.ProjectID,
		RootPath:  p.cfg.Target,
	})
	if upsertErr != nil {
		p.logger.Warn("failed to upsert project record", "err", upsertErr)
	} else {
		ingResult.ProjectID = effectiveID
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
func (p *Pipeline) resolveScope(ctx context.Context, ingResult *ingestion.Result) []string {
	// Load cached CPG on no-change scans.
	if p.cfg.JoernBin != "" && (ingResult.ChangeSet == nil || len(ingResult.ChangeSet.Changed) == 0) {
		p.loadCachedCPG(ctx, ingResult)
	}

	var scopeFiles []string
	if ingResult.ChangeSet != nil && len(ingResult.ChangeSet.Changed) > 0 {
		scopeFiles = p.buildScopeFromChanges(ctx, ingResult)
	}

	output.Emit(p.events, output.Event{
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
func (p *Pipeline) runDedup(ctx context.Context, allFindings []finding.Finding) ([]finding.Finding, error) {
	output.Emit(p.events, output.Event{Kind: output.EventStageStart, Stage: "dedup"})
	scored, err := p.dd.Process(ctx, allFindings)
	if err != nil {
		return nil, fmt.Errorf("dedup: %w", err)
	}
	output.Emit(p.events, output.Event{
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
func (p *Pipeline) persistFindings(ctx context.Context, ingResult *ingestion.Result, scored []finding.Finding) {
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

// persistPatches writes generated patch text back to the DB so curate.py can
// read them without re-invoking Ollama.
func (p *Pipeline) persistPatches(ctx context.Context, scored []finding.Finding) {
	if p.db == nil {
		return
	}
	for i := range scored {
		f := &scored[i]
		if f.Patch == "" {
			continue
		}
		if err := p.db.UpdateFindingPatch(ctx, f.ID, f.Patch, f.PatchStatus); err != nil {
			p.logger.Warn("failed to cache patch", "finding_id", f.ID, "err", err)
		}
	}
}

// generatePatches runs patch generation for all scored findings.
func (p *Pipeline) generatePatches(ctx context.Context, scored []finding.Finding) error {
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
func (p *Pipeline) generateReport(start time.Time, scored []finding.Finding) {
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
func (p *Pipeline) finalize(ctx context.Context, ingResult *ingestion.Result, start time.Time, changedCount int, scored []finding.Finding) {
	if err := p.ingester.CommitScan(ctx, ingResult.ProjectID, ingResult.ChangeSet); err != nil {
		output.Emit(p.events, output.Event{
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

	output.Emit(p.events, output.Event{
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
func (p *Pipeline) runPathA(ctx context.Context, res *ingestion.Result, scopeFiles []string, ch finding.Channel) error {
	output.Emit(p.events, output.Event{Kind: output.EventStageStart, Stage: "path a"})

	// DiffIndex returns paths relative to the project root; make them absolute
	// so subprocess scanners (opengrep, ast-grep) can find them from any CWD.
	var changed []string
	if res.ChangeSet != nil {
		for _, rel := range res.ChangeSet.Changed {
			changed = append(changed, filepath.Join(p.cfg.Target, rel))
		}
	}

	// Incremental bypass: no changed files and no scope → nothing to scan.
	if len(changed) == 0 && len(scopeFiles) == 0 {
		slog.Debug("path a: no files changed or in scope, skipping")
		output.Emit(p.events, output.Event{
			Kind:  output.EventStageEnd,
			Stage: "path a",
			Summary: &output.StageSummary{
				Stage:  "path a",
				Detail: "bypassed: no files changed",
			},
		})
		return nil
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
			output.Emit(p.events, output.Event{
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
			output.Emit(p.events, output.Event{
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

	output.Emit(p.events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "path a",
		Summary: &output.StageSummary{
			Stage:  "path a",
			Detail: fmt.Sprintf("%d findings", len(rawBuf)),
		},
	})
	return nil
}

// runPathB executes the Path B semantic detection tier pipeline and writes
// findings to ch. Returns nil when Joern CPG is unavailable (0 surfaces selected).
func (p *Pipeline) Close() error {
	p.logger.Debug("closing pipeline", "component", "scan", "run_id", p.runID)
	// Stop Joern subprocess if we spawned it. Use a fixed timeout — this runs
	// after the scan; we don't want it to block indefinitely on cleanup.
	if p.cfg.JoernBin != "" && p.joern != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), tuning.JoernScanStopTimeout)
		defer cancel()
		_ = p.joern.Stop(stopCtx) //nolint:errcheck // best-effort cleanup
	}

	if p.db != nil {
		_ = p.db.Close() //nolint:errcheck // best-effort; SQLite WAL checkpoint on close
	}
	if p.logFile != nil {
		_ = p.logFile.Close() //nolint:errcheck // best-effort log file close on scan end
	}
	return nil
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

// countLOC returns the total line count across all given files.
// Files that cannot be read or opened are silently skipped.
func newRunID() string {
	var b [8]byte
	_, _ = rand.Read(b[:]) //nolint:errcheck
	return fmt.Sprintf("%x", b)
}
