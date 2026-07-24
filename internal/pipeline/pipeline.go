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
//  2. DETERMINISTIC — OpenGrep + ast-grep + Joern CPG run in parallel goroutines.
//     LLM Verifier filters false positives from pattern findings.
//  3. REASONING — Sequential tier pipeline:
//     Heuristic Targeting → CVE Enrichment → CodeT5+ Classifier →
//     Call Chain Assembler → Semantic Summarizer → Token Budget → LLM Scan.
//     Each tier feeds directly into the next.
//     Scan Security Context Store accumulates inferences across surfaces.
//  4. DEDUP   — Merged findings from both paths de-duplicated and SSVC-scored.
//  5. PATCH   — Patch suggestions generated and validated for BLOCK/HIGH findings.
//  6. REPORT  — Self-contained HTML report written to OutputPath.
//
// Both paths run concurrently (steps 2 and 3 overlap). Reasoning starts as soon as
// the CPG build in Deterministic reports ready; it does not wait for LLM Verifier output.

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
	"github.com/hoangharry-tm/zerotrust/pkg/llm"

	"github.com/hoangharry-tm/zerotrust/internal/cpg_engine"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion/diffindex"
	"github.com/hoangharry-tm/zerotrust/internal/ingestion/miv"
	"github.com/hoangharry-tm/zerotrust/internal/orchestrator"
	"github.com/hoangharry-tm/zerotrust/internal/output"
	"github.com/hoangharry-tm/zerotrust/internal/scanner"
	"github.com/hoangharry-tm/zerotrust/internal/scanner/opengrep"
	analysis "github.com/hoangharry-tm/zerotrust/internal/semantic/analysis"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/contracts"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/crypto"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/triage"
	"github.com/hoangharry-tm/zerotrust/pkg/postgres"
)

// Pipeline holds all constructed stage instances for a single scan.
// It is built by newPipeline and driven by run.
type Pipeline struct {
	cfg     Config
	logger  *slog.Logger
	logFile *os.File

	runID     string
	projectID string
	db        *postgres.DB
	ingester  *ingestion.Ingester

	provider llm.Provider

	// Deterministic — legacy incremental flow
	opengrep *opengrep.Runner
	joern    *cpg_engine.Client
	// orch runs the dynamic tool dispatcher concurrently with Joern CPG init.
	orch *orchestrator.Engine

	// Reasoning
	target        *targeting.Targeter
	enrich        *enrichment.Enricher
	checker       *contracts.Checker
	triager       *triage.Triager
	scan          *analysis.Scanner
	cryptoChecker *crypto.Checker

	// degradation alerts surfaced during the scan (logged, no report to render into)
	alerts []string

	// shared
	dd     *dedup.Layer
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

// New constructs the full pipeline from cfg.
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

	// Structured logger — JSON lines written to build/zerotrust.log.
	// Also set as slog.Default so all slog.* calls in every package flow to the log file
	// (and optionally to stderr when --verbose is active).
	logDir := "build"
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

	// Ingestion layer — Postgres state cache + DiffIndex + MIV.
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("open state db: %w", err)
	}
	runID := newRunID()
	indexer := diffindex.New(db, logger)
	mivVer := miv.New("", "", logger)
	ingester := ingestion.New(indexer, mivVer)

	// LLM provider — provider-agnostic; backend selected via cfg.LLMProvider.
	llmProvider, err := llm.New(llm.Config{
		Provider: llm.ProviderKind(cfg.LLMProvider),
		BaseURL:  cfg.LLMBaseURL,
		Model:    cfg.ModelName,
		APIKey:   cfg.LLMAPIKey,
		Timeout:  600 * time.Second, // ponytail: 8192 num_predict for B5 needs up to ~480s; 600s gives margin
	})
	if err != nil {
		return nil, fmt.Errorf("llm: %w", err)
	}

	// Deterministic
	og := opengrep.NewMulti(scanner.BinarySpec{Name: "opengrep"}, logger).
		WithExclude(".github", "test", "tests", "it")
	orch := orchestrator.New(
		scanner.NewGitleaks(scanner.BinarySpec{Name: "gitleaks"}),
		scanner.NewOSV(scanner.BinarySpec{Name: "osv-scanner"}),
	)
	joernOpts := []cpg_engine.Option{cpg_engine.WithServerURL(cfg.JoernURL)}
	if cfg.JoernBin != "" {
		joernOpts = append(joernOpts, cpg_engine.WithBinaryPath(cfg.JoernBin))
	}
	if secs := ztCfg.JoernQueryTimeoutSeconds; secs > 0 {
		joernOpts = append(joernOpts, cpg_engine.WithQueryTimeout(time.Duration(secs)*time.Second))
	}
	if mb := ztCfg.JoernMaxHeapMB; mb > 0 {
		joernOpts = append(joernOpts, cpg_engine.WithMaxHeapMB(mb))
	}
	jc, err := cpg_engine.New(joernOpts...)
	if err != nil {
		return nil, fmt.Errorf("configure joern: %w", err)
	}

	// Reasoning — graph shared from Joern after CPG build
	graph := jc.GraphWithContext(ctx)
	tgt := targeting.New(graph, cfg.Target)
	enr := enrichment.New(graph, "trivy", false) // CVE enrichment always attempts network lookup
	// NewWithEscalation: Contracts asks one scoped yes/no question (via the
	// same LLM provider as Triage/Analysis) only for the narrow case where a
	// confirmed taint path isn't sanitized by CPG structure or keyword —
	// never a general "does this look vulnerable" prompt. See the Checker
	// doc comment in internal/semantic/contracts for the asymmetric-trust
	// rule this follows.
	cc := contracts.NewWithEscalation(llmProvider).WithRoot(cfg.Target).WithGraph(graph)
	cc2 := crypto.New()
	tr := triage.New(llmProvider, cfg.TriageThreshold)
	sc := analysis.New(llmProvider).WithRoot(cfg.Target).WithGraph(graph)

	dd := dedup.New(cfg.Target)

	return &Pipeline{
		cfg:           cfg,
		logger:        logger,
		logFile:       logFile,
		runID:         runID,
		db:            db,
		ingester:      ingester,
		provider:      llmProvider,
		opengrep:      og,
		joern:         jc,
		orch:          orch,
		target:        tgt,
		enrich:        enr,
		checker:       cc,
		cryptoChecker: cc2,
		triager:       tr,
		scan:          sc,
		dd:            dd,
	}, nil
}

// StartScanProcess executes the full pipeline to completion, persisting
// scored findings to the database. events receives stage notifications
// consumed by the active CLI renderer (may be nil). The caller is
// responsible for closing events after it returns.
func (p *Pipeline) StartScanProcess(
	ctx context.Context,
	events chan<- output.Event,
) ([]finding.Finding, error) {
	p.events = events
	start := time.Now()

	p.logger = slog.New(&eventsHandler{next: p.logger.Handler(), events: events})
	slog.SetDefault(p.logger)

	p.logger.Info("scan started",
		"component", "scan", "target", p.cfg.Target, "mode", p.cfg.ScanMode)

	// Prewarm Targeting's import-boundary classification (Phase 1 of
	// Targeter.Run) as early as possible — it's pure Go/AST over the source
	// tree with no CPG or ingestion dependency, so there's no reason to make
	// it wait behind Joern startup, CPG build, and ingestion the way it
	// would if Reasoning only computed it when Targeter.Run is eventually
	// called. Fire-and-forget: Targeter.Run falls back to computing it
	// itself if this hasn't finished (or failed) by the time Reasoning
	// actually needs it, so a failure here is non-fatal.
	go func() {
		if err := p.target.PrewarmImportBoundaries(ctx); err != nil {
			p.logger.Debug("prewarm import boundaries failed — Targeting will compute it inline", "err", err)
		}
	}()

	// Step 0: Joern pre-start
	p.startJoern(ctx)

	// Step 1: Ingestion — MIV + DiffIndex + CPG build
	ingResult, err := p.runIngestion(ctx)
	if err != nil {
		return nil, err
	}
	p.registerRun(ctx, ingResult)
	if p.db != nil {
		p.dd.SetDB(p.db, ingResult.ProjectID)
	}
	scopeFiles := p.resolveScope(ctx, ingResult)

	// Steps 2+3: Deterministic ∥ Reasoning ∥ Orchestrator (parallel detection)
	findCh := make(finding.Channel, 256)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return p.runDeterministic(gctx, ingResult, scopeFiles, findCh) })
	g.Go(func() error { return p.runReasoning(gctx, ingResult, findCh) })
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
		return nil, fmt.Errorf("detection paths: %w", err)
	}

	scored, err := p.runDedup(ctx, allFindings)
	if err != nil {
		return nil, err
	}

	p.persistFindings(ctx, ingResult, scored)

	changedCount := 0
	if ingResult != nil && ingResult.ChangeSet != nil {
		changedCount = len(ingResult.ChangeSet.Changed)
	}
	p.finalize(ctx, ingResult, start, changedCount, scored)
	return scored, nil
}

// Provider returns the pipeline's configured LLM provider, for post-scan
// stages driven from main.go (patch generation, PoE verification) that need
// the same provider without reconstructing it.
func (p *Pipeline) Provider() llm.Provider { return p.provider }

// Graph returns the shared CPG graph, for post-scan stages (PoE verification)
// that need call-graph queries after StartScanProcess has returned.
func (p *Pipeline) Graph() cpg_engine.Graph { return p.joern.GraphWithContext(context.Background()) }

// startJoern spawns the Joern subprocess before ingestion so the JVM is warm.
// Non-fatal: failures disable taint analysis but pattern matching continues.
func (p *Pipeline) startJoern(ctx context.Context) {
	if p.cfg.JoernBin == "" {
		// JoernBin empty means "connect to an externally managed server at
		// JoernURL instead" — but that's a real, deliberate config choice,
		// not the common case. Most callers (including the CLI's default,
		// which never sets --joern-bin) land here by omission, and without
		// this warning the entire CPG/taint-analysis path (Deterministic's
		// Joern half, all of Reasoning, PoE route resolution) silently
		// no-ops for the whole scan — the operator sees pattern-only
		// findings with zero indication CPG analysis never ran.
		p.logger.Warn("JoernBin not set — assuming an externally managed Joern server is already running at JoernURL; CPG/taint analysis will silently produce nothing if it isn't",
			"joern_url", p.cfg.JoernURL)
		return
	}
	if err := p.joern.Start(ctx); err != nil {
		if errors.Is(err, cpg_engine.ErrPortInUse) {
			p.resolvePortConflict(ctx)
		} else {
			p.logger.Warn("joern start failed — taint analysis disabled for this scan", "err", err)
		}
	}
}

// MVP: runIngestion, registerRun, resolveScope bypassed.
// Implementations preserved below — uncomment bodies to re-enable after demo.

func (p *Pipeline) runIngestion(ctx context.Context) (*ingestion.Result, error) {
	output.Emit(p.events, output.Event{Kind: output.EventStageStart, Stage: "ingestion"})
	ingResult, err := p.ingester.Run(ctx, ingestion.Config{
		ProjectID:   p.cfg.ProjectID,
		ProjectRoot: p.cfg.Target,
	})
	if err != nil {
		return nil, fmt.Errorf("ingestion: %w", err)
	}
	if ingResult.BlockLLM {
		llm.SetProviderMIVBlocked(p.provider)
		p.alerts = append(p.alerts, "MIV blocked LLM")
	}

	// Build the CPG for the ingestion result's scope.
	cpgPath := cpgSnapshotPath(p.cfg.ProjectID)
	changedFiles := ingResult.ChangeSet.Changed
	if len(changedFiles) == 0 {
		// No changes detected — use full target as scope for initial full scan
		changedFiles = []string{p.cfg.Target}
	}
	if buildErr := p.buildOrLoadCPG(ctx, ingResult.ProjectID, cpgPath, changedFiles); buildErr != nil {
		p.logger.Warn("CPG build during ingestion failed — Reasoning will be degraded", "err", buildErr)
		// Non-fatal: Deterministic still runs, Reasoning runs with limited taint analysis
	}

	// Pre-flag dangerous sinks so TaintPaths has seeds to work with.
	sinkFiles := changedFiles
	if len(sinkFiles) == 1 && sinkFiles[0] == p.cfg.Target {
		// Full scan: walk target for source files instead of passing the directory
		sinkFiles = []string{p.cfg.Target}
	}
	if pfErr := p.joern.PreFlagSinks(ctx, sinkFiles); pfErr != nil {
		p.logger.Warn("sink pre-flagging failed", "err", pfErr)
	} else {
		p.logger.Info("sink pre-flagging complete", "sinks", len(p.joern.PreFlaggedSinks()))
	}

	output.Emit(p.events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "ingestion",
		Summary: &output.StageSummary{
			Stage:  "ingestion",
			Detail: fmt.Sprintf("project_id=%s changed=%d", ingResult.ProjectID, len(changedFiles)),
		},
	})
	return ingResult, nil
}

func (p *Pipeline) registerRun(ctx context.Context, ingResult *ingestion.Result) {
	if p.db == nil {
		return
	}
	projectID := p.cfg.Target
	if ingResult != nil && ingResult.ProjectID != "" {
		projectID = ingResult.ProjectID
	}
	p.projectID = projectID
	if _, err := p.db.UpsertProject(ctx, postgres.ProjectRow{
		ProjectID:     projectID,
		RootPath:      p.cfg.Target,
		LastScannedAt: time.Now().Unix(),
	}); err != nil {
		p.logger.Warn("registerRun: failed to upsert project", "err", err)
	}
	if err := p.db.CreateScanRun(ctx, postgres.ScanRunRow{
		RunID:     p.runID,
		ProjectID: projectID,
		ScanMode:  p.cfg.ScanMode,
	}); err != nil {
		p.logger.Warn("registerRun: failed to create scan run", "err", err)
	}
	p.logger.Debug("registered run", "project_id", projectID, "run_id", p.runID)
}

func (p *Pipeline) resolveScope(ctx context.Context, ingResult *ingestion.Result) []string {
	// Build incremental scope from DiffIndex changeset.
	// If no changes detected, returns the full target for full-scan mode.
	if ingResult == nil || ingResult.ChangeSet == nil || len(ingResult.ChangeSet.Changed) == 0 {
		return []string{p.cfg.Target}
	}
	var scopeFiles []string
	for _, rel := range ingResult.ChangeSet.Changed {
		scopeFiles = append(scopeFiles, filepath.Join(p.cfg.Target, rel))
	}
	p.logger.Debug("resolved scope", "files", len(scopeFiles))
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

// persistFindings upserts every scored finding into the findings table under
// the current run. Best-effort: a write failure is logged, not fatal — the
// scan already succeeded, and the DB is a durability layer, not the pipeline
// itself.
func (p *Pipeline) persistFindings(ctx context.Context, ingResult *ingestion.Result, scored []finding.Finding) {
	if p.db == nil || p.runID == "" || ingResult == nil {
		return
	}
	now := time.Now().Unix()
	for i := range scored {
		f := &scored[i]
		row := postgres.FindingRow{
			FindingID: f.ID, ProjectID: ingResult.ProjectID, RunID: p.runID,
			FilePath: f.Path, LineStart: f.LineRange.Start, LineEnd: f.LineRange.End,
			CWE: f.CWE, Severity: f.SeverityLabel.String(), Confidence: f.Confidence,
			SourcePath: string(f.SourcePath), RuleID: f.RuleID, MatchedCode: f.MatchedCode,
			Justification: f.Justification, SuppressReason: string(f.SuppressReason),
			Patch: f.Patch, PatchStatus: f.PatchStatus,
			FirstSeenAt: now, LastSeenAt: now,
		}
		if err := p.db.UpsertFinding(ctx, row); err != nil {
			p.logger.Warn("failed to persist finding", "finding_id", f.ID, "err", err)
			continue // ssvc_scores/poe_results FK-reference findings; skip if the parent row failed
		}

		if f.SSVC != (finding.SSVCDimensions{}) {
			if err := p.db.UpsertSSVCScore(ctx, postgres.SSVCScoreRow{
				FindingID: f.ID, Exploitation: f.SSVC.Exploitation,
				Automatable: f.SSVC.Automatable, TechnicalImpact: f.SSVC.TechnicalImpact,
			}); err != nil {
				p.logger.Warn("failed to persist SSVC score", "finding_id", f.ID, "err", err)
			}
		}

		if f.PoEResult != nil {
			if err := p.db.UpsertPoEResult(ctx, postgres.PoEResultRow{
				FindingID: f.ID, Status: string(f.PoEResult.Status),
				Confidence: f.PoEResult.Confidence, BusinessImpactTier: f.PoEResult.BusinessImpactTier,
				ExecSummary: f.PoEResult.ExecSummary,
			}); err != nil {
				p.logger.Warn("failed to persist PoE result", "finding_id", f.ID, "err", err)
			}
		}
	}
}

// PersistPoEResults writes PoE verdicts back to Postgres for findings that
// were verified. This is deliberately a separate call from persistFindings,
// not folded into StartScanProcess: PoE verification is a post-scan,
// opt-in step driven from main.go via Provider()/Graph() (it needs the
// caller-supplied --poe-artifact path, which the pipeline itself has no
// reason to know about). But persistFindings already upserted every
// finding's row — including a nil poe_results row — by the time PoE runs,
// so without this second write, poe_results and the boosted
// confidence/severity on a PoESuccess never reach the database at all,
// silently defeating the point of persisting them in the first place. Call
// this after Verifier.Run, before process exit.
func (p *Pipeline) PersistPoEResults(ctx context.Context, scored []finding.Finding) {
	if p.db == nil || p.runID == "" {
		return
	}
	for i := range scored {
		f := &scored[i]
		if f.PoEResult == nil {
			continue
		}
		if err := p.db.UpsertFinding(ctx, postgres.FindingRow{
			FindingID: f.ID, ProjectID: p.projectID, RunID: p.runID,
			FilePath: f.Path, LineStart: f.LineRange.Start, LineEnd: f.LineRange.End,
			CWE: f.CWE, Severity: f.SeverityLabel.String(), Confidence: f.Confidence,
			SourcePath: string(f.SourcePath), RuleID: f.RuleID, MatchedCode: f.MatchedCode,
			Justification: f.Justification, SuppressReason: string(f.SuppressReason),
			Patch: f.Patch, PatchStatus: f.PatchStatus,
		}); err != nil {
			p.logger.Warn("failed to persist PoE-updated finding", "finding_id", f.ID, "err", err)
			continue
		}
		if err := p.db.UpsertPoEResult(ctx, postgres.PoEResultRow{
			FindingID: f.ID, Status: string(f.PoEResult.Status),
			Confidence: f.PoEResult.Confidence, BusinessImpactTier: f.PoEResult.BusinessImpactTier,
			ExecSummary: f.PoEResult.ExecSummary,
		}); err != nil {
			p.logger.Warn("failed to persist PoE result", "finding_id", f.ID, "err", err)
		}
	}
}

// finalize commits the ingestion changeset, finalizes the scan_run row, and
// emits the completion event.
func (p *Pipeline) finalize(ctx context.Context, ingResult *ingestion.Result, start time.Time, changedCount int, scored []finding.Finding) {
	if ingResult != nil {
		if err := p.ingester.CommitScan(ctx, ingResult.ProjectID, ingResult.ChangeSet); err != nil {
			p.logger.Warn("commit scan state failed", "err", err)
		}
	}
	elapsed := time.Since(start)
	p.logger.Info("scan complete", "component", "scan", "findings", len(scored), "elapsed", elapsed)
	if p.db != nil && p.runID != "" {
		if err := p.db.FinalizeScanRun(ctx, p.runID, time.Now().Unix(), changedCount, len(scored)); err != nil {
			p.logger.Warn("failed to finalize scan_run", "component", "scan", "err", err)
		}
	}
	p.emitDone(start, scored)
}

// emitDone logs scan completion and emits EventDone.
func (p *Pipeline) emitDone(start time.Time, scored []finding.Finding) {
	bySeverity := make(map[finding.SeverityLabel]int, 5)
	for _, s := range scored {
		bySeverity[s.SeverityLabel]++
	}
	elapsed := time.Since(start)
	p.logger.Info("scan complete",
		"component", "scan", "findings", len(scored), "elapsed", elapsed)
	output.Emit(p.events, output.Event{
		Kind: output.EventDone,
		Done: &output.ScanSummary{
			Elapsed:       elapsed,
			TotalFindings: len(scored),
			BySeverity:    bySeverity,
		},
	})
}

// runDeterministic executes all Deterministic detectors concurrently, then runs the LLM Verifier
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
// isTestPath reports whether path is inside a test source tree and should be
// excluded from pattern scanning. opengrep --exclude is ignored for explicit
// file paths (only applies to directory tree scans), so we filter in Go.
func isTestPath(path string) bool {
	return strings.Contains(path, "/src/test/") ||
		strings.Contains(path, "/src/it/") ||
		strings.Contains(path, "/test/java/") ||
		strings.Contains(path, "/tests/java/")
}

func (p *Pipeline) runDeterministic(ctx context.Context, res *ingestion.Result, scopeFiles []string, ch chan<- finding.Finding) error {
	output.Emit(p.events, output.Event{Kind: output.EventStageStart, Stage: "deterministic"})

	// DiffIndex returns paths relative to the project root; make them absolute
	// so subprocess scanners (opengrep, ast-grep) can find them from any CWD.
	var changed []string
	if res != nil && res.ChangeSet != nil {
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
			p.logger.Warn("joern taint analysis failed", "err", err)
			return nil
		}
		collect(findings)
		return nil
	})

	// 1. OpenGrep — owns Python/Java/JS/TS/Go/Ruby/PHP.
	// Full-scan mode (no changed files): use Scan on the target directory.
	// Incremental mode (changed files present): use ScanFiles on the diff.
	g.Go(func() error {
		var findings []finding.Finding
		var err error
		if len(changed) > 0 {
			// ponytail: opengrep --exclude is ignored for explicit file paths; filter in Go.
			filtered := make([]string, 0, len(changed))
			for _, p := range changed {
				if !isTestPath(p) {
					filtered = append(filtered, p)
				}
			}
			findings, err = p.opengrep.ScanFiles(gctx, filtered)
		} else {
			findings, err = p.opengrep.Scan(gctx, p.cfg.Target)
		}
		if err != nil {
			p.logger.Warn("opengrep scan failed", "err", err)
			return nil
		}
		collect(findings)
		return nil
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("deterministic: %w", err)
	}

	for _, f := range rawBuf {
		ch <- f
	}

	output.Emit(p.events, output.Event{
		Kind:  output.EventStageEnd,
		Stage: "deterministic",
		Summary: &output.StageSummary{
			Stage:  "deterministic",
			Detail: fmt.Sprintf("%d findings", len(rawBuf)),
		},
	})
	return nil
}

// runReasoning executes the Reasoning semantic detection tier pipeline and writes
// findings to ch. Returns nil when Joern CPG is unavailable (0 surfaces selected).
func (p *Pipeline) Close() error {
	p.logger.Debug("closing pipeline", "component", "scan")
	if p.cfg.JoernBin != "" && p.joern != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), config.JoernScanStopTimeout)
		defer cancel()
		_ = p.joern.Stop(stopCtx) //nolint:errcheck // best-effort cleanup
	}
	if p.db != nil {
		_ = p.db.Close() //nolint:errcheck // best-effort cleanup
	}
	if p.logFile != nil {
		_ = p.logFile.Close() //nolint:errcheck
	}
	return nil
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
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x", b)
}
