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
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
	og := opengrep.New("opengrep", "rules/", logger)
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
	dd := dedup.New()
	pg := patch.New(cfg.Target)
	rg := report.New(cfg.ReportPath)

	return &pipeline{
		cfg:      cfg,
		logger:   logger,
		logFile:  logFile,
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
	scored, err := p.dd.Process(allFindings)
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

	// ── 5. PATCH ──────────────────────────────────────────────────────────────
	patches, err := p.gen.Generate(ctx, scored)
	if err != nil {
		return fmt.Errorf("patch generation: %w", err)
	}
	_ = patches

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

	var changed []string
	if res.ChangeSet != nil {
		changed = res.ChangeSet.Changed
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

	// Emit bypass findings immediately — no LLM cost.
	for _, f := range bypass {
		fc := f
		output.Emit(events, output.Event{Kind: output.EventFinding, Finding: &fc})
		ch <- fc
	}

	// Verify the remainder; degrade gracefully on worker failure.
	if len(needsVerify) > 0 {
		results, err := p.verif.Verify(ctx, needsVerify)
		if err != nil {
			output.Emit(events, output.Event{
				Kind: output.EventLog,
				Log:  fmt.Sprintf("warn: llm verifier: %v — emitting unverified findings", err),
			})
			for _, f := range needsVerify {
				fc := f
				output.Emit(events, output.Event{Kind: output.EventFinding, Finding: &fc})
				ch <- fc
			}
		} else {
			verified := verifier.ApplyResults(needsVerify, results)
			for _, f := range verified {
				fc := f
				output.Emit(events, output.Event{Kind: output.EventFinding, Finding: &fc})
				ch <- fc
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
// findings to ch. Stubs will be filled in ML3.
func (p *pipeline) runPathB(ctx context.Context, _ *ingestion.Result, ch finding.Channel, events chan<- output.Event) error {
	output.Emit(events, output.Event{Kind: output.EventStageStart, Stage: "path b"})
	_ = ctx
	_ = ch
	_ = p.store
	output.Emit(events, output.Event{
		Kind:    output.EventStageEnd,
		Stage:   "path b",
		Summary: &output.StageSummary{Stage: "path b", Detail: "stub — wired in ML3"},
	})
	return nil
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

// buildOrLoadCPG builds a fresh CPG or loads an existing snapshot and applies
// incremental patches. Returns nil on success or an error if the CPG cannot be
// prepared (non-fatal — callers proceed without taint analysis).
func (p *pipeline) buildOrLoadCPG(ctx context.Context, cpgPath string, changedFiles []string, events chan<- output.Event) error {
	if p.joern == nil {
		return fmt.Errorf("joern client not initialized")
	}

	// Check if a prior CPG snapshot exists.
	snapshotExists := false
	if _, err := os.Stat(cpgPath); err == nil {
		snapshotExists = true
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
func (p *pipeline) buildFullCPG(ctx context.Context, cpgPath string, scopeFiles []string) error {
	if len(scopeFiles) == 0 {
		return fmt.Errorf("no files in scope for CPG build")
	}
	err := p.joern.BuildCPG(ctx, joern.BuildConfig{
		Paths:             scopeFiles,
		Language:          "", // auto-detect
		SerializedCPGPath: cpgPath,
	})
	if err != nil {
		return fmt.Errorf("build cpg: %w", err)
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
			// Match against source definitions.
			if _, ok := joern.SourceDefForCall(lang, c.Name); ok {
				sources = append(sources, cpg.TaintSource{
					NodeID: c.ID,
					Kind:   "http_param",
					File:   c.File,
					Line:   c.Line,
				})
			}
			// Match against sink definitions.
			if _, ok := joern.SinkDefForCall(lang, c.Name); ok {
				sinks = append(sinks, cpg.TaintSink{
					NodeID: c.ID,
					Kind:   cpg.SinkSQL, // refined by TaintPaths via classifySinkKind
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
