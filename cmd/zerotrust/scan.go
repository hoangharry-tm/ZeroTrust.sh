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
	"github.com/hoangharry-tm/zerotrust/pkg/sqlite"
)

// pipeline holds all constructed stage instances for a single scan.
// It is built by newPipeline and driven by run.
type pipeline struct {
	cfg ScanConfig

	// ingestion
	ingester *ingestion.Ingester

	// Path A
	opengrep *opengrep.Runner
	astgrep  *astgrep.Runner
	joern    *joern.Client
	instr    *instrscan.Scanner
	verif    *verifier.Verifier

	// Path B
	target  *targeting.Targeter
	enrich  *enrichment.Enricher
	clf     *classifier.Gate
	asm     *assembler.Assembler
	sum     *summarizer.Summarizer
	bud     *budget.Controller
	scan    *llmscan.Scanner
	store   *scs.Store

	// shared
	w    *worker.Manager
	dd   *dedup.Layer
	gen  *patch.Generator
	rep  *report.Generator
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

	// SQLite state cache at ~/.zerotrust/scans.db
	dbPath, err := stateDBPath()
	if err != nil {
		return nil, err
	}
	db, err := sqlite.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	_ = db

	// Python worker — started once, shared by verifier, classifier, summarizer, llmscan.
	wm, err := worker.Start(ctx, "worker/main.py")
	if err != nil {
		return nil, fmt.Errorf("start python worker: %w", err)
	}

	// Ingestion layer
	indexer := diffindex.New(db)
	mivVer := miv.New("", "") // paths resolved from embedded registry in G2
	ingester := ingestion.New(indexer, mivVer)

	// Path A
	og := opengrep.New("opengrep", "rules/")
	ag := astgrep.New("ast-grep", "rules/astgrep/")
	jc := joern.New(cfg.JoernURL)
	is := instrscan.New()
	vf := verifier.New(wm)

	// Path B — graph shared from Joern after CPG build
	graph := jc.Graph()
	tgt := targeting.New(graph)
	enr := enrichment.New(graph, "trivy", cfg.Offline)
	clf := classifier.New(wm)
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
		ingester: ingester,
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

	// ── 2 + 3. PATH A ∥ PATH B ───────────────────────────────────────────────
	// Both paths write findings to a shared buffered channel; results are
	// collected by the drain goroutine below. Neither path gates the other.
	findCh := make(finding.Channel, 256)

	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer func() { /* Path A done; Path B may still be running */ }()
		return p.runPathA(gctx, ingResult, findCh, events)
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
	if err := os.MkdirAll(filepath.Dir(p.cfg.ReportPath), 0o755); err != nil {
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

	// Build per-severity counts for the done summary.
	bySeverity := make(map[finding.SeverityLabel]int, 5)
	for _, s := range scored {
		bySeverity[s.SeverityLabel]++
	}
	output.Emit(events, output.Event{
		Kind: output.EventDone,
		Done: &output.ScanSummary{
			Elapsed:       time.Since(start),
			TotalFindings: len(scored),
			BySeverity:    bySeverity,
			ReportPath:    p.cfg.ReportPath,
		},
	})
	return nil
}

// runPathA executes all Path A detectors concurrently and writes findings to ch.
// Stubs for individual stages (opengrep, astgrep, joern, instrscan, verifier)
// will be filled in ML0.5 / ML2.
func (p *pipeline) runPathA(ctx context.Context, _ *ingestion.Result, ch finding.Channel, events chan<- output.Event) error {
	output.Emit(events, output.Event{Kind: output.EventStageStart, Stage: "path a"})
	// Individual stage goroutines (opengrep, ast-grep, Joern, instrscan) will
	// be wired here in ML0.5 / ML2.1 when the wrappers are production-ready.
	_ = ctx
	_ = ch
	output.Emit(events, output.Event{
		Kind:    output.EventStageEnd,
		Stage:   "path a",
		Summary: &output.StageSummary{Stage: "path a", Detail: "stub — wired in ML0.5"},
	})
	return nil
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

// close shuts down the Python worker and releases any other held resources.
func (p *pipeline) close() error {
	if p.w != nil {
		return p.w.Stop()
	}
	return nil
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
