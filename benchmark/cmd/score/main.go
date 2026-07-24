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

// Command score computes precision/recall against the OWASP Benchmark's
// expectedresults CSV, using whatever findings are currently in Postgres for
// a scan of benchmark/data/owasp-benchmark-java. It does not run the scan
// itself — run `make scan` first, then point this at the same database.
//
// Usage:
//
//	go run ./benchmark/cmd/score \
//	    -db "postgres://zerotrust:zerotrust@localhost:5544/zerotrust?sslmode=disable" \
//	    -csv benchmark/data/owasp-benchmark-java/expectedresults-1.2.csv
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// expected is one row of the OWASP Benchmark ground truth: which test case,
// which vulnerability category, whether it's a real vulnerability (as
// opposed to a deliberate false-positive trap), and its CWE.
type expected struct {
	testName string
	category string
	realVuln bool
	cwe      int
}

// findingRow is the subset of a Postgres findings row this scorer needs.
type findingRow struct {
	filePath   string
	cwe        int
	sourcePath string
	severity   string
}

var cweNumRE = regexp.MustCompile(`CWE-(\d+)`)

func main() {
	dbDSN := flag.String("db", "postgres://zerotrust:zerotrust@localhost:5544/zerotrust?sslmode=disable", "Postgres DSN")
	csvPath := flag.String("csv", "benchmark/data/owasp-benchmark-java/expectedresults-1.2.csv", "path to OWASP Benchmark expectedresults CSV")
	flag.Parse()

	expectedRows, err := loadExpected(*csvPath)
	if err != nil {
		log.Fatalf("loading expected results: %v", err)
	}

	findings, err := loadFindings(*dbDSN)
	if err != nil {
		log.Fatalf("loading findings: %v", err)
	}

	// Index findings by test name (the .java file's base name without
	// extension), since OWASP Benchmark names every test file after its own
	// test-case ID.
	byTest := make(map[string][]findingRow)
	for _, f := range findings {
		base := filepath_base(f.filePath)
		name := strings.TrimSuffix(base, ".java")
		byTest[name] = append(byTest[name], f)
	}

	report(expectedRows, byTest)
}

func filepath_base(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func loadExpected(path string) ([]expected, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	var out []expected
	for _, row := range rows {
		if len(row) < 4 || strings.HasPrefix(row[0], "#") {
			continue
		}
		var e expected
		e.testName = strings.TrimSpace(row[0])
		e.category = strings.TrimSpace(row[1])
		e.realVuln = strings.TrimSpace(row[2]) == "true"
		fmt.Sscanf(strings.TrimSpace(row[3]), "%d", &e.cwe)
		out = append(out, e)
	}
	return out, nil
}

func loadFindings(dsn string) ([]findingRow, error) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	defer pool.Close()

	rows, err := pool.Query(ctx,
		`select file_path, cwe, source_path, severity from findings where file_path like '%/testcode/%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []findingRow
	for rows.Next() {
		var f findingRow
		var cweText string
		if err := rows.Scan(&f.filePath, &cweText, &f.sourcePath, &f.severity); err != nil {
			return nil, err
		}
		// findings.cwe is free-text (e.g. "CWE-798" or "CWE-798: Use of
		// Hard-coded Credentials", depending on which producer wrote it) —
		// extract just the number to compare against the benchmark's CSV.
		if m := cweNumRE.FindStringSubmatch(cweText); m != nil {
			fmt.Sscanf(m[1], "%d", &f.cwe)
		} else {
			continue // no parseable CWE number, can't match against ground truth
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// predictedSource collapses the set of finding rows matching one test case
// (already filtered to matching CWE, non-suppressed) into a single
// PATTERN/SEMANTIC/BOTH label, so the report can attribute a true positive to
// the layer(s) that actually caught it.
func predictedSource(rows []findingRow) string {
	seenPattern, seenSemantic, seenBoth := false, false, false
	for _, r := range rows {
		switch r.sourcePath {
		case "PATTERN":
			seenPattern = true
		case "SEMANTIC":
			seenSemantic = true
		case "BOTH":
			seenBoth = true
		}
	}
	switch {
	case seenBoth || (seenPattern && seenSemantic):
		return "BOTH"
	case seenSemantic:
		return "SEMANTIC_ONLY"
	case seenPattern:
		return "PATTERN_ONLY"
	default:
		return "UNKNOWN"
	}
}

// confusion holds a standard binary-classification confusion matrix.
type confusion struct {
	tp, fp, fn, tn int
}

func (c confusion) precision() float64 {
	if c.tp+c.fp == 0 {
		return 0
	}
	return float64(c.tp) / float64(c.tp+c.fp)
}

func (c confusion) recall() float64 {
	if c.tp+c.fn == 0 {
		return 0
	}
	return float64(c.tp) / float64(c.tp+c.fn)
}

func (c confusion) f1() float64 {
	p, r := c.precision(), c.recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func report(expectedRows []expected, byTest map[string][]findingRow) {
	overall := confusion{}
	byCategory := make(map[string]*confusion)
	sourceOfTP := make(map[string]int) // PATTERN_ONLY / SEMANTIC_ONLY / BOTH

	for _, e := range expectedRows {
		candidates := byTest[e.testName]

		// A "predicted positive" is any non-suppressed finding at this test's
		// file whose CWE matches the ground truth's CWE. Suppressed findings
		// were the reasoning layer's own conclusion of "not exploitable", so
		// counting them as a positive prediction would be scoring our own
		// dismissal as a detection.
		var matched []findingRow
		for _, f := range candidates {
			if f.cwe == e.cwe && f.severity != "SUPPRESSED" {
				matched = append(matched, f)
			}
		}
		predictedPositive := len(matched) > 0

		cat := byCategory[e.category]
		if cat == nil {
			cat = &confusion{}
			byCategory[e.category] = cat
		}

		switch {
		case e.realVuln && predictedPositive:
			overall.tp++
			cat.tp++
			sourceOfTP[predictedSource(matched)]++
		case e.realVuln && !predictedPositive:
			overall.fn++
			cat.fn++
		case !e.realVuln && predictedPositive:
			overall.fp++
			cat.fp++
		default:
			overall.tn++
			cat.tn++
		}
	}

	fmt.Printf("=== OWASP Benchmark scoring — %d test cases ===\n\n", len(expectedRows))
	fmt.Printf("Overall: TP=%d FP=%d FN=%d TN=%d\n", overall.tp, overall.fp, overall.fn, overall.tn)
	fmt.Printf("Precision=%.3f Recall=%.3f F1=%.3f\n\n", overall.precision(), overall.recall(), overall.f1())

	fmt.Println("True positives by detection layer:")
	for _, label := range []string{"PATTERN_ONLY", "SEMANTIC_ONLY", "BOTH"} {
		fmt.Printf("  %-14s %d\n", label, sourceOfTP[label])
	}
	fmt.Println()

	fmt.Println("By category:")
	cats := make([]string, 0, len(byCategory))
	for c := range byCategory {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	fmt.Printf("  %-14s %6s %6s %6s %6s %10s %8s\n", "category", "TP", "FP", "FN", "TN", "precision", "recall")
	for _, c := range cats {
		m := byCategory[c]
		fmt.Printf("  %-14s %6d %6d %6d %6d %10.3f %8.3f\n", c, m.tp, m.fp, m.fn, m.tn, m.precision(), m.recall())
	}
}
