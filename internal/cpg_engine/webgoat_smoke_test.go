//go:build smoke

package cpg_engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hoangharry-tm/zerotrust/pkg/postgres"
)

// parseREPLInt extracts an integer from a Joern REPL result line like:
//
//	val res2: Int = 2911
//	res2: Int = 2911
//	2911
func parseREPLInt(raw []byte) (int, error) {
	s := strings.TrimSpace(string(raw))
	if idx := strings.LastIndex(s, " = "); idx != -1 {
		s = strings.TrimSpace(s[idx+3:])
	}
	s = strings.Trim(s, "\"")
	return strconv.Atoi(s)
}

func TestWebGoatSmoke(t *testing.T) {
	ctx := context.Background()

	// ── 2a. Start Joern and build CPG ────────────────────────────────────────
	fmt.Println("=== 2a. Start Joern and build CPG ===")

	bin := os.Getenv("JOERN_BIN")
	if bin == "" {
		bin = "joern"
	}

	c, err := New(
		WithServerURL("http://127.0.0.1:18080"),
		WithBinaryPath(bin),
		WithPort(18080),
		WithBuildTimeout(10*time.Minute),
		WithQueryTimeout(2*time.Minute),
		WithPingRetries(120),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	startCtx, startCancel := context.WithTimeout(ctx, 3*time.Minute)
	defer startCancel()
	if err := c.Start(startCtx); err != nil {
		if errors.Is(err, ErrPortInUse) {
			t.Skipf("port 18080 already in use")
		}
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer stopCancel()
		_ = c.Stop(stopCtx)
	}()

	cpgStart := time.Now()
	buildCtx, buildCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer buildCancel()

	err = c.BuildCPG(buildCtx, BuildConfig{
		Paths:    []string{"/tmp/webgoat-smoke"},
		Language: "JAVASRC",
	})
	if err != nil {
		t.Fatalf("BuildCPG failed: %v", err)
	}
	cpgBuildDuration := time.Since(cpgStart)
	fmt.Printf("CPG build succeeded in %v\n", cpgBuildDuration)

	g := c.Graph()

	// ── 2b. Validate CPG is non-empty ────────────────────────────────────────
	fmt.Println("=== 2b. Validate CPG is non-empty ===")
	methods, err := g.QueryNodes(NodeMethod)
	if err != nil {
		t.Fatalf("QueryNodes(NodeMethod): %v", err)
	}
	calls, err := g.QueryNodes(NodeCall)
	if err != nil {
		t.Fatalf("QueryNodes(NodeCall): %v", err)
	}
	edges, err := g.GetCallGraph()
	if err != nil {
		t.Fatalf("GetCallGraph: %v", err)
	}

	methodCount := len(methods)
	callCount := len(calls)
	edgeCount := len(edges)

	fmt.Printf("Method Count: %d\n", methodCount)
	fmt.Printf("Call Count: %d\n", callCount)
	fmt.Printf("Edge Count: %d\n", edgeCount)

	if methodCount == 0 || callCount == 0 || edgeCount == 0 {
		fmt.Printf("CPG EMPTY: methods=%d calls=%d edges=%d\n", methodCount, callCount, edgeCount)
		t.Fatalf("CPG is empty")
	}

	// ── 2c. Validate pagination ──────────────────────────────────────────────
	fmt.Println("=== 2c. Validate pagination ===")
	rawDirectSize, err := c.doQuery(ctx, "cpg.method.size")
	if err != nil {
		t.Fatalf("Direct size query failed: %v", err)
	}
	directSize, serr := parseREPLInt(rawDirectSize)
	if serr != nil {
		t.Fatalf("Failed to parse cpg.method.size response: %v, raw: %s", serr, string(rawDirectSize))
	}
	fmt.Printf("QueryNodes Method Count: %d, Direct Size Count: %d\n", methodCount, directSize)
	deltaPercent := float64(0)
	if directSize > 0 {
		diff := methodCount - directSize
		if diff < 0 {
			diff = -diff
		}
		deltaPercent = (float64(diff) / float64(directSize)) * 100
	}
	if deltaPercent > 5.0 {
		fmt.Printf("PAGINATION MISMATCH: live count = %d, direct count = %d (delta = %.2f%%)\n", methodCount, directSize, deltaPercent)
	} else {
		fmt.Println("Pagination match (within 5% delta)")
	}

	// ── 2d. Ingest into Postgres ─────────────────────────────────────────────
	fmt.Println("=== 2d. Ingest into Postgres ===")
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping Postgres ingest smoke steps")
	}
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("postgres.Open: %v", err)
	}
	defer db.Close()

	projectID := "webgoat-smoke"
	version := "smoke-1"

	ingestStart := time.Now()
	err = g.IngestCPGToDB(ctx, db, projectID, version)
	ingestDuration := time.Since(ingestStart)
	if err != nil {
		t.Fatalf("IngestCPGToDB: %v", err)
	}
	fmt.Printf("Ingested CPG into Postgres in %v\n", ingestDuration)

	// ── 2e. Validate Postgres round-trip ─────────────────────────────────────
	fmt.Println("=== 2e. Validate Postgres round-trip ===")
	cur, err := db.QueryNodesByType(ctx, projectID, version, "METHOD")
	if err != nil {
		t.Fatalf("QueryNodesByType: %v", err)
	}
	defer cur.Close()
	pgMethodCount := 0
	for cur.Next() {
		pgMethodCount++
	}
	fmt.Printf("Live count: %d, Postgres count: %d\n", methodCount, pgMethodCount)
	if methodCount != pgMethodCount {
		fmt.Printf("Postgres round-trip mismatch: live=%d vs postgres=%d\n", methodCount, pgMethodCount)
	} else {
		fmt.Println("Postgres round-trip match")
	}

	// ── 2f. Taint source node ID correctness ─────────────────────────────────
	fmt.Println("=== 2f. Taint source node ID correctness ===")
	methodIDs := make(map[string]bool, len(methods))
	for _, m := range methods {
		methodIDs[m.ID] = true
	}

	limit := 3
	if len(methods) < limit {
		limit = len(methods)
	}
	for i := 0; i < limit; i++ {
		m := methods[i]
		flows, err := g.TaintPaths([]TaintSource{{NodeID: m.ID}}, []TaintSink{{NodeID: m.ID}})
		if err != nil {
			fmt.Printf("Method %q (ID %s): TaintPaths error: %v\n", m.Name, m.ID, err)
			continue
		}
		if len(flows) == 0 {
			fmt.Printf("Method %q (ID %s): empty flows\n", m.Name, m.ID)
			continue
		}
		srcID := flows[0].Source.NodeID
		if methodIDs[srcID] {
			fmt.Printf("Method %q (ID %s): source node type = METHOD\n", m.Name, srcID)
		} else {
			fmt.Printf("Method %q (ID %s): source node type = CALL (or other non-METHOD)\n", m.Name, srcID)
		}
	}

	// ── 2g. Call graph spot-check ────────────────────────────────────────────
	fmt.Println("=== 2g. Call graph spot-check ===")
	var targetMethod Node
	foundTarget := false
	for _, m := range methods {
		if m.Name == "processRequest" || m.Name == "handleRequest" || m.Name == "doGet" {
			targetMethod = m
			foundTarget = true
			break
		}
	}

	if !foundTarget {
		fmt.Println("Target method (processRequest/handleRequest/doGet) not found")
	} else {
		fmt.Printf("Target method found: %s (ID: %s)\n", targetMethod.Name, targetMethod.ID)
		callers, err := g.GetCallers(targetMethod.ID)
		if err != nil {
			t.Fatalf("GetCallers: %v", err)
		}
		callees, err := g.GetCallees(targetMethod.ID)
		if err != nil {
			t.Fatalf("GetCallees: %v", err)
		}
		fmt.Printf("Callers: %d, Callees: %d\n", len(callers), len(callees))
		limitCallers := 3
		if len(callers) < limitCallers {
			limitCallers = len(callers)
		}
		for i := 0; i < limitCallers; i++ {
			fmt.Printf("Caller %d: %s\n", i+1, callers[i].Name)
		}
		limitCallees := 3
		if len(callees) < limitCallees {
			limitCallees = len(callees)
		}
		for i := 0; i < limitCallees; i++ {
			fmt.Printf("Callee %d: %s\n", i+1, callees[i].Name)
		}
	}
}
