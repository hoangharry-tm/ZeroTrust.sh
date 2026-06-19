// preview/main.go — CLI design preview for ZeroTrust.sh.
// Run with: go run ./preview/
// Simulates a full scan with realistic delays and animated spinners.
package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"
)

// ── colour palette ────────────────────────────────────────────────────────────

var (
	// severity
	cBlock  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	cHigh   = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	cMedium = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	cLow    = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
	cAI     = lipgloss.NewStyle().Foreground(lipgloss.Color("141")) // purple — AI-specific vectors

	// status icons
	cOK   = lipgloss.NewStyle().Foreground(lipgloss.Color("77")).Bold(true)
	cWarn = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	cErr  = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)

	// structural chrome
	cStage  = lipgloss.NewStyle().Foreground(lipgloss.Color("75")).Bold(true)
	cBox    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	cDim    = lipgloss.NewStyle().Faint(true)
	cLabel  = lipgloss.NewStyle().Bold(true)
	cPath   = lipgloss.NewStyle().Foreground(lipgloss.Color("75"))
	cCode   = lipgloss.NewStyle().Foreground(lipgloss.Color("80"))
	cRule   = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	cCWE    = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Faint(true)
	cURL    = lipgloss.NewStyle().Foreground(lipgloss.Color("75")).Underline(true)
	cSupr   = lipgloss.NewStyle().Faint(true)
	cSpin   = lipgloss.NewStyle().Foreground(lipgloss.Color("75")) // spinner frame colour

	// bar chart
	barBlock  = color.New(color.FgHiRed)
	barHigh   = color.New(color.FgRed)
	barMedium = color.New(color.FgYellow)
	barLow    = color.New(color.FgWhite)
)

const (
	termWidth = 60

	iconOK   = "✓"
	iconWarn = "⚠"
	iconFail = "✖"
	iconHigh = "●"
	iconMid  = "◆"
	iconLow  = "○"
	iconSupr = "–"
	iconDot  = "·"
	iconArr  = "→"
)

// ── inline spinner ────────────────────────────────────────────────────────────
// inlineSpinner animates a single terminal line using \r overwrite.
// It uses bubbles/spinner for the frame sequence and advances the model
// manually on each tick — no tea.Program needed.

type inlineSpinner struct {
	model  spinner.Model
	label  string
	mu     sync.Mutex
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func newInlineSpinner(label string) *inlineSpinner {
	s := spinner.New()
	s.Spinner = spinner.MiniDot // ⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏
	s.Style = cSpin
	return &inlineSpinner{
		model:  s,
		label:  label,
		stopCh: make(chan struct{}),
	}
}

// Start begins the animation goroutine.
func (s *inlineSpinner) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case t := <-ticker.C:
				s.mu.Lock()
				frame := s.model.View()
				// advance the model by feeding it a TickMsg
				newModel, _ := s.model.Update(spinner.TickMsg{Time: t})
				s.model = newModel
				s.mu.Unlock()
				fmt.Printf("\r  %s  %s  %-12s%s",
					cBox.Render("│"),
					frame,
					cLabel.Render(s.label),
					cDim.Render("..."),
				)
			}
		}
	}()
}

// Done stops the animation, clears the line, and prints the resolved result.
func (s *inlineSpinner) Done(value string) {
	close(s.stopCh)
	s.wg.Wait()
	// clear spinner line, print final ✓ line
	fmt.Printf("\r  %s  %s  %-12s%s\n",
		cBox.Render("│"),
		cOK.Render(iconOK),
		cLabel.Render(s.label),
		cDim.Render(value),
	)
}

// Fail stops the animation and prints an error result.
func (s *inlineSpinner) Fail(value string) {
	close(s.stopCh)
	s.wg.Wait()
	fmt.Printf("\r  %s  %s  %-12s%s\n",
		cBox.Render("│"),
		cErr.Render(iconFail),
		cLabel.Render(s.label),
		cErr.Render(value),
	)
}

// ── box helpers ───────────────────────────────────────────────────────────────

func rule() string { return cBox.Render(strings.Repeat("━", termWidth)) }

func openBox(title, subtitle string) {
	label := cStage.Render(title)
	if subtitle != "" {
		label += "  " + cDim.Render(subtitle)
	}
	labelW := lipgloss.Width(label)
	fillW := max(0, termWidth-2-2-1-labelW-1-1)
	fill := strings.Repeat("─", fillW)
	fmt.Printf("  %s %s %s%s\n",
		cBox.Render("┌─"),
		label,
		cBox.Render(fill+"─"),
		cBox.Render("┐"),
	)
}

func closeBox() {
	fmt.Printf("  %s%s\n\n",
		cBox.Render("└"+strings.Repeat("─", termWidth-2)),
		cBox.Render("┘"),
	)
}

func boxLine(icon, label, value string) {
	col := fmt.Sprintf("%-12s", label)
	fmt.Printf("  %s  %s  %s%s\n",
		cBox.Render("│"),
		icon,
		cLabel.Render(col),
		value,
	)
}

func boxBlank() { fmt.Printf("  %s\n", cBox.Render("│")) }

// ── finding card ──────────────────────────────────────────────────────────────

type finding struct {
	severity string
	path     string
	line     int
	cwe      string
	ruleID   string
	detail   string
	source   string
	aiVector bool
}

func printFinding(f finding) {
	var icon, sevText string
	switch f.severity {
	case "BLOCK":
		icon = cBlock.Render(iconFail)
		sevText = cBlock.Render("BLOCK ")
	case "HIGH":
		icon = cHigh.Render(iconHigh)
		sevText = cHigh.Render("HIGH  ")
	case "MEDIUM":
		if f.aiVector {
			icon = cAI.Render(iconMid)
			sevText = cAI.Render("MEDIUM")
		} else {
			icon = cMedium.Render(iconMid)
			sevText = cMedium.Render("MEDIUM")
		}
	case "LOW":
		icon = cLow.Render(iconLow)
		sevText = cLow.Render("LOW   ")
	default:
		icon = cSupr.Render(iconSupr)
		sevText = cSupr.Render("SUPPR ")
	}

	loc := cPath.Render(fmt.Sprintf("%s:%d", f.path, f.line))
	ruleID := cRule.Render(f.ruleID)
	cwe := cCWE.Render(f.cwe)

	src := ""
	if f.source == "BOTH" {
		src = "  " + cOK.Render("[A+B]")
	}

	fmt.Printf("  %s  %s %s  %s  %s  %s%s\n",
		cBox.Render("│"),
		icon, sevText,
		loc, ruleID, cwe, src,
	)
	if f.detail != "" {
		detail := cDim.Render(f.detail)
		if f.aiVector {
			detail = cAI.Render(f.detail)
		}
		fmt.Printf("  %s         %s\n", cBox.Render("│"), detail)
	}
	boxBlank()
}

// ── bar chart ─────────────────────────────────────────────────────────────────

func printBar(label string, count, maxCount int, c *color.Color, note string) {
	if count == 0 {
		return
	}
	barLen := 1
	if maxCount > 0 {
		barLen = max(1, (count*24)/maxCount)
	}
	bar := c.Sprint(strings.Repeat("█", barLen))
	fmt.Printf("  %-10s %2d  %s  %s\n", label, count, bar, cDim.Render(note))
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	// 1. header
	fmt.Println()
	fmt.Printf("  %s  %s\n",
		cLabel.Render("zerotrust v0.1.0"),
		cDim.Render("local · privacy-first AI security scanner"),
	)
	fmt.Printf("  %s\n\n", rule())

	// 2. dep check
	fmt.Printf("  %s  %-10s %s\n", cOK.Render(iconOK), cLabel.Render("Docker"), cDim.Render("27.4.0"))
	fmt.Printf("  %s  %-10s %s\n", cWarn.Render(iconWarn), cLabel.Render("Ollama"), cWarn.Render("not detected  ·  LLM steps will run on CPU (slower)"))
	fmt.Printf("     %s  %s\n", cDim.Render("Install for faster scans "+iconArr), cURL.Render("https://ollama.com"))
	fmt.Println()

	fmt.Printf("  %s  %s  %s\n", cDim.Render("Scanning"), cCode.Render("/Users/alice/myproject"), cDim.Render("[Default mode]"))
	fmt.Println()
	time.Sleep(300 * time.Millisecond)

	// 3. ingestion
	openBox("ingestion", "")

	s := newInlineSpinner("model")
	s.Start()
	time.Sleep(500 * time.Millisecond)
	s.Done("qwen2.5-3b  ·  sha256:a3f9e1  ·  verified")

	s = newInlineSpinner("diff")
	s.Start()
	time.Sleep(400 * time.Millisecond)
	s.Done("4 files changed  ·  18 unchanged  ·  CPG patch depth 3")

	closeBox()

	// 4. path-a
	openBox("path-a", "pattern detection")

	s = newInlineSpinner("opengrep")
	s.Start()
	time.Sleep(800 * time.Millisecond)
	s.Done("3 matches  ·  0.8s")

	s = newInlineSpinner("ast-grep")
	s.Start()
	time.Sleep(500 * time.Millisecond)
	s.Done("1 match  ·  0.3s")

	s = newInlineSpinner("joern")
	s.Start()
	time.Sleep(1200 * time.Millisecond)
	s.Done("CPG ready  ·  12 methods  ·  4 taint paths  ·  2.1s")

	s = newInlineSpinner("verifier")
	s.Start()
	time.Sleep(700 * time.Millisecond)
	s.Done("3 confirmed  ·  1 filtered  ·  0.9s")

	closeBox()

	// 5. path-b
	openBox("path-b", "semantic detection")

	s = newInlineSpinner("targeting")
	s.Start()
	time.Sleep(300 * time.Millisecond)
	s.Done("8 surfaces selected from CPG")

	s = newInlineSpinner("trivy")
	s.Start()
	time.Sleep(600 * time.Millisecond)
	s.Done("2 CVEs matched  ·  3 packages  ·  0.6s")

	s = newInlineSpinner("classifier")
	s.Start()
	time.Sleep(500 * time.Millisecond)
	s.Done("3 flagged  ·  5 eliminated  ·  0.4s")

	s = newInlineSpinner("llm-scan")
	s.Start()
	time.Sleep(900 * time.Millisecond)
	s.Done("2 confirmed  ·  1 suppressed  ·  12,400 tokens  ·  3.2s")

	closeBox()

	// 6. dedup
	openBox("dedup", "")

	s = newInlineSpinner("dedup")
	s.Start()
	time.Sleep(300 * time.Millisecond)
	s.Done("5 unique findings  ·  1 cross-path boost applied (+15pp)")

	closeBox()

	// 7. findings
	openBox("findings", "")
	boxBlank()
	time.Sleep(100 * time.Millisecond)

	printFinding(finding{severity: "BLOCK", path: "UserController.java", line: 42, cwe: "CWE-89", ruleID: "sql-injection-jdbc", detail: "taint: getParameter() → executeQuery()", source: "BOTH"})
	time.Sleep(80 * time.Millisecond)
	printFinding(finding{severity: "HIGH", path: "config.py", line: 11, cwe: "CWE-798", ruleID: "hardcoded-ai-api-key", detail: "AI agent introduced literal credential in commit a3f9e1", source: "PATTERN"})
	time.Sleep(80 * time.Millisecond)
	printFinding(finding{severity: "HIGH", path: "AuthService.java", line: 87, cwe: "CWE-306", ruleID: "auth-bypass-stub", detail: "TODO stub — security control removed; was present in HEAD~1", source: "BOTH"})
	time.Sleep(80 * time.Millisecond)
	printFinding(finding{severity: "MEDIUM", path: ".cursor/rules", line: 3, cwe: "AI-001", ruleID: "prompt-injection-rules", detail: "indirect prompt injection in AI agent instruction file", source: "PATTERN", aiVector: true})
	time.Sleep(80 * time.Millisecond)
	printFinding(finding{severity: "LOW", path: "utils.py", line: 44, cwe: "CWE-22", ruleID: "path-traversal-risk", source: "PATTERN"})
	time.Sleep(80 * time.Millisecond)
	printFinding(finding{severity: "SUPPRESSED", path: "helpers.py", line: 102, cwe: "CWE-89", ruleID: "sql-injection-orm", detail: "suppressed: ORM parameterised query confirmed by classifier", source: "SEMANTIC"})

	closeBox()

	// 8. summary
	fmt.Printf("  %s\n\n", rule())

	counts := map[string]int{"BLOCK": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1, "SUPPRESSED": 1}
	maxCount := 2

	fmt.Printf("  %s  %s\n\n",
		cLabel.Render("5 findings"),
		cDim.Render("6.8s"),
	)

	printBar("BLOCK",  counts["BLOCK"],  maxCount, barBlock,  "stop deployment")
	printBar("HIGH",   counts["HIGH"],   maxCount, barHigh,   "review before merge")
	printBar("MEDIUM", counts["MEDIUM"], maxCount, barMedium, "address soon")
	printBar("LOW",    counts["LOW"],    maxCount, barLow,    "informational")
	fmt.Println()

	fmt.Printf("  %s  %d suppressed  %s\n\n",
		cSupr.Render(iconSupr),
		counts["SUPPRESSED"],
		cDim.Render("(confidence below threshold)"),
	)

	fmt.Printf("  %s  %s\n", cDim.Render("report"), cCode.Render("build/report.html"))
	fmt.Println()
	fmt.Printf("  %s  CI exit code %s  —  BLOCK or HIGH findings present\n\n",
		cErr.Render(iconFail),
		cCode.Render("1"),
	)

	os.Exit(0) // preview only
}
