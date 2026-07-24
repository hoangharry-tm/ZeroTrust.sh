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

// Package report generates the self-contained HTML vulnerability dashboard
// from a scored finding set. All user-derived strings pass through html/template
// contextual escaping — no template.HTML casts are used.
package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

//go:embed template/layout.html template/styles.css template/scripts.js
var tmplFS embed.FS

// ScanInfo holds per-scan metadata rendered in the report header.
type ScanInfo struct {
	ProjectName    string // e.g. "my-service"
	ScannedAt      string // formatted timestamp, e.g. "2026-06-16 09:41 UTC"
	ScanMode       string // "Default" | "Thorough" | "Full"
	ScopeNote      string // human-readable scope description shown in the scope notice bar
	ModulesScanned int    // number of modules in scope (0 = omit from display)
	LOC            int    // lines of code scanned (0 = omit)
	ScanDuration   string // e.g. "4.2s" (empty = omit)
	// RootDir is the absolute path of the scanned project root.
	// When set, all finding paths from Reasoning (Joern CPG) that start with
	// this prefix are normalized to relative paths in the rendered report.
	RootDir string
	// Alerts are operator-facing degradation notices (e.g. MIV block, CPG build failure).
	// Non-empty entries are rendered as warning banners in the report header.
	Alerts []string
}

// FileGroup is a pre-computed (file, count) pair used by the sidebar file list.
type FileGroup struct {
	File      string // full path as stored in Finding.Path
	ShortName string // basename or last two path segments for display
	Count     int
}

// templateData is the root object passed to the HTML template.
type templateData struct {
	Info       ScanInfo
	Findings   []finding.Finding
	FileGroups []FileGroup
}

// CountBySeverity returns the number of findings with the given severity label.
func (d templateData) CountBySeverity(sev string) int {
	n := 0
	for _, f := range d.Findings {
		if f.SeverityLabel.String() == sev {
			n++
		}
	}
	return n
}

// CountByPath returns the number of findings produced by the given source path.
func (d templateData) CountByPath(path string) int {
	n := 0
	for _, f := range d.Findings {
		if string(f.SourcePath) == path {
			n++
		}
	}
	return n
}

// codeLine is a single rendered line in the code snippet block.
type codeLine struct {
	LineNum   int
	Content   string
	Highlight bool // true for the primary finding line
}

// diffLine is a single rendered line in a unified-diff block.
type diffLine struct {
	Class   string // " add", " del", " hunk", or ""
	Sign    string // "+", "-", "@", or " "
	Content string
}

// templateFuncs are the custom functions available in the template.
var templateFuncs = template.FuncMap{
	// not inverts a boolean or checks emptiness for strings and slices.
	// Used in the template for {{ if not .Findings }} and {{ if and (not .MatchedCode) ... }}.
	"not": func(v any) bool {
		switch val := v.(type) {
		case bool:
			return !val
		case string:
			return val == ""
		case []finding.Finding:
			return len(val) == 0
		}
		return false
	},

	// sourcepathLabel maps SourcePath constants to short display labels.
	"sourcepathLabel": func(sp finding.SourcePath) string {
		switch sp {
		case finding.SourcePattern:
			return "Deterministic"
		case finding.SourceSemantic:
			return "Reasoning"
		case finding.SourceBoth:
			return "Deterministic + Reasoning"
		default:
			return string(sp)
		}
	},

	// confPct converts a 0–1 confidence float to an integer percentage.
	"confPct": func(c float64) int {
		pct := int(c * 100)
		if pct > 100 {
			return 100
		}
		if pct < 0 {
			return 0
		}
		return pct
	},

	// ssvcClass maps an SSVC dimension value to a CSS class for colouring.
	"ssvcClass": func(val string) string {
		switch strings.ToLower(val) {
		case "active":
			return "ssvc-active"
		case "poc":
			return "ssvc-poc"
		case "none":
			return "ssvc-none"
		case "total":
			return "ssvc-total"
		case "partial":
			return "ssvc-partial"
		case "yes":
			return "ssvc-yes"
		case "no":
			return "ssvc-no"
		default:
			return ""
		}
	},

	// diffLines parses a unified diff string into diffLine values for the template.
	"diffLines": func(patch string) []diffLine {
		raw := strings.Split(strings.TrimRight(patch, "\n"), "\n")
		lines := make([]diffLine, 0, len(raw))
		for _, l := range raw {
			var dl diffLine
			switch {
			case strings.HasPrefix(l, "@@"):
				dl = diffLine{Class: " hunk", Sign: "@", Content: l}
			case strings.HasPrefix(l, "+"):
				dl = diffLine{Class: " add", Sign: "+", Content: l[1:]}
			case strings.HasPrefix(l, "-"):
				dl = diffLine{Class: " del", Sign: "-", Content: l[1:]}
			default:
				dl = diffLine{Sign: " ", Content: l}
			}
			lines = append(lines, dl)
		}
		return lines
	},

	// codeLines splits MatchedCode into numbered codeLine values.
	// startLine is the first line number (from LineRange.Start); 0 defaults to 1.
	// sinkLine is the absolute line number to highlight (from LineRange.End).
	// When sinkLine <= 0 or sinkLine < startLine, the last line is highlighted
	// as fallback (preserves Deterministic behaviour where End == Start).
	"codeLines": func(code string, startLine, sinkLine int) []codeLine {
		if startLine <= 0 {
			startLine = 1
		}
		raw := strings.Split(strings.TrimRight(code, "\n"), "\n")
		lines := make([]codeLine, len(raw))
		for i, l := range raw {
			absLine := startLine + i
			var highlight bool
			if sinkLine > 0 && sinkLine >= startLine {
				highlight = absLine == sinkLine
			} else {
				highlight = i == len(raw)-1
			}
			lines[i] = codeLine{
				LineNum:   absLine,
				Content:   l,
				Highlight: highlight,
			}
		}
		return lines
	},

	// displayTitle returns the best human-readable title for a finding card.
	// If Summary is set, it is returned verbatim. Otherwise falls back to
	// extracting the B5 explanation from Justification, or truncating to 120 chars.
	"displayTitle": func(summary, justification string) string {
		if summary != "" {
			return summary
		}
		j := justification
		for _, marker := range []string{" — B5 confirmed (conf=", " — B5 LLM confirmed"} {
			if i := strings.Index(j, marker); i > 0 {
				after := j[i:]
				if ci := strings.Index(after, "): "); ci >= 0 {
					return after[ci+3:]
				}
			}
		}
		if len(j) > 120 {
			return j[:117] + "..."
		}
		return j
	},

	// inlineCSS returns the embedded stylesheet as safe CSS.
	"inlineCSS": func() template.CSS { return cssContent },

	// inlineJS returns the embedded script as safe JavaScript.
	"inlineJS": func() template.JS { return jsContent },
}

var (
	cssContent template.CSS
	jsContent  template.JS
)

func init() {
	data, err := tmplFS.ReadFile("template/styles.css")
	if err != nil {
		panic(err)
	}
	cssContent = template.CSS(data)
	data, err = tmplFS.ReadFile("template/scripts.js")
	if err != nil {
		panic(err)
	}
	jsContent = template.JS(data)
}

var tmpl = template.Must(
	template.New("layout.html").Funcs(templateFuncs).ParseFS(tmplFS, "template/layout.html"),
)

// Generator produces the HTML report from a scored finding set.
type Generator struct {
	outputPath string
}

// New returns a Generator that writes its output to outputPath.
func New(outputPath string) *Generator {
	return &Generator{outputPath: outputPath}
}

// Render writes the self-contained HTML report to w.
// Findings are sorted by severity (BLOCK first) before rendering.
// normalizePaths converts absolute finding paths to relative by stripping the
// RootDir prefix. Paths that are already relative or don't share the prefix are
// left unchanged. This ensures Deterministic (OpenGrep, relative) and Reasoning (Joern
// CPG, often absolute) use consistent path forms in the report.
func normalizePaths(rootDir string, findings []finding.Finding) {
	if rootDir == "" {
		return
	}
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return
	}
	absRoot = filepath.ToSlash(absRoot)
	for i := range findings {
		p := findings[i].Path
		if p == "" || !filepath.IsAbs(p) {
			continue
		}
		cleaned := filepath.ToSlash(filepath.Clean(p))
		if strings.HasPrefix(cleaned, absRoot+"/") {
			findings[i].Path = cleaned[len(absRoot)+1:]
		} else if cleaned == absRoot {
			findings[i].Path = "."
		}
	}
}

func (g *Generator) Render(w io.Writer, info ScanInfo, findings []finding.Finding) error {
	slog.Debug("rendering layout",
		slog.String("project", info.ProjectName),
		slog.Int("findings", len(findings)),
	)
	sorted := sortFindings(findings)
	normalizePaths(info.RootDir, sorted)
	data := templateData{
		Info:       info,
		Findings:   sorted,
		FileGroups: buildFileGroups(sorted),
	}
	if err := tmpl.Execute(w, data); err != nil {
		slog.Error("layout render failed", "err", err)
		return err
	}
	slog.Debug("layout rendered", slog.Int("file_groups", len(data.FileGroups)))
	return nil
}

// sortFindings returns a copy of findings ordered BLOCK > HIGH > MEDIUM > LOW > SUPPRESSED,
// with ties broken by descending confidence.
func sortFindings(in []finding.Finding) []finding.Finding {
	order := map[finding.SeverityLabel]int{
		finding.SeverityBlock:      0,
		finding.SeverityHigh:       1,
		finding.SeverityMedium:     2,
		finding.SeverityLow:        3,
		finding.SeveritySuppressed: 4,
	}
	out := make([]finding.Finding, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		oi := order[out[i].SeverityLabel]
		oj := order[out[j].SeverityLabel]
		if oi != oj {
			return oi < oj
		}
		return out[i].Confidence > out[j].Confidence
	})
	return out
}

// buildFileGroups computes the sidebar file list from the sorted finding set.
func buildFileGroups(findings []finding.Finding) []FileGroup {
	counts := make(map[string]int)
	order := []string{}
	for _, f := range findings {
		if _, seen := counts[f.Path]; !seen {
			order = append(order, f.Path)
		}
		counts[f.Path]++
	}
	groups := make([]FileGroup, 0, len(order))
	for _, path := range order {
		groups = append(groups, FileGroup{
			File:      path,
			ShortName: shortName(path),
			Count:     counts[path],
		})
	}
	return groups
}

// shortName returns a compact display name for a file path.
// Shows the last two path segments (dir/file.ext) to avoid truncation of
// deeply nested paths while still providing useful context.
func shortName(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	if len(parts) <= 2 {
		return path
	}
	return fmt.Sprintf("%s/%s", parts[len(parts)-2], parts[len(parts)-1])
}
