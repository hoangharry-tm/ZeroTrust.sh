package crypto

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
)

var (
	pbkdf2Re = regexp.MustCompile(`(?i)pbkdf2.*?\b(\d+)\b`)
	bcryptRe = regexp.MustCompile(`(?i)bcrypt.*?\b(\d+)\b`)
)

type Checker struct{}

func New() *Checker {
	slog.Debug("creating crypto checker")
	return &Checker{}
}

func (c *Checker) Check(ctx context.Context, es enrichment.EnrichedSurface) []finding.Finding {
	slog.Debug("checking crypto for surface",
		"surface_id", es.ID, "file", es.File)
	var ff []finding.Finding
	ff = append(ff, c.cwe327(es)...)
	ff = append(ff, c.cwe321(es)...)
	ff = append(ff, c.cwe338(es)...)
	ff = append(ff, c.cwe916(es)...)
	return ff
}

func (c *Checker) CheckAll(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]finding.Finding, error) {
	slog.Debug("checking crypto for all surfaces",
		"surface_count", len(surfaces), "workers", min(runtime.NumCPU(), 4))

	w := min(runtime.NumCPU(), 4)
	ch := make(chan struct{}, w)
	var mu sync.Mutex
	var out []finding.Finding
	for _, es := range surfaces {
		select {
		case <-ctx.Done():
			slog.Warn("crypto check cancelled", "error", ctx.Err())
			return nil, ctx.Err()
		case ch <- struct{}{}:
		}
		go func(s enrichment.EnrichedSurface) {
			defer func() { <-ch }()
			mu.Lock()
			out = append(out, c.Check(ctx, s)...)
			mu.Unlock()
		}(es)
	}
	for range w {
		ch <- struct{}{}
	}
	slog.Debug("crypto check completed", "findings", len(out))
	return out, nil
}

// codeOffsetToLine returns the 1-based source line number for a byte offset
// within a function body, given the function's start line.
func codeOffsetToLine(code string, offset int, funcLine int) int {
	if offset < 0 || funcLine <= 0 {
		return funcLine
	}
	if offset > len(code) {
		offset = len(code)
	}
	line := funcLine
	for _, c := range code[:offset] {
		if c == '\n' {
			line++
		}
	}
	return line
}

func (c *Checker) cwe327(es enrichment.EnrichedSurface) []finding.Finding {
	slog.Debug("checking CWE-327 (weak crypto)", "surface_id", es.ID)
	weak := []string{"MessageDigest.getInstance", "md5", "sha1", "sha-1", "DES", "RC4", "ECB", "crypto.MD5", "crypto.SHA1", "des", "rc4"}
	for _, sink := range es.SinkNodes {
		for _, a := range weak {
			if strings.Contains(strings.ToLower(sink), strings.ToLower(a)) {
				return []finding.Finding{c.mkf(es, "CWE-327", finding.SeverityHigh, "weak algorithm: "+a, a, -1)}
			}
		}
	}
	for _, a := range []string{"MD5", "SHA-1", "DES", "RC4", "ECB"} {
		if strings.Contains(es.Code, a) {
			offset := strings.Index(es.Code, a)
			return []finding.Finding{c.mkf(es, "CWE-327", finding.SeverityHigh, "weak algorithm: "+a, a, offset)}
		}
	}
	return nil
}

func (c *Checker) cwe321(es enrichment.EnrichedSurface) []finding.Finding {
	slog.Debug("checking CWE-321 (hardcoded key)", "surface_id", es.ID)
	pats := []string{`key\s*=\s*"`, `iv\s*=\s*"`, `secret\s*=\s*"`, `password\s*=\s*"`, `salt\s*=\s*"`}
	for _, p := range pats {
		if ok, _ := regexp.MatchString(p, es.Code); ok {
			re := regexp.MustCompile(p)
			idx := re.FindStringIndex(es.Code)
			if idx != nil {
				m := es.Code[idx[0]:idx[1]]
				if len(m) > 120 {
					m = m[:120]
				}
				return []finding.Finding{c.mkf(es, "CWE-321", finding.SeverityHigh, "hardcoded key", m, idx[0])}
			}
		}
	}
	return nil
}

func (c *Checker) cwe338(es enrichment.EnrichedSurface) []finding.Finding {
	slog.Debug("checking CWE-338 (weak PRNG)", "surface_id", es.ID)
	safe := []string{"crypto/rand", "crypto.rand", "SecureRandom", "cryptoRandom"}
	for _, s := range safe {
		if strings.Contains(es.Code, s) {
			return nil
		}
		for _, sink := range es.SinkNodes {
			if strings.Contains(sink, s) {
				return nil
			}
		}
	}
	weak := []string{"math/rand", "math.rand", "new Random(", "Math.random(", "random.random("}
	for _, p := range weak {
		for _, sink := range es.SinkNodes {
			if strings.Contains(strings.ToLower(sink), strings.ToLower(p)) {
				return []finding.Finding{c.mkf(es, "CWE-338", finding.SeverityHigh, "weak PRNG", p, -1)}
			}
		}
		if strings.Contains(es.Code, p) {
			offset := strings.Index(es.Code, p)
			return []finding.Finding{c.mkf(es, "CWE-338", finding.SeverityHigh, "weak PRNG", p, offset)}
		}
	}
	return nil
}

func (c *Checker) cwe916(es enrichment.EnrichedSurface) []finding.Finding {
	slog.Debug("checking CWE-916 (low iterations)", "surface_id", es.ID)
	m := pbkdf2Re.FindStringSubmatch(es.Code)
	if len(m) > 1 {
		var n int
		fmt.Sscanf(m[1], "%d", &n)
		if n > 0 && n < 10000 {
			idx := pbkdf2Re.FindStringIndex(es.Code)
			return []finding.Finding{c.mkf(es, "CWE-916", finding.SeverityMedium, "low PBKDF2 iterations", m[0], idx[0])}
		}
	}
	m = bcryptRe.FindStringSubmatch(es.Code)
	if len(m) > 1 {
		var n int
		fmt.Sscanf(m[1], "%d", &n)
		if n > 0 && n < 10 {
			idx := bcryptRe.FindStringIndex(es.Code)
			return []finding.Finding{c.mkf(es, "CWE-916", finding.SeverityMedium, "low bcrypt work factor", m[0], idx[0])}
		}
	}
	return nil
}

func (c *Checker) mkf(es enrichment.EnrichedSurface, cwe string, sev finding.SeverityLabel, just, code string, offset int) finding.Finding {
	if len(code) > 120 {
		code = code[:120]
	}
	conf := 0.85
	if sev == finding.SeverityMedium {
		conf = 0.80
	}
	line := codeOffsetToLine(es.Code, offset, es.Line)
	if line <= 0 {
		line = 1
	}
	f := finding.New(es.File, finding.LineRange{Start: line, End: line}, cwe, just,
		finding.WithMatchedCode(code), finding.WithConfidence(conf), finding.WithSourcePath(finding.SourceSemantic),
		finding.WithRuleID("crypto-"+strings.ToLower(strings.TrimPrefix(cwe, "CWE-"))))
	f.Summary = just
	return f
}
