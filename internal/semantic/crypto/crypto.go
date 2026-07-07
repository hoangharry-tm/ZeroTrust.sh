package crypto

import (
	"context"
	"fmt"
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

func New() *Checker { return &Checker{} }

func (c *Checker) Check(ctx context.Context, es enrichment.EnrichedSurface) []finding.Finding {
	var ff []finding.Finding
	ff = append(ff, c.cwe327(es)...)
	ff = append(ff, c.cwe321(es)...)
	ff = append(ff, c.cwe338(es)...)
	ff = append(ff, c.cwe916(es)...)
	return ff
}

func (c *Checker) CheckAll(ctx context.Context, surfaces []enrichment.EnrichedSurface) ([]finding.Finding, error) {
	w := runtime.NumCPU()
	if w > 4 {
		w = 4
	}
	ch := make(chan struct{}, w)
	var mu sync.Mutex
	var out []finding.Finding
	for _, es := range surfaces {
		select {
		case <-ctx.Done():
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
	for i := 0; i < w; i++ {
		ch <- struct{}{}
	}
	return out, nil
}

func (c *Checker) cwe327(es enrichment.EnrichedSurface) []finding.Finding {
	weak := []string{"MessageDigest.getInstance", "md5", "sha1", "sha-1", "DES", "RC4", "ECB", "crypto.MD5", "crypto.SHA1", "des", "rc4"}
	for _, sink := range es.SinkNodes {
		for _, a := range weak {
			if strings.Contains(strings.ToLower(sink), strings.ToLower(a)) {
				return []finding.Finding{c.mkf(es, "CWE-327", finding.SeverityHigh, "weak algorithm: "+a, a)}
			}
		}
	}
	for _, a := range []string{"MD5", "SHA-1", "DES", "RC4", "ECB"} {
		if strings.Contains(es.Code, a) {
			return []finding.Finding{c.mkf(es, "CWE-327", finding.SeverityHigh, "weak algorithm: "+a, a)}
		}
	}
	return nil
}

func (c *Checker) cwe321(es enrichment.EnrichedSurface) []finding.Finding {
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
				return []finding.Finding{c.mkf(es, "CWE-321", finding.SeverityHigh, "hardcoded key", m)}
			}
		}
	}
	return nil
}

func (c *Checker) cwe338(es enrichment.EnrichedSurface) []finding.Finding {
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
				return []finding.Finding{c.mkf(es, "CWE-338", finding.SeverityHigh, "weak PRNG", p)}
			}
		}
		if strings.Contains(es.Code, p) {
			return []finding.Finding{c.mkf(es, "CWE-338", finding.SeverityHigh, "weak PRNG", p)}
		}
	}
	return nil
}

func (c *Checker) cwe916(es enrichment.EnrichedSurface) []finding.Finding {
	m := pbkdf2Re.FindStringSubmatch(es.Code)
	if len(m) > 1 {
		var n int
		fmt.Sscanf(m[1], "%d", &n)
		if n > 0 && n < 10000 {
			return []finding.Finding{c.mkf(es, "CWE-916", finding.SeverityMedium, "low PBKDF2 iterations", m[0])}
		}
	}
	m = bcryptRe.FindStringSubmatch(es.Code)
	if len(m) > 1 {
		var n int
		fmt.Sscanf(m[1], "%d", &n)
		if n > 0 && n < 10 {
			return []finding.Finding{c.mkf(es, "CWE-916", finding.SeverityMedium, "low bcrypt work factor", m[0])}
		}
	}
	return nil
}

func (c *Checker) mkf(es enrichment.EnrichedSurface, cwe string, sev finding.SeverityLabel, just, code string) finding.Finding {
	if len(code) > 120 {
		code = code[:120]
	}
	conf := 0.85
	if sev == finding.SeverityMedium {
		conf = 0.80
	}
	return finding.New(es.File, finding.LineRange{Start: 1, End: 1}, cwe, just,
		finding.WithMatchedCode(code), finding.WithConfidence(conf), finding.WithSourcePath(finding.SourceSemantic),
		finding.WithRuleID("crypto-"+strings.ToLower(strings.TrimPrefix(cwe, "CWE-"))))
}
