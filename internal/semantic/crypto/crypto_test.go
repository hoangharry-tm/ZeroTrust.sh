package crypto

import (
	"context"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

func TestCryptoChecker_CWE327LineFromCodeOffset(t *testing.T) {
	c := &Checker{}
	es := enrichment.EnrichedSurface{
		Surface: targeting.Surface{File: "Foo.java", Line: 10},
		Code:    "void foo() {\n  // nothing\n  Cipher.getInstance(\"DES\");\n}",
	}
	findings := c.cwe327(es)
	if len(findings) == 0 {
		t.Fatal("want finding")
	}
	if findings[0].LineRange.Start != 12 {
		t.Errorf("want line 12, got %d", findings[0].LineRange.Start)
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name   string
		es     enrichment.EnrichedSurface
		expect string
	}{
		{"CWE-327", enrichment.EnrichedSurface{Surface: targeting.Surface{File: "h.go"}, Code: "x := MD5()", SinkNodes: []string{"crypto.MD5"}}, "CWE-327"},
		{"CWE-321", enrichment.EnrichedSurface{Surface: targeting.Surface{File: "a.go"}, Code: `key = "xyz"`, SinkNodes: nil}, "CWE-321"},
		{"CWE-338", enrichment.EnrichedSurface{Surface: targeting.Surface{File: "r.go"}, Code: "r := math.rand", SinkNodes: []string{"math/rand"}}, "CWE-338"},
		{"CWE-916", enrichment.EnrichedSurface{Surface: targeting.Surface{File: "h.go"}, Code: "pbkdf2(p, s, 1000, 32)", SinkNodes: nil}, "CWE-916"},
		{"clean", enrichment.EnrichedSurface{Surface: targeting.Surface{File: "s.go"}, Code: "x := crypto.rand.Read()", SinkNodes: []string{"crypto/rand"}}, ""},
	}
	c := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := c.Check(context.Background(), tt.es)
			if tt.expect == "" && len(ff) != 0 {
				t.Errorf("want no findings, got %d", len(ff))
			} else if tt.expect != "" && (len(ff) == 0 || ff[0].CWE != tt.expect) {
				t.Errorf("want %s, got %v", tt.expect, ff)
			}
		})
	}
}
