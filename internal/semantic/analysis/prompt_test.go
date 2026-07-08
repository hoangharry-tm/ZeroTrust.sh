package analysis

import (
	"strings"
	"testing"

	"github.com/hoangharry-tm/zerotrust/internal/semantic/enrichment"
	"github.com/hoangharry-tm/zerotrust/internal/semantic/targeting"
)

func TestShortPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "src/main/java/org/owasp/webgoat/container/mailbox/MailboxController.java",
			expected: "mailbox/MailboxController.java",
		},
		{
			input:    "MailboxController.java",
			expected: "MailboxController.java",
		},
		{
			input:    "a/b",
			expected: "a/b",
		},
		{
			input:    "",
			expected: "",
		},
	}
	for _, tc := range tests {
		got := shortPath(tc.input)
		if got != tc.expected {
			t.Errorf("shortPath(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestBuildCFP_ShortPath(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "src/main/java/org/owasp/webgoat/container/MailboxController.java",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	cfp := buildCFP(surface)
	if strings.Contains(cfp, "owasp") {
		t.Errorf("buildCFP output should not contain 'owasp', got:\n%s", cfp)
	}
	if strings.Contains(cfp, "webgoat") {
		t.Errorf("buildCFP output should not contain 'webgoat', got:\n%s", cfp)
	}
	if !strings.Contains(cfp, "container/MailboxController.java") {
		t.Errorf("buildCFP output should contain last 2 path components, got:\n%s", cfp)
	}
}

func TestBuildPrompt_NoWorldKnowledge(t *testing.T) {
	surface := enrichment.EnrichedSurface{
		Surface: targeting.Surface{
			ID:   "s1",
			File: "test.go",
			Kind: targeting.SurfaceExternalInput,
		},
	}
	prompt := buildPrompt(surface)
	if !strings.Contains(prompt, "Do NOT use prior knowledge") {
		t.Errorf("buildPrompt should contain 'Do NOT use prior knowledge', got:\n%s", prompt)
	}
}
