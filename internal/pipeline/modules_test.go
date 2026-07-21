package pipeline

import "testing"

func TestIsTestFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"src/main/java/FooTest.java", true},
		{"src/main/java/FooService.java", false},
		{"src/test/java/FooService.java", true},
		{"handler_test.go", true},
		{"handler.go", false},
		{"test_utils.py", true},
		{"utils.py", false},
		{"src/contest/entry.go", false},
		{"__tests__/foo.test.ts", true},
		{"src/components/Button.tsx", false},

		// Maven integration test (src/it/) coverage
		{"src/it/java/org/owasp/webgoat/integration/SSRFIntegrationTest.java", true},
		{"src/test/java/Foo.java", true},
		{"src/main/java/FooService.java", false},
		{"src/it/resources/logback-test.xml", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isTestFile(tt.path); got != tt.want {
				t.Errorf("isTestFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
