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

package util

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
			if got := IsTestFile(tt.path); got != tt.want {
				t.Errorf("IsTestFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
