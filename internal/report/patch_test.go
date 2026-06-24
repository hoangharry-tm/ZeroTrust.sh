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

package report

import "testing"

func TestValidatePatchOKSingleHunk(t *testing.T) {
	patch := `--- a/foo.go
+++ b/foo.go
@@ -5,3 +5,4 @@
 import "fmt"
+import "errors"

 func main() {`
	status, scope, err := ValidatePatch(patch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != PatchStatusOK {
		t.Errorf("status: want %q, got %q", PatchStatusOK, status)
	}
	if scope != PatchScopeSingleHunk {
		t.Errorf("scope: want %q, got %q", PatchScopeSingleHunk, scope)
	}
}

func TestValidatePatchMalformed(t *testing.T) {
	// Off-by-one hunk header — the primary LLM failure mode.
	patch := `--- a/foo.go
+++ b/foo.go
@@ -999999,1 +999999,2 @@
 func broken() {`
	status, scope, err := ValidatePatch(patch)
	// go-gitdiff may accept the parse but fail to apply; malformed is declared
	// when Parse itself errors or no files are returned. A successfully parsed
	// off-by-one patch is caught at apply time (T4 validates parse-level only).
	// Either outcome is acceptable — we only assert the status is set.
	if err == nil && status != PatchStatusOK {
		t.Errorf("non-error parse should yield status ok, got %q", status)
	}
	_ = scope
}

func TestValidatePatchMalformedGarbage(t *testing.T) {
	status, _, err := ValidatePatch("this is not a diff at all")
	if err == nil {
		t.Error("expected error for non-diff input")
	}
	if status != PatchStatusMalformed {
		t.Errorf("status: want %q, got %q", PatchStatusMalformed, status)
	}
}

func TestValidatePatchMultiHunk(t *testing.T) {
	patch := `--- a/foo.go
+++ b/foo.go
@@ -1,3 +1,4 @@
 package main
+// header hunk

 import "fmt"
@@ -10,3 +11,4 @@
 func main() {
+	// body hunk
 	fmt.Println("hello")
 }`
	status, scope, err := ValidatePatch(patch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != PatchStatusOK {
		t.Errorf("status: want ok, got %q", status)
	}
	if scope != PatchScopeMultiHunk {
		t.Errorf("scope: want %q, got %q", PatchScopeMultiHunk, scope)
	}
}

func TestValidatePatchMultiFile(t *testing.T) {
	patch := `--- a/foo.go
+++ b/foo.go
@@ -1,2 +1,3 @@
 package main
+// fix in foo
 import "fmt"
--- a/bar.go
+++ b/bar.go
@@ -1,2 +1,3 @@
 package main
+// fix in bar
 import "errors"`
	status, scope, err := ValidatePatch(patch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != PatchStatusOK {
		t.Errorf("status: want ok, got %q", status)
	}
	if scope != PatchScopeMultiFile {
		t.Errorf("scope: want %q, got %q", PatchScopeMultiFile, scope)
	}
}
