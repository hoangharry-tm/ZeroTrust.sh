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

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountLOC_EmptyFiles(t *testing.T) {
	n, err := countLOC(nil)
	if err != nil {
		t.Fatalf("countLOC(nil) = %v", err)
	}
	if n != 0 {
		t.Errorf("countLOC(nil) = %d, want 0", n)
	}
}

func TestCountLOC_SingleFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(f, []byte("line1\nline2\nline3\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	n, err := countLOC([]string{f})
	if err != nil {
		t.Fatalf("countLOC = %v", err)
	}
	if n != 3 {
		t.Errorf("countLOC = %d, want 3", n)
	}
}

func TestCountLOC_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a.txt")
	f2 := filepath.Join(dir, "b.txt")
	_ = os.WriteFile(f1, []byte("line1\nline2\n"), 0o644)
	_ = os.WriteFile(f2, []byte("line1\nline2\nline3\n"), 0o644)

	n, err := countLOC([]string{f1, f2})
	if err != nil {
		t.Fatalf("countLOC = %v", err)
	}
	if n != 5 {
		t.Errorf("countLOC = %d, want 5", n)
	}
}

func TestCountLOC_SkipsMissingFile(t *testing.T) {
	n, err := countLOC([]string{"/nonexistent/path/file.txt"})
	if err != nil {
		t.Fatalf("countLOC = %v", err)
	}
	if n != 0 {
		t.Errorf("countLOC = %d, want 0", n)
	}
}

func TestCountLOC_TrailingNewline(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	// A file with trailing newline: 2 lines of text, 3 newlines
	if err := os.WriteFile(f, []byte("line1\nline2\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	n, err := countLOC([]string{f})
	if err != nil {
		t.Fatalf("countLOC = %v", err)
	}
	if n != 2 {
		t.Errorf("countLOC = %d, want 2", n)
	}
}
