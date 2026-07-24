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

package poe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectArtifactRuntime_Jar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.jar")
	mustWrite(t, path, "fake jar bytes")

	if got, err := detectArtifactRuntime(path); err != nil || got != runtimeJava {
		t.Fatalf("detectArtifactRuntime(.jar) = (%q, %v), want (%q, nil)", got, err, runtimeJava)
	}
}

func TestDetectArtifactRuntime_Python(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.py")
	mustWrite(t, path, "print('hi')")

	if got, err := detectArtifactRuntime(path); err != nil || got != runtimePython {
		t.Fatalf("detectArtifactRuntime(.py) = (%q, %v), want (%q, nil)", got, err, runtimePython)
	}
}

func TestDetectArtifactRuntime_Node(t *testing.T) {
	for _, ext := range []string{".js", ".mjs", ".cjs"} {
		path := filepath.Join(t.TempDir(), "app"+ext)
		mustWrite(t, path, "console.log('hi')")

		if got, err := detectArtifactRuntime(path); err != nil || got != runtimeNode {
			t.Errorf("detectArtifactRuntime(%s) = (%q, %v), want (%q, nil)", ext, got, err, runtimeNode)
		}
	}
}

func TestDetectArtifactRuntime_NativeBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app")
	mustWrite(t, path, "\x7fELF fake binary bytes")
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if got, err := detectArtifactRuntime(path); err != nil || got != runtimeGo {
		t.Fatalf("detectArtifactRuntime(executable, no ext) = (%q, %v), want (%q, nil)", got, err, runtimeGo)
	}
}

func TestDetectArtifactRuntime_UnrecognizedExtNonExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.txt")
	mustWrite(t, path, "not an artifact")

	if _, err := detectArtifactRuntime(path); err != ErrUnsupportedArtifact {
		t.Fatalf("detectArtifactRuntime(.txt, non-executable) error = %v, want ErrUnsupportedArtifact", err)
	}
}

func TestRuntimeDockerfileFor_KnownRuntimes(t *testing.T) {
	for _, rt := range []artifactRuntime{runtimeJava, runtimePython, runtimeNode, runtimeGo} {
		content, err := runtimeDockerfileFor(rt)
		if err != nil {
			t.Fatalf("runtimeDockerfileFor(%q) error: %v", rt, err)
		}
		if len(content) == 0 {
			t.Fatalf("runtimeDockerfileFor(%q) returned empty content", rt)
		}
	}
}

func TestRuntimeDockerfileFor_Unsupported(t *testing.T) {
	if _, err := runtimeDockerfileFor(runtimeNone); err != ErrUnsupportedArtifact {
		t.Fatalf("runtimeDockerfileFor(none) error = %v, want ErrUnsupportedArtifact", err)
	}
}

func TestCopyFile_PreservesExecutableBit(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	mustWrite(t, src, "binary content")
	if err := os.Chmod(src, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("copyFile did not preserve executable bit: mode = %v", info.Mode())
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
