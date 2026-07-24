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
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed dockerfiles/*.Dockerfile
var dockerfiles embed.FS

//go:embed seccomp-profile.json
var seccompProfile []byte

// artifactRuntime identifies how a user-supplied build artifact should be
// packaged and started inside the sandbox container. Grey-box PoE takes a
// single pre-built artifact — a jar, a bundled JS file, a Python script, or a
// native binary — rather than building the project from source. This is
// deliberately narrower than "arbitrary project layout": each runtime expects
// exactly one self-contained file. Multi-file Python/Node deployments
// (requirements.txt, node_modules) are a follow-up, not in scope here.
type artifactRuntime string

const (
	runtimeJava   artifactRuntime = "java"
	runtimePython artifactRuntime = "python"
	runtimeNode   artifactRuntime = "node"
	runtimeGo     artifactRuntime = "go"
	runtimeNone   artifactRuntime = ""
)

// ErrUnsupportedArtifact means the supplied artifact's type could not be
// determined from its extension or file mode. Callers must treat this as
// finding.PoELanguageUnsupported, not as a build failure.
var ErrUnsupportedArtifact = errors.New("poe: could not determine runtime for the supplied artifact (expected .jar, .py, .js/.mjs/.cjs, or an executable binary)")

// artifactFileName is the fixed in-container filename each runtime's
// Dockerfile expects — the supplied artifact is staged under this name
// regardless of its original filename, so the Dockerfiles never need templating.
var artifactFileName = map[artifactRuntime]string{
	runtimeJava:   "app.jar",
	runtimePython: "app.py",
	runtimeNode:   "app.js",
	runtimeGo:     "app",
}

// runCommand is the default process the runtime Dockerfile's ENTRYPOINT runs.
// No override flag yet — one sane default per runtime, extend when needed.
var runCommand = map[artifactRuntime]string{
	runtimeJava:   "java -jar /app/app.jar",
	runtimePython: "python3 /app/app.py",
	runtimeNode:   "node /app/app.js",
	runtimeGo:     "/app/app",
}

// detectArtifactRuntime infers the runtime from the artifact's extension, or
// (for extension-less files) whether it's an executable — the native-binary case.
func detectArtifactRuntime(artifactPath string) (artifactRuntime, error) {
	slog.Debug("detecting artifact runtime", "artifact_path", artifactPath)
	switch strings.ToLower(filepath.Ext(artifactPath)) {
	case ".jar":
		return runtimeJava, nil
	case ".py":
		return runtimePython, nil
	case ".js", ".mjs", ".cjs":
		return runtimeNode, nil
	}

	info, err := os.Stat(artifactPath)
	if err != nil {
		return runtimeNone, fmt.Errorf("poe: stat artifact: %w", err)
	}
	if !info.IsDir() && info.Mode()&0o111 != 0 {
		return runtimeGo, nil
	}
	return runtimeNone, ErrUnsupportedArtifact
}

// runtimeDockerfileFor returns the embedded, static (non-templated) runtime
// Dockerfile for rt.
func runtimeDockerfileFor(rt artifactRuntime) ([]byte, error) {
	slog.Debug("resolving runtime dockerfile", "runtime", rt)
	switch rt {
	case runtimeJava:
		return dockerfiles.ReadFile("dockerfiles/java-runtime.Dockerfile")
	case runtimePython:
		return dockerfiles.ReadFile("dockerfiles/python-runtime.Dockerfile")
	case runtimeNode:
		return dockerfiles.ReadFile("dockerfiles/node-runtime.Dockerfile")
	case runtimeGo:
		return dockerfiles.ReadFile("dockerfiles/go-runtime.Dockerfile")
	default:
		return nil, ErrUnsupportedArtifact
	}
}

// buildSandboxImage packages artifactPath into a minimal runtime-only image —
// no compile step. It stages the artifact under its runtime's fixed filename
// in a throwaway build-context directory alongside the static Dockerfile, so
// none of the four Dockerfiles need templating (docker build -f <dir>/Dockerfile
// requires the Dockerfile and its COPY sources to share a build context).
func buildSandboxImage(ctx context.Context, artifactPath, imageTag string, timeout time.Duration) error {
	slog.Info("building sandbox image",
		"artifact", artifactPath, "image_tag", imageTag, "timeout", timeout)

	rt, err := detectArtifactRuntime(artifactPath)
	if err != nil {
		slog.Warn("unsupported artifact runtime", "artifact", artifactPath, "error", err)
		return err
	}
	slog.Debug("detected artifact runtime", "runtime", rt)

	content, err := runtimeDockerfileFor(rt)
	if err != nil {
		return err
	}

	buildCtxDir, err := os.MkdirTemp("", "zt-poe-build-*")
	if err != nil {
		return fmt.Errorf("poe: create build context: %w", err)
	}
	defer os.RemoveAll(buildCtxDir) //nolint:errcheck // best-effort cleanup
	slog.Debug("created build context directory", "dir", buildCtxDir)

	if err := copyFile(artifactPath, filepath.Join(buildCtxDir, artifactFileName[rt])); err != nil {
		return fmt.Errorf("poe: stage artifact: %w", err)
	}
	dfPath := filepath.Join(buildCtxDir, "Dockerfile")
	if err := os.WriteFile(dfPath, content, 0o600); err != nil {
		return fmt.Errorf("poe: write dockerfile: %w", err)
	}

	buildCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	//nolint:gosec // buildCtxDir/imageTag are scan-local, not user network input
	cmd := exec.CommandContext(buildCtx, "docker", "build",
		"-f", dfPath,
		"-t", imageTag,
		buildCtxDir,
	)
	slog.Debug("executing docker build", "image_tag", imageTag)
	out, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("docker build failed", "image_tag", imageTag, "error", err)
		return fmt.Errorf("poe: docker build failed: %w\n%s", err, truncate(string(out), 4096))
	}
	slog.Info("sandbox image built successfully", "image_tag", imageTag)
	return nil
}

// copyFile copies src to dst, preserving src's executable bit (needed for the
// native-binary/Go runtime case).
func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// removeSandboxImage removes a previously built image. Best-effort: errors are
// swallowed since a leftover image is a disk-space nit, not a correctness bug.
func removeSandboxImage(ctx context.Context, imageTag string) {
	slog.Debug("removing sandbox image", "image_tag", imageTag)
	_ = exec.CommandContext(ctx, "docker", "rmi", "-f", imageTag).Run() //nolint:errcheck
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}
