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
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"
)

// ── symbols & colours ─────────────────────────────────────────────────────────

var (
	iconOK   = color.New(color.FgGreen, color.Bold).Sprint("✓")
	iconWarn = color.New(color.FgYellow, color.Bold).Sprint("⚠")
	iconFail = color.New(color.FgRed, color.Bold).Sprint("✗")

	labelStyle  = color.New(color.Bold).SprintfFunc()
	dimStyle    = color.New(color.Faint).SprintFunc()
	codeStyle   = color.New(color.FgCyan).SprintFunc()
	urlStyle    = color.New(color.FgCyan, color.Underline).SprintFunc()
	warnColor   = color.New(color.FgYellow).SprintFunc()
	errorBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("9")). // bright red
			Padding(1, 3).
			Width(62)
)

// ── public entry point ────────────────────────────────────────────────────────

// checkDeps checks Docker (hard required) and Ollama (optional).
// It prints a styled status block to stderr, then returns (ollamaFound bool, error)
// so the caller can wire GPU passthrough or propagate the error.
func checkDeps() (bool, error) {
	slog.Debug("checking runtime dependencies", "component", "deps")
	dockerVer, dockerOK := dockerVersion()
	ollamaOK := ollamaReachable(ollamaHostURL)

	if !dockerOK {
		slog.Error("Docker not found on PATH", "component", "deps")
		printDockerError()
		return false, fmt.Errorf("docker not found")
	}

	slog.Info("dependency check complete",
		"component", "deps",
		"docker_version", dockerVer,
		"ollama_ok", ollamaOK,
	)
	printDepStatus(dockerVer, ollamaOK)
	return ollamaOK, nil
}

// ── status block ─────────────────────────────────────────────────────────────

func printDepStatus(dockerVer string, ollamaOK bool) {
	// Docker — always OK here (checkDeps exits early otherwise)
	fmt.Fprintf(os.Stderr, "  %s  %-10s %s\n",
		iconOK,
		labelStyle("Docker"),
		dimStyle(dockerVer),
	)

	// Ollama — soft warning when missing
	if ollamaOK {
		fmt.Fprintf(os.Stderr, "  %s  %-10s %s\n",
			iconOK,
			labelStyle("Ollama"),
			dimStyle("running  ·  GPU passthrough enabled"),
		)
	} else {
		fmt.Fprintf(os.Stderr, "  %s  %-10s %s\n",
			iconWarn,
			labelStyle("Ollama"),
			warnColor("not detected  ·  LLM steps will run on CPU (slower)"),
		)
		fmt.Fprintf(os.Stderr, "     %s  %s\n",
			dimStyle("Install for faster scans →"),
			urlStyle("https://ollama.com"),
		)
	}

	fmt.Fprintln(os.Stderr)
}

// ── docker error box ──────────────────────────────────────────────────────────

func printDockerError() {
	guide := dockerInstallGuide()
	body := strings.Join([]string{
		fmt.Sprintf("%s  Docker not found\n", iconFail),
		"ZeroTrust.sh runs its analysis engine inside a Docker",
		"container — this keeps Joern, Python ML, and all heavy",
		"dependencies off your machine.\n",
		"Docker is the only hard requirement.\n",
		guide,
		fmt.Sprintf("Then re-run:  %s", codeStyle("zerotrust scan .")),
	}, "\n")

	fmt.Fprintln(os.Stderr, errorBorder.Render(body))
}

func dockerInstallGuide() string {
	var b strings.Builder

	switch runtime.GOOS {
	case "darwin":
		b.WriteString(labelStyle("Install Docker on macOS") + "\n\n")
		b.WriteString("  " + codeStyle("brew install --cask docker") + "\n\n")
		b.WriteString("  or download Docker Desktop:\n")
		b.WriteString("  " + urlStyle("https://www.docker.com/products/docker-desktop") + "\n")

	case "linux":
		b.WriteString(labelStyle("Install Docker on Linux") + "\n\n")
		b.WriteString("  " + codeStyle("sudo apt-get install docker.io") + "\n")
		b.WriteString("  " + codeStyle("sudo systemctl enable --now docker") + "\n")
		b.WriteString("  " + codeStyle("sudo usermod -aG docker $USER") + "\n\n")
		b.WriteString("  " + dimStyle("(Re-login after the usermod step)") + "\n\n")
		b.WriteString("  Or follow the official guide:\n")
		b.WriteString("  " + urlStyle("https://docs.docker.com/engine/install/") + "\n")

	case "windows":
		b.WriteString(labelStyle("Install Docker on Windows") + "\n\n")
		b.WriteString("  " + codeStyle("winget install Docker.DockerDesktop") + "\n\n")
		b.WriteString("  or download Docker Desktop:\n")
		b.WriteString("  " + urlStyle("https://www.docker.com/products/docker-desktop") + "\n")

	default:
		b.WriteString(labelStyle("Install Docker") + "\n\n")
		b.WriteString("  " + urlStyle("https://docs.docker.com/engine/install/") + "\n")
	}

	return b.String()
}

// ── helpers ───────────────────────────────────────────────────────────────────

// dockerVersion returns the Docker client version string and whether Docker is
// on PATH. Runs "docker version --format {{.Client.Version}}" to get a clean
// semver string (e.g. "27.4.0") rather than the full verbose output.
func dockerVersion() (version string, found bool) {
	path, err := exec.LookPath("docker")
	if err != nil || path == "" {
		return "", false
	}
	out, err := exec.Command("docker", "version", "--format", "{{.Client.Version}}").Output()
	if err != nil {
		// Docker is on PATH but the daemon may not be running yet; still found.
		return "found", true
	}
	ver := strings.TrimSpace(string(out))
	if ver == "" {
		return "found", true
	}
	return ver, true
}
