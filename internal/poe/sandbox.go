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
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/config"
)

// containerPort is the port the sandboxed app is expected to listen on inside
// the container — all four runtime Dockerfiles EXPOSE 8080 by convention
// (Spring Boot's default, and the convention carried over to the other three
// runtimes for consistency). Not user-configurable yet.
const containerPort = 8080

// sandbox manages one Docker container + network for the lifetime of a scan.
// One instance is created per Verifier.Run call, not per finding.
type sandbox struct {
	networkName      string
	imageTag         string
	containerID      string
	hostPort         int
	seccompStagePath string // staged copy of the embedded seccomp profile; "" if staging failed
}

// stageSeccompProfile writes the embedded seccomp policy (originally the
// Approach 3 scaffold at docker/sandbox/seccomp-profile.json, copied into
// this package so it ships inside the compiled binary via go:embed) to a
// temp file so `docker run --security-opt seccomp=<path>` can reference it.
//
// This replaced an earlier cwd-relative path lookup ("docker/sandbox/...")
// that only worked when zerotrust was invoked from the repo root — an
// installed CLI binary run from any other directory would silently skip
// the seccomp profile with no warning, a silent security-control downgrade.
// Embedding removes that failure mode entirely.
func stageSeccompProfile() (string, error) {
	f, err := os.CreateTemp("", "zt-poe-seccomp-*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(seccompProfile); err != nil {
		os.Remove(f.Name()) //nolint:errcheck
		return "", err
	}
	return f.Name(), nil
}

// boot creates an isolated bridge network and starts the container, waiting
// for the app to accept connections before returning.
func (s *sandbox) boot(ctx context.Context) error {
	port, err := pickFreePort()
	if err != nil {
		return fmt.Errorf("poe: pick free port: %w", err)
	}
	s.hostPort = port

	// Deliberately NOT --internal: an internal network isn't NAT'd, so the
	// host-side `-p` publish below never becomes reachable (confirmed via a
	// live Docker Desktop test — the container boots and listens, but every
	// connection to the published port times out). Direct-by-bridge-IP
	// access as a workaround also fails on Docker Desktop for Mac/Windows,
	// since the host-to-bridge route goes through its Linux VM, which does
	// not forward into internal networks either. A plain bridge network is
	// the only thing that gets the host a working path to the container, at
	// the accepted cost of not hard-blocking the sandboxed app's own
	// outbound internet access. That's judged acceptable here: PoE targets a
	// developer-supplied artifact for a scan the developer requested, not an
	// adversarial payload the sandbox needs to contain from a hostile actor.
	s.networkName = fmt.Sprintf("zt-poe-%d", time.Now().UnixNano())
	//nolint:gosec // networkName is generated locally, not user input
	if out, err := exec.CommandContext(ctx, "docker", "network", "create",
		s.networkName).CombinedOutput(); err != nil {
		return fmt.Errorf("poe: create network: %w\n%s", err, out)
	}

	args := []string{
		"run", "-d",
		"--name", fmt.Sprintf("%s-app", s.networkName),
		"--network", s.networkName,
		"--read-only",
		"--tmpfs", "/tmp",
		"--memory", "512m",
		"--cpus", "1.0",
		"--user", "65534:65534",
		"-p", fmt.Sprintf("127.0.0.1:%d:%d", s.hostPort, containerPort),
	}
	if stagedPath, err := stageSeccompProfile(); err != nil {
		slog.Warn("poe: could not stage seccomp profile — container will run without it", "err", err)
	} else {
		s.seccompStagePath = stagedPath
		args = append(args, "--security-opt", "seccomp="+stagedPath)
	}
	args = append(args, s.imageTag)

	//nolint:gosec // args are built from local scan state, not user network input
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		_ = s.teardownNetwork(context.Background())
		return fmt.Errorf("poe: docker run: %w\n%s", err, out)
	}
	s.containerID = trimTrailingNewline(string(out))

	return s.waitHealthy(ctx)
}

// waitHealthy polls the mapped port until the app accepts TCP connections or
// the timeout elapses. Mirrors cpg_engine/joern.go's /ready-poll pattern —
// the sandboxed app has no dedicated health endpoint, so a bare TCP dial is
// the only universal signal available across arbitrary Spring apps.
func (s *sandbox) waitHealthy(ctx context.Context) error {
	deadline := time.Now().Add(config.PoEHealthPollTimeout)
	addr := fmt.Sprintf("127.0.0.1:%d", s.hostPort)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, config.PoEHealthPollInterval)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(config.PoEHealthPollInterval):
		}
	}
	return fmt.Errorf("poe: sandbox app did not become healthy within %s", config.PoEHealthPollTimeout)
}

// baseURL returns the host-reachable base URL for firing exploit requests.
func (s *sandbox) baseURL() string {
	return "http://127.0.0.1:" + strconv.Itoa(s.hostPort)
}

// teardown stops and removes the container and network. Idempotent and
// best-effort: a leaked container is a resource nit, never silently ignored
// (always logged), but must never fail the scan itself.
func (s *sandbox) teardown(ctx context.Context) {
	if s.containerID != "" {
		// The outer Go context gets a few seconds of slack beyond docker's own
		// `-t` grace period — otherwise the CLI process itself can be SIGKILLed
		// right as `docker stop` is about to report success, turning a clean
		// stop into a spurious "docker stop failed" log (confirmed via a live
		// boot/teardown run where the two timeouts were previously equal).
		stopCtx, cancel := context.WithTimeout(ctx, config.PoEStopTimeout+5*time.Second)
		if out, err := exec.CommandContext(stopCtx, "docker", "stop", "-t",
			strconv.Itoa(int(config.PoEStopTimeout.Seconds())), s.containerID).CombinedOutput(); err != nil {
			slog.Warn("poe: docker stop failed", "err", err, "output", string(out))
		}
		cancel()
		if out, err := exec.CommandContext(ctx, "docker", "rm", "-f", s.containerID).CombinedOutput(); err != nil {
			slog.Warn("poe: docker rm failed", "err", err, "output", string(out))
		}
	}
	_ = s.teardownNetwork(ctx)
	if s.seccompStagePath != "" {
		if err := os.Remove(s.seccompStagePath); err != nil && !os.IsNotExist(err) {
			slog.Warn("poe: could not remove staged seccomp profile", "err", err, "path", s.seccompStagePath)
		}
	}
}

func (s *sandbox) teardownNetwork(ctx context.Context) error {
	if s.networkName == "" {
		return nil
	}
	if out, err := exec.CommandContext(ctx, "docker", "network", "rm", s.networkName).CombinedOutput(); err != nil {
		slog.Warn("poe: docker network rm failed", "err", err, "output", string(out))
		return err
	}
	return nil
}

// pickFreePort asks the OS for an ephemeral port by binding and immediately
// releasing it. Inherently racy (another process could grab it first) but
// this is the standard Go idiom and the window is a few milliseconds before
// `docker run -p` binds it for real.
func pickFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func trimTrailingNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// dockerAvailable reports whether the docker CLI is on PATH. Used as a
// fail-fast preflight when --verify-poc is set, matching the existing Joern
// binary-presence contract rather than silently degrading.
func dockerAvailable() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}
