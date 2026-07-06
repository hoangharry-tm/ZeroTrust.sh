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

package pipeline

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hoangharry-tm/zerotrust/internal/output"
)

func (p *Pipeline) resolvePortConflict(ctx context.Context) {
	port := joernPortFromURL(p.cfg.JoernURL)
	if port <= 0 {
		port = 8080
	}

	pid, name, lsofErr := findProcessOnPort(port)
	if lsofErr != nil || pid == 0 {
		output.Emit(p.events, output.Event{
			Kind: output.EventLog,
			Log:  fmt.Sprintf("warn: joern port %d in use — cannot identify process: %v — taint analysis disabled", port, lsofErr),
		})
		return
	}

	fmt.Fprintf(os.Stderr, "\nJoern port %d is in use by PID %d (%s)\n", port, pid, name)
	fmt.Fprintf(os.Stderr, "Kill it and retry? [y/N] ")

	var buf [1]byte
	var interactive bool
	if stat, statErr := os.Stdin.Stat(); statErr == nil && stat.Mode()&os.ModeCharDevice != 0 {
		_, err := io.ReadFull(os.Stdin, buf[:1])
		interactive = err == nil
	}

	if !interactive || (buf[0] != 'y' && buf[0] != 'Y') {
		fmt.Fprintln(os.Stderr)
		output.Emit(p.events, output.Event{
			Kind: output.EventLog,
			Log:  fmt.Sprintf("warn: joern port %d in use by PID %d (%s) — taint analysis disabled", port, pid, name),
		})
		return
	}

	if killErr := syscall.Kill(pid, syscall.SIGTERM); killErr != nil {
		output.Emit(p.events, output.Event{
			Kind: output.EventLog,
			Log:  fmt.Sprintf("warn: failed to kill PID %d on port %d: %v — taint analysis disabled", pid, port, killErr),
		})
		return
	}

	// ponytail: poll until port is free — JVMs take 2–10s to release after SIGTERM
	portAddr := fmt.Sprintf("127.0.0.1:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		c, dialErr := net.DialTimeout("tcp", portAddr, 100*time.Millisecond)
		if dialErr != nil {
			break // port is free
		}
		c.Close()
	}

	if retryErr := p.joern.Start(ctx); retryErr != nil {
		output.Emit(p.events, output.Event{
			Kind: output.EventLog,
			Log:  fmt.Sprintf("warn: joern retry after killing port %d failed: %v — taint analysis disabled", port, retryErr),
		})
	}
}

// joernPortFromURL extracts the TCP port from a Joern URL string.
// Returns 0 if the URL cannot be parsed.
func joernPortFromURL(rawURL string) int {
	if !strings.Contains(rawURL, ":") {
		return 0
	}
	// Strip scheme prefix if present.
	hostPort := rawURL
	if strings.HasPrefix(hostPort, "http://") {
		hostPort = hostPort[7:]
	} else if strings.HasPrefix(hostPort, "https://") {
		hostPort = hostPort[8:]
	}
	// hostPort is now "host:port/path" or "host:port".
	if idx := strings.IndexByte(hostPort, ':'); idx >= 0 {
		rest := hostPort[idx+1:]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			rest = rest[:slash]
		}
		if p, err := strconv.Atoi(rest); err == nil {
			return p
		}
	}
	return 0
}

// findProcessOnPort returns the PID and process name of the process bound to
// the given TCP port. Returns (0, "", error) if the process cannot be identified.
func findProcessOnPort(port int) (int, string, error) {
	if _, err := exec.LookPath("lsof"); err != nil {
		return 0, "", fmt.Errorf("lsof not found: %w", err)
	}
	cmd := exec.Command("lsof", "-ti", "tcp:"+strconv.Itoa(port))
	pidOut, err := cmd.Output()
	if err != nil || len(pidOut) == 0 {
		return 0, "", fmt.Errorf("lsof: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidOut)))
	if err != nil || pid == 0 {
		return 0, "", fmt.Errorf("parse pid from lsof: %w", err)
	}

	nameOut, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return pid, "unknown", nil
	}

	return pid, strings.TrimSpace(string(nameOut)), nil
}

// close shuts down all managed subprocesses and releases held resources.
// Always called after run() returns, even on error.
