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
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func (p *Pipeline) resolvePortConflict(ctx context.Context) {
	port := joernPortFromURL(p.cfg.JoernURL)
	if port <= 0 {
		port = 8080
	}

	p.logger.Warn("resolving joern port conflict",
		"port", port, "joern_url", p.cfg.JoernURL)

	pid, name, lsofErr := findProcessOnPort(port)
	if lsofErr != nil || pid == 0 {
		p.logger.Warn("joern port in use — cannot identify process, taint analysis disabled",
			"port", port, "err", lsofErr)
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
		p.logger.Warn("joern port in use, declined to kill — taint analysis disabled",
			"port", port, "pid", pid, "process", name)
		return
	}

	p.logger.Info("killing process on joern port", "pid", pid, "port", port, "process", name)
	if killErr := syscall.Kill(pid, syscall.SIGTERM); killErr != nil {
		p.logger.Warn("failed to kill process on joern port — taint analysis disabled",
			"pid", pid, "port", port, "err", killErr)
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
		p.logger.Warn("joern retry after killing port owner failed — taint analysis disabled",
			"port", port, "err", retryErr)
	}
}

// joernPortFromURL extracts the TCP port from a Joern URL string.
// Returns 0 if the URL cannot be parsed.
func joernPortFromURL(rawURL string) int {
	slog.Debug("extracting port from joern URL", "url", rawURL)
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
	slog.Debug("finding process on port", "port", port)
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
