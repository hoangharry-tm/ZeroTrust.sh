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

package joern

import "errors"

// Sentinel errors returned by the Joern client.
// Callers must use errors.Is / errors.As — never string matching.
var (
	// ErrPortInUse is returned by Start when the target port is already
	// bound by another process. The caller should retry with a different port
	// or stop the existing listener.
	ErrPortInUse = errors.New("joern: port already in use on 127.0.0.1")

	// ErrJoernUnreachable is returned by Ping when the server does not respond
	// successfully within the configured retry window.
	ErrJoernUnreachable = errors.New("joern: server unreachable after retries")

	// ErrJoernCrashed is returned when the managed subprocess has exited
	// unexpectedly. Any further method call on the client returns this error.
	// Callers should stop the client and start a fresh one.
	ErrJoernCrashed = errors.New("joern: server process exited unexpectedly")

	// ErrBuildTimeout is returned by BuildCPG when the build does not complete
	// within the configured timeout (default 120 s). Large codebases may require
	// a longer timeout via WithBuildTimeout.
	ErrBuildTimeout = errors.New("joern: CPG build timed out")

	// ErrDepthExceeded is returned by GetNeighboursAtDepth when depth > 6.
	// The bound of 6 is the taint-correctness cap from Effendi et al.
	// (SOAP/PLDI 2025, Joern core team). Callers must not pass a higher value.
	ErrDepthExceeded = errors.New("joern: BFS depth exceeds maximum of 6 (SOAP/PLDI 2025 bound)")

	// ErrHubModuleDetected is returned by IncrementalPatch when a changed
	// function has ≥ HubCallerThreshold callers. The caller must fall back to a
	// full CPG rebuild via BuildCPG.
	ErrHubModuleDetected = &hubModuleError{}

	// ErrMalformedResponse is returned when the server's HTTP response cannot
	// be parsed as the expected JSON schema. The raw body is included in the
	// wrapped error for debuggability.
	ErrMalformedResponse = errors.New("joern: malformed response from server")

	// ErrPathTraversal is returned by BuildCPG when any entry in BuildConfig.Paths
	// contains a ".." component, which could escape the project root.
	ErrPathTraversal = errors.New("joern: path contains traversal component (../)")

	// ErrEmptyCPG is returned by BuildCPG when the verification query
	// (cpg.method.size) returns zero — no methods were parsed, indicating a
	// wrong frontend, unreachable source files, or an empty project.
	// ponytail: zero-method threshold only — file count vs ingested count
	// check deferred
	ErrEmptyCPG = errors.New("joern: CPG built but contains zero methods — check frontend and file paths")

	// ErrEmptyPaths is returned by BuildCPG when BuildConfig.Paths is empty.
	ErrEmptyPaths = errors.New("joern: BuildConfig.Paths must not be empty")

	// ErrAlreadyStarted is returned by Start when a subprocess is already
	// running under this client. Call Stop first.
	ErrAlreadyStarted = errors.New("joern: subprocess already running — call Stop first")

	// ErrNotManaged is returned by Stop when the client was not started with
	// Start (i.e. it connects to an externally managed Joern instance).
	ErrNotManaged = errors.New("joern: no managed subprocess — this client connects to an external server")

	// ErrInvalidServerURL is returned by New when the server URL resolves to a
	// non-localhost host. Remote Joern instances are not supported; all CPG
	// communication must stay on loopback.
	ErrInvalidServerURL = errors.New("joern: server URL must be localhost (127.0.0.1 / ::1) — remote instances are not supported")
)

// hubModuleError is the concrete type behind ErrHubModuleDetected.
// It is a pointer type so errors.Is works correctly.
type hubModuleError struct{}

func (e *hubModuleError) Error() string {
	return "joern: hub module detected — incremental patch aborted, full rebuild required"
}
