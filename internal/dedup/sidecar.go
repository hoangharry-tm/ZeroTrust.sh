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

package dedup

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/hoangharry-tm/zerotrust/internal/finding"
)

// SidecarFile is the well-known project-root sidecar for user-defined suppression rules.
// Changes to this file are detected by DiffIndex on the next scan and trigger re-evaluation.
const SidecarFile = ".zerotrust-suppressions.yaml"

// SidecarEntry is one user-defined suppression rule.
// Rules are matched in order; the first match wins.
type SidecarEntry struct {
	// ID suppresses a finding by its stable dedup hash (exact match).
	ID string `yaml:"id,omitempty"`
	// Path suppresses all findings whose path matches this glob pattern.
	Path string `yaml:"path,omitempty"`
	// CWE suppresses findings with this CWE (used together with Path).
	CWE string `yaml:"cwe,omitempty"`
	// Reason is required; emitted as SuppressReason on the suppressed finding.
	Reason string `yaml:"reason"`
}

// Sidecar holds the parsed user-defined suppression rules.
type Sidecar struct {
	Suppressions []SidecarEntry `yaml:"suppressions"`
}

// LoadSidecar reads .zerotrust-suppressions.yaml from root.
// Returns an empty Sidecar (no suppressions) if the file does not exist.
func LoadSidecar(root string) Sidecar {
	if root == "" {
		return Sidecar{}
	}
	path := filepath.Join(root, SidecarFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("dedup: sidecar read error", "path", path, "err", err)
		}
		return Sidecar{}
	}
	var sc Sidecar
	if err := yaml.Unmarshal(data, &sc); err != nil {
		slog.Warn("dedup: sidecar parse error", "path", path, "err", err)
		return Sidecar{}
	}
	return sc
}

// Apply checks f against the sidecar rules.
// Returns f with SeverityLabel=SUPPRESSED and SuppressReason set if a rule matches.
func (sc *Sidecar) Apply(f finding.Finding) finding.Finding {
	for _, rule := range sc.Suppressions {
		if rule.ID != "" && f.ID != rule.ID {
			continue
		}
		if rule.Path != "" {
			matched, _ := filepath.Match(rule.Path, filepath.ToSlash(f.Path))
			if !matched {
				// Also try glob against path components for directory patterns.
				matched = globMatchPath(rule.Path, f.Path)
			}
			if !matched {
				continue
			}
		}
		if rule.CWE != "" && !strings.EqualFold(f.CWE, rule.CWE) {
			continue
		}
		f.SeverityLabel = finding.SeveritySuppressed
		f.SuppressReason = finding.SuppressReason(rule.Reason)
		return f
	}
	return f
}

// globMatchPath returns true if pattern matches any slash-separated segment of path.
func globMatchPath(pattern, path string) bool {
	p := filepath.ToSlash(path)
	for part := range strings.SplitSeq(p, "/") {
		if ok, _ := filepath.Match(pattern, part); ok {
			return true
		}
	}
	return false
}

// ── Framework-safe suppression ────────────────────────────────────────────────

// frameworkSafePatterns maps path glob patterns to the SuppressReason to emit.
// Findings whose file path matches are framework-safe: a recognised security
// control at the framework level makes exploitation infeasible without a separate
// bypass vulnerability.
var frameworkSafePatterns = []struct {
	glob   string
	reason finding.SuppressReason
}{
	// Django ORM migrations are always parameterized; SQL injection not possible.
	{"*/migrations/*.py", finding.SuppressReasonFrameworkSafe},
	// Django settings — SQL engine config, not user-controlled input.
	{"*/settings.py", finding.SuppressReasonFrameworkSafe},
	// Spring Security config classes enforce AuthZ at the framework level.
	{"*SecurityConfig.java", finding.SuppressReasonFrameworkSafe},
	{"*SecurityConfiguration.java", finding.SuppressReasonFrameworkSafe},
	// Generated protobuf/gRPC stubs — not user-authored logic.
	{"*.pb.go", finding.SuppressReasonFrameworkSafe},
	{"*_grpc.pb.go", finding.SuppressReasonFrameworkSafe},
	// Alembic/SQLAlchemy migrations — ORM always parameterizes.
	{"*/alembic/versions/*.py", finding.SuppressReasonFrameworkSafe},
	// Laravel migrations.
	{"*/database/migrations/*.php", finding.SuppressReasonFrameworkSafe},
}

// applyFrameworkSafe suppresses f if its file path matches a framework-safe pattern.
func applyFrameworkSafe(f finding.Finding) finding.Finding {
	p := filepath.ToSlash(f.Path)
	base := filepath.Base(p)
	for _, pat := range frameworkSafePatterns {
		// Try full path match first (covers directory-anchored globs like */migrations/*.py).
		if matched, _ := filepath.Match(pat.glob, p); matched {
			f.SeverityLabel = finding.SeveritySuppressed
			f.SuppressReason = pat.reason
			return f
		}
		// Fall back to matching the glob against just the base filename
		// (covers suffix patterns like *.pb.go and *SecurityConfig.java).
		if matched, _ := filepath.Match(pat.glob, base); matched {
			f.SeverityLabel = finding.SeveritySuppressed
			f.SuppressReason = pat.reason
			return f
		}
	}
	return f
}
