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

// Package tuning is the single source of truth for all numeric thresholds,
// batch sizes, depth limits, and timeouts used across the ZeroTrust pipeline.
// Change a value here and rebuild — no other file needs to be touched.
package tuning

import (
	"encoding/json"
	"os"
	"time"
)

// ── Severity band thresholds ─────────────────────────────────────────────────
// Used by finding.SeverityFromConfidence to map composite confidence → label.

const (
	ConfBlock  = 0.92
	ConfHigh   = 0.75
	ConfMedium = 0.60
	ConfLow    = 0.30
)

// ── CodeT5+ classifier gates ───────────────────────────────────────────────
// Go-side gates applied on top of the Python model output (worker/tuning.py).
// A-18: conservative until CVEFixes multi-language benchmark is complete.

const (
	ClassifierVulnerableThreshold = 0.80
	ClassifierSafeThreshold       = 0.20
	// EscalationCap is the maximum fraction of surfaces allowed to reach the LLM tier.
	EscalationCap = 0.25
)

// ── LLM Verifier / ASC ───────────────────────────────────────────────────────

const (
	// VerifierHighConfidence: findings at or above this skip LLM verification.
	VerifierHighConfidence = 0.90
	// VerifierASCThreshold: ASC is triggered when LLM confidence falls below this.
	VerifierASCThreshold = 0.70
	VerifierASCMaxRounds = 2
	// VerifierUncertainPenalty: multiplier applied to confidence on the uncertain path.
	VerifierUncertainPenalty = 0.80
)

// ── Dedup similarity ─────────────────────────────────────────────────────────

const (
	DedupEmbeddingExact    = 0.95 // cosine ≥ this → definite duplicate (Gate 3)
	DedupEmbeddingNearMiss = 0.85 // lower bound of near-miss range → escalate to Gate 4
	DedupASTEdit           = 0.85 // AST token edit similarity ≥ this → duplicate (Gate 4)
	// ponytail: circuit breaker — O(N²) pairs; raise when repos routinely exceed this
	DedupGate3MaxSurvivors = 300 // skip Gate 3 and pass straight to Gate 4 above this count
)

// ── Confidence boosts ────────────────────────────────────────────────────────

const (
	BoostCrossPath       = 0.15 // +15 pp when Path A and Path B both confirm
	BoostSSVCActive      = 0.10 // +10 pp when SSVC exploitation = Active
	BoostSSVCAutomatable = 0.05 // +5 pp when SSVC Automatable = Yes
	FloorPatternPath     = 0.60 // Path A findings never fall below MEDIUM
)

// ── CVSS → confidence mapping ────────────────────────────────────────────────

const (
	CVSSCritical       = 9.0
	CVSSHigh           = 7.0
	CVSSMedium         = 4.0
	CVSSMissingDefault = 5.0 // used when CVSSScore == 0
	ConfCVSSCritical   = 0.95
	ConfCVSSHigh       = 0.82
	ConfCVSSMedium     = 0.68
	AutoFlagCVSS       = 7.0 // Trivy/targeting auto-flag threshold
)

// ── EPSS exploitation thresholds ─────────────────────────────────────────────

const (
	EPSSPoC    = 0.1 // EPSS ≥ this → "PoC"
	EPSSActive = 0.5 // EPSS ≥ this → "Active"
)

// ── Token budget ─────────────────────────────────────────────────────────────

const (
	DefaultTokenCap     = 50_000
	BudgetWeightCVSS    = 0.4
	BudgetWeightUncert  = 0.4
	BudgetWeightDepth   = 0.2
	TokenEstCharsPerTok = 0.3 // heuristic: tokens ≈ chars × 0.3
	TokenEstOverhead    = 50  // structural prompt overhead per surface
)

// ── Batch sizes ──────────────────────────────────────────────────────────────

const (
	AssemblerBatchSize  = 5
	SummarizerBatchSize = 5
	// ClassifierBatchSize is the maximum surfaces per classify IPC call.
	// Mirrored in worker/tuning.py — keep in sync.
	ClassifierBatchSize = 8
)

// ── CPG / call-graph depth ───────────────────────────────────────────────────

const (
	AssemblerMaxDepth     = 3
	CPGDefaultMaxDepth    = 5
	CPGHardMaxDepth       = 6  // SOAP/PLDI 2025 correctness bound
	CPGHubCallerThreshold = 50 // functions with ≥ this many callers trigger full rebuild
	CPGMaxScopeLOC        = 5_000
	CPGMaxTaintPaths      = 1_000
	ModuleDepthDefault    = 2
	ModuleDepthThorough   = 3
)

// ── Path A hardcoded confidence assignments ───────────────────────────────────

const (
	ConfSchemaCheck = 0.90
	ConfLowPattern  = 0.65
	ConfMidPattern  = 0.75
)

// ── Joern subprocess timeouts ────────────────────────────────────────────────

const (
	JoernDefaultPort        = 8080
	JoernPingRetries        = 12
	JoernPingInterval       = 500 * time.Millisecond
	JoernPingTimeout        = 30 * time.Second
	JoernStopTimeout        = 5 * time.Second
	JoernQueryTimeout       = 30 * time.Second
	JoernBuildTimeout       = 900 * time.Second
	JoernResultPollInterval = 200 * time.Millisecond
	JoernScanStopTimeout    = 10 * time.Second
)

// JoernIdleTimeout is the max consecutive 202-polling duration with no
// state change before we treat Joern as frozen and surface ErrBuildTimeout.
const JoernIdleTimeout = 120 * time.Second

// ── Network / worker timeouts ────────────────────────────────────────────────

const (
	OllamaHTTPTimeout        = 120 * time.Second
	RekorHTTPTimeout         = 3 * time.Second
	KEVCacheTTL              = 24 * time.Hour
	SSVCNetTimeout           = 3 * time.Second
	WorkerStartPingTimeout   = 5 * time.Second
	WorkerRestartPingTimeout = 3 * time.Second
	WorkerShutdownTimeout    = 2 * time.Second
)

// ── Patch generation LLM options ─────────────────────────────────────────────

const (
	PatchLLMTemperature = 0.1
	PatchLLMMaxTokens   = 512
)

// ── Runtime calibration ───────────────────────────────────────────────────────

// Calibration holds scoring parameters that can be updated from labeled scan
// data via scripts/calibrate.py. Zero values in optional fields fall back to
// the compile-time constants above.
//
// Load with LoadCalibration; use DefaultCalibration when no file is provided.
type Calibration struct {
	// ClassifierVulnerableThreshold and ClassifierSafeThreshold replace the
	// compile-time CodeT5+ operating point. Surfaces between the two thresholds
	// escalate to the LLM tier.
	ClassifierVulnerableThreshold float64 `json:"classifier_vulnerable_threshold"`
	ClassifierSafeThreshold       float64 `json:"classifier_safe_threshold"`

	// CVSSPlattSlope and CVSSPlattIntercept define a Platt-scaled sigmoid for
	// CVSS → confidence mapping: σ(slope×cvss + intercept).
	// Both must be non-zero to activate; otherwise band bucketing is used.
	CVSSPlattSlope     float64 `json:"cvss_platt_slope"`
	CVSSPlattIntercept float64 `json:"cvss_platt_intercept"`

	// Budget ranking weights; must sum to 1.0.
	BudgetWeightCVSS   float64 `json:"budget_weight_cvss"`
	BudgetWeightUncert float64 `json:"budget_weight_uncert"`
	BudgetWeightDepth  float64 `json:"budget_weight_depth"`

	// Severity label thresholds (confidence → BLOCK/HIGH/MEDIUM/LOW).
	ConfBlock  float64 `json:"conf_block"`
	ConfHigh   float64 `json:"conf_high"`
	ConfMedium float64 `json:"conf_medium"`
	ConfLow    float64 `json:"conf_low"`
}

// DefaultCalibration returns a Calibration populated from the compile-time
// constants. Behaviour is identical to the pre-calibration codebase.
func DefaultCalibration() Calibration {
	return Calibration{
		ClassifierVulnerableThreshold: ClassifierVulnerableThreshold,
		ClassifierSafeThreshold:       ClassifierSafeThreshold,
		BudgetWeightCVSS:              BudgetWeightCVSS,
		BudgetWeightUncert:            BudgetWeightUncert,
		BudgetWeightDepth:             BudgetWeightDepth,
		ConfBlock:                     ConfBlock,
		ConfHigh:                      ConfHigh,
		ConfMedium:                    ConfMedium,
		ConfLow:                       ConfLow,
		// CVSSPlattSlope/Intercept intentionally zero → band bucketing fallback.
	}
}

// LoadCalibration reads a JSON calibration file produced by scripts/calibrate.py.
// If path is empty or the file does not exist, DefaultCalibration is returned
// with no error — the scanner runs with compile-time defaults unchanged.
func LoadCalibration(path string) (Calibration, error) {
	if path == "" {
		return DefaultCalibration(), nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return DefaultCalibration(), nil
	}
	if err != nil {
		return Calibration{}, err
	}
	base := DefaultCalibration()
	if err := json.Unmarshal(data, &base); err != nil {
		return Calibration{}, err
	}
	return base, nil
}
