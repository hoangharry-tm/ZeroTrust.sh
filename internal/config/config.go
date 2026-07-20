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

// Package config is the single source of truth for all numeric thresholds,
// batch sizes, depth limits, and LLM parameters used across the ZeroTrust
// pipeline. Values are loaded from calibration.json at startup; compile-time
// defaults are used when no file is provided.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/go-playground/validator/v10"
)

// Config holds every numeric parameter that crosses a process boundary or is
// produced by the calibration script.
type Config struct {
	// ── Severity band thresholds ────────────────────────────────────────────────
	ConfBlock  float64 `json:"conf_block"  validate:"gte=0,lte=1"`
	ConfHigh   float64 `json:"conf_high"   validate:"gte=0,lte=1"`
	ConfMedium float64 `json:"conf_medium" validate:"gte=0,lte=1"`
	ConfLow    float64 `json:"conf_low"    validate:"gte=0,lte=1"`

	// ── CodeT5+ classifier gates ─────────────────────────────────────────────────
	ClassifierVulnerableThreshold float64 `json:"classifier_vulnerable_threshold" validate:"gte=0,lte=1"`
	ClassifierSafeThreshold       float64 `json:"classifier_safe_threshold"       validate:"gte=0,lte=1"`
	EscalationCap                 float64 `json:"escalation_cap"                  validate:"gte=0,lte=1"`
	ClassifierBatchSize           int     `json:"classifier_batch_size"           validate:"gte=1"`
	ClassifierMaxLength           int     `json:"classifier_max_length"           validate:"gte=1"`
	ClassifierHiddenSize          int     `json:"classifier_hidden_size"          validate:"gte=1"`

	// ── LLM Verifier / ASC ───────────────────────────────────────────────────────
	VerifierHighConfidence   float64 `json:"verifier_high_confidence"   validate:"gte=0,lte=1"`
	VerifierASCThreshold     float64 `json:"verifier_asc_threshold"     validate:"gte=0,lte=1"`
	VerifierASCMaxRounds     int     `json:"verifier_asc_max_rounds"    validate:"gte=1"`
	VerifierUncertainPenalty float64 `json:"verifier_uncertain_penalty" validate:"gte=0,lte=1"`

	// ── Dedup similarity ─────────────────────────────────────────────────────────
	DedupEmbeddingExact    float64 `json:"dedup_embedding_exact"     validate:"gte=0,lte=1"`
	DedupEmbeddingNearMiss float64 `json:"dedup_embedding_near_miss" validate:"gte=0,lte=1"`
	DedupASTEdit           float64 `json:"dedup_ast_edit"            validate:"gte=0,lte=1"`
	// ponytail: circuit breaker — O(N²) pairs; raise when repos routinely exceed this
	DedupGate3MaxSurvivors int `json:"dedup_gate3_max_survivors" validate:"gte=0"`

	// ── Confidence boosts ────────────────────────────────────────────────────────
	BoostCrossPath       float64 `json:"boost_cross_path"        validate:"gte=0,lte=1"`
	BoostSSVCActive      float64 `json:"boost_ssvc_active"       validate:"gte=0,lte=1"`
	BoostSSVCAutomatable float64 `json:"boost_ssvc_automatable"  validate:"gte=0,lte=1"`
	FloorPatternPath     float64 `json:"floor_pattern_path"      validate:"gte=0,lte=1"`

	// ── CVSS → confidence mapping ────────────────────────────────────────────────
	CVSSCritical       float64 `json:"cvss_critical"        validate:"gte=0,lte=10"`
	CVSSHigh           float64 `json:"cvss_high"            validate:"gte=0,lte=10"`
	CVSSMedium         float64 `json:"cvss_medium"          validate:"gte=0,lte=10"`
	CVSSMissingDefault float64 `json:"cvss_missing_default" validate:"gte=0,lte=10"`
	ConfCVSSCritical   float64 `json:"conf_cvss_critical"   validate:"gte=0,lte=1"`
	ConfCVSSHigh       float64 `json:"conf_cvss_high"       validate:"gte=0,lte=1"`
	ConfCVSSMedium     float64 `json:"conf_cvss_medium"     validate:"gte=0,lte=1"`
	AutoFlagCVSS       float64 `json:"auto_flag_cvss"       validate:"gte=0,lte=10"`

	// Platt sigmoid for CVSS→confidence (both zero → band bucketing).
	CVSSPlattSlope     float64 `json:"cvss_platt_slope"     validate:"gte=0"`
	CVSSPlattIntercept float64 `json:"cvss_platt_intercept"`

	// ── EPSS exploitation thresholds ─────────────────────────────────────────────
	EPSSPoC    float64 `json:"epss_poc"    validate:"gte=0,lte=1"`
	EPSSActive float64 `json:"epss_active" validate:"gte=0,lte=1"`

	// ── Token budget ─────────────────────────────────────────────────────────────
	DefaultTokenCap     int     `json:"default_token_cap"      validate:"gte=1"`
	BudgetWeightCVSS    float64 `json:"budget_weight_cvss"     validate:"gte=0,lte=1"`
	BudgetWeightUncert  float64 `json:"budget_weight_uncert"   validate:"gte=0,lte=1"`
	BudgetWeightDepth   float64 `json:"budget_weight_depth"    validate:"gte=0,lte=1"`
	BudgetWeightKind    float64 `json:"budget_weight_kind"     validate:"gte=0,lte=1"`
	TokenEstCharsPerTok float64 `json:"token_est_chars_per_tok" validate:"gte=0"`
	TokenEstOverhead    int     `json:"token_est_overhead"     validate:"gte=0"`

	// ── Batch sizes ──────────────────────────────────────────────────────────────
	AssemblerBatchSize             int `json:"assembler_batch_size"               validate:"gte=1"`
	SummarizerBatchSize            int `json:"summarizer_batch_size"              validate:"gte=1"`
	SummarizerMaxFunctionsPerBatch int `json:"summarizer_max_functions_per_batch" validate:"gte=1"`

	// ── CPG / call-graph depth ───────────────────────────────────────────────────
	AssemblerMaxDepth     int `json:"assembler_max_depth"      validate:"gte=1"`
	CPGDefaultMaxDepth    int `json:"cpg_default_max_depth"    validate:"gte=1"`
	CPGHardMaxDepth       int `json:"cpg_hard_max_depth"       validate:"gte=1"` // SOAP/PLDI 2025 correctness bound
	CPGHubCallerThreshold int `json:"cpg_hub_caller_threshold" validate:"gte=1"`
	CPGMaxScopeLOC        int `json:"cpg_max_scope_loc"        validate:"gte=1000"`
	CPGMaxTaintPaths      int `json:"cpg_max_taint_paths"      validate:"gte=1"`
	ModuleDepthDefault    int `json:"module_depth_default"     validate:"gte=0"`
	ModuleDepthThorough   int `json:"module_depth_thorough"    validate:"gte=0"`

	// ── Path A hardcoded confidence assignments ───────────────────────────────────
	ConfSchemaCheck float64 `json:"conf_schema_check" validate:"gte=0,lte=1"`
	ConfLowPattern  float64 `json:"conf_low_pattern"  validate:"gte=0,lte=1"`
	ConfMidPattern  float64 `json:"conf_mid_pattern"  validate:"gte=0,lte=1"`

	// ── Patch generation LLM options ─────────────────────────────────────────────
	PatchLLMTemperature float64 `json:"patch_llm_temperature" validate:"gte=0,lte=2"`
	PatchLLMMaxTokens   int     `json:"patch_llm_max_tokens"  validate:"gte=1"`
	GeneratePatches     bool    `mapstructure:"generate_patches"`

	// ── Joern (non-Duration) ──────────────────────────────────────────────────────
	JoernDefaultPort         int `json:"joern_default_port"          validate:"gte=1,lte=65535"`
	JoernPingRetries         int `json:"joern_ping_retries"          validate:"gte=1"`
	JoernQueryTimeoutSeconds int `json:"joern_query_timeout_seconds" validate:"gte=1"`

	// ── Python worker thresholds (shared via ZT_CONFIG_PATH) ─────────────────────
	LLMVerifyTemperature    float64   `json:"llm_verify_temperature"     validate:"gte=0,lte=2"`
	LLMVerifyMaxPredict     int       `json:"llm_verify_max_predict"     validate:"gte=1"`
	ASCTemperatures         []float64 `json:"asc_temperatures"           validate:"dive,gte=0,lte=2"`
	ASCMaxRounds            int       `json:"asc_max_rounds"             validate:"gte=1"`
	ASCConfidenceThreshold  float64   `json:"asc_confidence_threshold"   validate:"gte=0,lte=1"`
	OllamaTimeoutSeconds    int       `json:"ollama_timeout_seconds"     validate:"gte=1"`
	VerdictMaxJustification int       `json:"verdict_max_justification_len" validate:"gte=1"`
}

// ── Joern subprocess timeouts ────────────────────────────────────────────────
const (
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
// Set below JoernQueryTimeout (30 s) so freeze detection fires before the
// per-query context deadline — if Joern returns 202 for 20+ consecutive
// seconds it is likely in a GC-deadlock or OOM state.
const JoernIdleTimeout = 90 * time.Second

// ── Network / worker timeouts ─────────────────────────────────────────────────
const (
	OllamaHTTPTimeout        = 120 * time.Second
	RekorHTTPTimeout         = 3 * time.Second
	KEVCacheTTL              = 24 * time.Hour
	SSVCNetTimeout           = 3 * time.Second
	WorkerStartPingTimeout   = 5 * time.Second
	WorkerRestartPingTimeout = 3 * time.Second
	WorkerShutdownTimeout    = 2 * time.Second
)

// C is the process-wide config singleton, pre-loaded with compile-time defaults.
//
// Deprecated: prefer constructing Config explicitly with New and passing it
// to pipeline stages. This global exists for backward compatibility during the
// incremental migration away from package-level mutable state; it will be
// removed in a future release.
var C = defaultConfig()

// Default returns a Config populated from the compile-time constants.
// Behaviour is identical to the pre-calibration codebase.
//
// Deprecated: use New() to get a validated Config instead.
func Default() Config { return defaultConfig() }

func defaultConfig() Config {
	return Config{
		ConfBlock:  0.92,
		ConfHigh:   0.75,
		ConfMedium: 0.60,
		ConfLow:    0.30,

		ClassifierVulnerableThreshold: 0.80,
		ClassifierSafeThreshold:       0.20,
		EscalationCap:                 0.25,
		ClassifierBatchSize:           8,
		ClassifierMaxLength:           1024,
		ClassifierHiddenSize:          1024,

		VerifierHighConfidence:   0.90,
		VerifierASCThreshold:     0.70,
		VerifierASCMaxRounds:     2,
		VerifierUncertainPenalty: 0.80,

		DedupEmbeddingExact:    0.95,
		DedupEmbeddingNearMiss: 0.85,
		DedupASTEdit:           0.85,
		DedupGate3MaxSurvivors: 300,

		BoostCrossPath:       0.15,
		BoostSSVCActive:      0.10,
		BoostSSVCAutomatable: 0.05,
		FloorPatternPath:     0.60,

		CVSSCritical:       9.0,
		CVSSHigh:           7.0,
		CVSSMedium:         4.0,
		CVSSMissingDefault: 5.0,
		ConfCVSSCritical:   0.95,
		ConfCVSSHigh:       0.82,
		ConfCVSSMedium:     0.68,
		AutoFlagCVSS:       7.0,

		EPSSPoC:    0.1,
		EPSSActive: 0.5,

		DefaultTokenCap:     50_000,
		BudgetWeightCVSS:    0.4,
		BudgetWeightUncert:  0.4,
		BudgetWeightDepth:   0.2,
		BudgetWeightKind:    0.3,
		TokenEstCharsPerTok: 0.3,
		TokenEstOverhead:    50,

		AssemblerBatchSize:  5,
		SummarizerBatchSize: 5,

		AssemblerMaxDepth:     3,
		CPGDefaultMaxDepth:    5,
		CPGHardMaxDepth:       6,
		CPGHubCallerThreshold: 50,
		CPGMaxScopeLOC:        50_000,
		CPGMaxTaintPaths:      1_000,
		ModuleDepthDefault:    2,
		ModuleDepthThorough:   3,

		ConfSchemaCheck: 0.90,
		ConfLowPattern:  0.65,
		ConfMidPattern:  0.75,

		PatchLLMTemperature: 0.1,
		PatchLLMMaxTokens:   512,
		GeneratePatches:     false,

		JoernDefaultPort:         8080,
		JoernPingRetries:         12,
		JoernQueryTimeoutSeconds: 120,

		LLMVerifyTemperature:    0.1,
		LLMVerifyMaxPredict:     300,
		ASCTemperatures:         []float64{0.35, 0.6},
		ASCMaxRounds:            2,
		ASCConfidenceThreshold:  0.70,
		OllamaTimeoutSeconds:    30,
		VerdictMaxJustification: 200,
	}
}

// validate is the shared validator instance, cached for performance.
var validate = validator.New()

// Validate checks that all Config fields are within their expected bounds.
// Returns a single error summarising all violations, or nil.
func (cfg Config) Validate() error {
	if err := validate.Struct(cfg); err != nil {
		return fmt.Errorf("config validate: %w", err)
	}
	return nil
}

// New returns a validated Config populated from the compile-time defaults.
// It panics on validation failure so the caller can be confident the returned
// Config is safe to use. Production code should call Load instead.
func New() Config {
	cfg := defaultConfig()
	if err := cfg.Validate(); err != nil {
		panic("config.New: " + err.Error())
	}
	return cfg
}

// Load reads a JSON calibration file and merges it over the defaults.
// If path is empty or the file does not exist, the defaults are returned
// with no error. The returned Config is validated before being returned.
func Load(path string) (Config, error) {
	if path == "" {
		return defaultConfig(), nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return defaultConfig(), nil
	}
	if err != nil {
		return Config{}, err
	}
	base := defaultConfig()
	if err := json.Unmarshal(data, &base); err != nil {
		return Config{}, err
	}
	if err := base.Validate(); err != nil {
		return Config{}, err
	}
	return base, nil
}

// Set replaces the global singleton. Call once at startup after Load.
//
// Deprecated: pass Config explicitly instead of relying on the global.
func Set(cfg Config) { C = cfg }
