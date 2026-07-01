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
//
// Usage:
//
//	cfg, _ := config.Load(path)   // in main
//	config.Set(cfg)               // installs the singleton
//	config.C.ConfBlock            // everywhere else
package config

import (
	"encoding/json"
	"os"
)

// Config holds every numeric parameter that crosses a process boundary or is
// produced by the calibration script. time.Duration constants are intentionally
// excluded — they live in internal/tuning and require a rebuild to change.
type Config struct {
	// ── Severity band thresholds ────────────────────────────────────────────────
	ConfBlock  float64 `json:"conf_block"`
	ConfHigh   float64 `json:"conf_high"`
	ConfMedium float64 `json:"conf_medium"`
	ConfLow    float64 `json:"conf_low"`

	// ── CodeT5+ classifier gates ─────────────────────────────────────────────────
	ClassifierVulnerableThreshold float64 `json:"classifier_vulnerable_threshold"`
	ClassifierSafeThreshold       float64 `json:"classifier_safe_threshold"`
	EscalationCap                 float64 `json:"escalation_cap"`
	ClassifierBatchSize           int     `json:"classifier_batch_size"`
	ClassifierMaxLength           int     `json:"classifier_max_length"`
	ClassifierHiddenSize          int     `json:"classifier_hidden_size"`

	// ── LLM Verifier / ASC ───────────────────────────────────────────────────────
	VerifierHighConfidence   float64 `json:"verifier_high_confidence"`
	VerifierASCThreshold     float64 `json:"verifier_asc_threshold"`
	VerifierASCMaxRounds     int     `json:"verifier_asc_max_rounds"`
	VerifierUncertainPenalty float64 `json:"verifier_uncertain_penalty"`

	// ── Dedup similarity ─────────────────────────────────────────────────────────
	DedupEmbeddingExact    float64 `json:"dedup_embedding_exact"`
	DedupEmbeddingNearMiss float64 `json:"dedup_embedding_near_miss"`
	DedupASTEdit           float64 `json:"dedup_ast_edit"`
	// ponytail: circuit breaker — O(N²) pairs; raise when repos routinely exceed this
	DedupGate3MaxSurvivors int `json:"dedup_gate3_max_survivors"`

	// ── Confidence boosts ────────────────────────────────────────────────────────
	BoostCrossPath       float64 `json:"boost_cross_path"`
	BoostSSVCActive      float64 `json:"boost_ssvc_active"`
	BoostSSVCAutomatable float64 `json:"boost_ssvc_automatable"`
	FloorPatternPath     float64 `json:"floor_pattern_path"`

	// ── CVSS → confidence mapping ────────────────────────────────────────────────
	CVSSCritical       float64 `json:"cvss_critical"`
	CVSSHigh           float64 `json:"cvss_high"`
	CVSSMedium         float64 `json:"cvss_medium"`
	CVSSMissingDefault float64 `json:"cvss_missing_default"`
	ConfCVSSCritical   float64 `json:"conf_cvss_critical"`
	ConfCVSSHigh       float64 `json:"conf_cvss_high"`
	ConfCVSSMedium     float64 `json:"conf_cvss_medium"`
	AutoFlagCVSS       float64 `json:"auto_flag_cvss"`

	// Platt sigmoid for CVSS→confidence (both zero → band bucketing).
	CVSSPlattSlope     float64 `json:"cvss_platt_slope"`
	CVSSPlattIntercept float64 `json:"cvss_platt_intercept"`

	// ── EPSS exploitation thresholds ─────────────────────────────────────────────
	EPSSPoC    float64 `json:"epss_poc"`
	EPSSActive float64 `json:"epss_active"`

	// ── Token budget ─────────────────────────────────────────────────────────────
	DefaultTokenCap     int     `json:"default_token_cap"`
	BudgetWeightCVSS    float64 `json:"budget_weight_cvss"`
	BudgetWeightUncert  float64 `json:"budget_weight_uncert"`
	BudgetWeightDepth   float64 `json:"budget_weight_depth"`
	TokenEstCharsPerTok float64 `json:"token_est_chars_per_tok"`
	TokenEstOverhead    int     `json:"token_est_overhead"`

	// ── Batch sizes ──────────────────────────────────────────────────────────────
	AssemblerBatchSize  int `json:"assembler_batch_size"`
	SummarizerBatchSize int `json:"summarizer_batch_size"`

	// ── CPG / call-graph depth ───────────────────────────────────────────────────
	AssemblerMaxDepth     int `json:"assembler_max_depth"`
	CPGDefaultMaxDepth    int `json:"cpg_default_max_depth"`
	CPGHardMaxDepth       int `json:"cpg_hard_max_depth"` // SOAP/PLDI 2025 correctness bound
	CPGHubCallerThreshold int `json:"cpg_hub_caller_threshold"`
	CPGMaxScopeLOC        int `json:"cpg_max_scope_loc"`
	CPGMaxTaintPaths      int `json:"cpg_max_taint_paths"`
	ModuleDepthDefault    int `json:"module_depth_default"`
	ModuleDepthThorough   int `json:"module_depth_thorough"`

	// ── Path A hardcoded confidence assignments ───────────────────────────────────
	ConfSchemaCheck float64 `json:"conf_schema_check"`
	ConfLowPattern  float64 `json:"conf_low_pattern"`
	ConfMidPattern  float64 `json:"conf_mid_pattern"`

	// ── Patch generation LLM options ─────────────────────────────────────────────
	PatchLLMTemperature float64 `json:"patch_llm_temperature"`
	PatchLLMMaxTokens   int     `json:"patch_llm_max_tokens"`

	// ── Joern (non-Duration) ──────────────────────────────────────────────────────
	JoernDefaultPort         int `json:"joern_default_port"`
	JoernPingRetries         int `json:"joern_ping_retries"`
	JoernQueryTimeoutSeconds int `json:"joern_query_timeout_seconds"`

	// ── Python worker thresholds (shared via ZT_CONFIG_PATH) ─────────────────────
	LLMVerifyTemperature    float64   `json:"llm_verify_temperature"`
	LLMVerifyMaxPredict     int       `json:"llm_verify_max_predict"`
	ASCTemperatures         []float64 `json:"asc_temperatures"`
	ASCMaxRounds            int       `json:"asc_max_rounds"`
	ASCConfidenceThreshold  float64   `json:"asc_confidence_threshold"`
	OllamaTimeoutSeconds    int       `json:"ollama_timeout_seconds"`
	VerdictMaxJustification int       `json:"verdict_max_justification_len"`
}

// C is the process-wide config singleton, pre-loaded with compile-time defaults.
// Call Set after Load to replace it before any pipeline stage runs.
var C = Default()

// Set replaces the singleton. Call once at startup after Load.
func Set(cfg Config) { C = cfg }

// Default returns a Config populated from the compile-time constants.
// Behaviour is identical to the pre-calibration codebase.
func Default() Config {
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
		TokenEstCharsPerTok: 0.3,
		TokenEstOverhead:    50,

		AssemblerBatchSize:  5,
		SummarizerBatchSize: 5,

		AssemblerMaxDepth:     3,
		CPGDefaultMaxDepth:    5,
		CPGHardMaxDepth:       6,
		CPGHubCallerThreshold: 50,
		CPGMaxScopeLOC:        5_000,
		CPGMaxTaintPaths:      1_000,
		ModuleDepthDefault:    2,
		ModuleDepthThorough:   3,

		ConfSchemaCheck: 0.90,
		ConfLowPattern:  0.65,
		ConfMidPattern:  0.75,

		PatchLLMTemperature: 0.1,
		PatchLLMMaxTokens:   512,

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

// Load reads a JSON calibration file and merges it over Default.
// If path is empty or the file does not exist, Default is returned with no error.
func Load(path string) (Config, error) {
	if path == "" {
		return Default(), nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, err
	}
	base := Default()
	if err := json.Unmarshal(data, &base); err != nil {
		return Config{}, err
	}
	return base, nil
}
