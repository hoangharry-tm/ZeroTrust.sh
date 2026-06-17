// Package miv implements the Model Integrity Verifier.
//
// At startup MIV hashes the local GGUF model file and verifies it against a
// cosign/Sigstore Rekor signed registry. The registry is a JSON file bundled
// with the binary, signed with a project-controlled ECDSA P-256 key whose
// public half is embedded at build time.
//
// Tiered response (ICML 2025 GGUF backdoor threat model):
//   - PASS:  known model ID, hash matches the signed registry → LLM proceeds.
//   - WARN:  unrecognised model ID (user's own model) → LLM proceeds after opt-in.
//   - BLOCK: known model ID, hash mismatch → all LLM calls are skipped; CPG and
//     pattern matching continue unaffected.
//
// MIV gates only LLM invocations. Joern CPG builds, OpenGrep / ast-grep pattern
// scans, and the HTML report are never blocked.
//
// Verification flow:
//  1. SHA-256 hash the GGUF file (streaming in 32 MB chunks).
//  2. Parse the GGUF header to extract the model ID (general.name).
//  3. Verify the bundled registry signature:
//     a. Primary: look up the registry hash in Sigstore Rekor (3s timeout).
//     b. Fallback: verify ECDSA P-256 signature against the embedded public key.
//     Registry signature must pass before hash comparison is trusted.
//  4. Look up the model ID in the verified registry.
//  5. Compare hashes → PASS / WARN / BLOCK.
package miv

import (
	_ "embed"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

//go:embed data/registry.json
var embeddedRegistry []byte

//go:embed data/registry.json.sig
var embeddedRegistrySig []byte

//go:embed data/cosign.pub
var embeddedPublicKey []byte

// ErrNotGGUF is returned by readGGUFModelID when the file is not a valid GGUF.
var ErrNotGGUF = errors.New("not a GGUF file")

// Status is the tiered verification outcome.
type Status string

const (
	// StatusPass means the model is known and its hash matches the signed registry.
	StatusPass Status = "PASS"
	// StatusWarn means the model ID is unrecognised; user opt-in is required.
	StatusWarn Status = "WARN"
	// StatusBlock means the model ID is known but its hash mismatches the registry.
	// All LLM invocations must be skipped when this status is returned.
	StatusBlock Status = "BLOCK"
)

// Result is returned by Verify.
type Result struct {
	// Status is the tiered outcome (PASS / WARN / BLOCK).
	Status Status
	// ModelID is the identifier extracted from the GGUF metadata header.
	ModelID string
	// ActualHash is the SHA-256 hex digest of the model file that was checked.
	ActualHash string
	// ExpectedHash is the hash from the signed registry (empty for WARN/unrecognised).
	ExpectedHash string
	// Message is a human-readable description of the outcome, shown in the report header.
	Message string
}

// RegistryEntry is one record in the signed JSON model hash registry.
//
// Example registry entry:
//
//	{
//	  "model_id": "llama3.2:3b-instruct-q4_K_M",
//	  "sha256":   "a3f7c...",
//	  "source":   "https://ollama.com/library/llama3.2",
//	  "added_at": "2025-09-01"
//	}
type RegistryEntry struct {
	// ModelID is the Ollama model tag (e.g. "llama3.2:3b-instruct-q4_K_M").
	ModelID string `json:"model_id"`
	// SHA256 is the expected SHA-256 hex digest of the GGUF file.
	SHA256 string `json:"sha256"`
	// Source is the canonical download URL for the model.
	Source string `json:"source"`
	// AddedAt is the ISO-8601 date when the entry was added to the registry.
	AddedAt string `json:"added_at"`
}

// Verifier hashes the GGUF model file and compares it against the signed registry.
type Verifier struct {
	registryPath  string // if empty, uses embeddedRegistry
	publicKeyPath string // if empty, uses embeddedPublicKey
	rekorURL      string // Sigstore Rekor base URL; injectable for tests
	httpClient    *http.Client
}

// New returns a Verifier using the bundled registry and public key at the given paths.
// Passing empty strings causes the embedded defaults to be used.
//
// Parameters:
//   - registryPath: path to the signed model hash registry JSON file.
//   - publicKeyPath: path to the cosign public key (.pub) for registry verification.
func New(registryPath, publicKeyPath string) *Verifier {
	return &Verifier{
		registryPath:  registryPath,
		publicKeyPath: publicKeyPath,
		rekorURL:      "https://rekor.sigstore.dev",
		httpClient:    &http.Client{Timeout: 5 * time.Second},
	}
}

// Verify runs the full integrity check pipeline for the model at modelPath:
//  1. SHA-256 hash the GGUF file.
//  2. Extract the model ID from the GGUF metadata (general.name).
//  3. Verify the registry signature (Rekor primary, ECDSA fallback).
//  4. Look up the model ID in the verified registry.
//  5. Compare hashes → PASS / WARN / BLOCK.
//
// WARN does not block; BLOCK stops all LLM invocations.
//
// Parameters:
//   - ctx: cancellation context; hashing a large GGUF file may take several seconds.
//   - modelPath: absolute path to the GGUF model file on disk.
//
// Returns:
//   - *Result: the verification outcome with status, hashes, and message.
//   - error: non-nil only for infrastructure failures (file unreadable, registry malformed).
func (v *Verifier) Verify(ctx context.Context, modelPath string) (*Result, error) {
	// 1. Hash the GGUF file.
	actualHash, err := hashGGUF(ctx, modelPath)
	if err != nil {
		return nil, fmt.Errorf("hash model file: %w", err)
	}

	// 2. Extract model ID from GGUF metadata.
	modelID, err := readGGUFModelID(modelPath)
	if err != nil {
		// Not a GGUF or unsupported version — WARN; user may opt in.
		msg := "unrecognised model format; cannot verify integrity — LLM proceeds after user opt-in"
		if !errors.Is(err, ErrNotGGUF) {
			msg = fmt.Sprintf("GGUF parse error (%v); cannot verify integrity — LLM proceeds after user opt-in", err)
		}
		return &Result{
			Status:     StatusWarn,
			ActualHash: actualHash,
			Message:    msg,
		}, nil
	}

	// 3. Load and verify the registry signature.
	entries, err := v.LoadRegistry(ctx)
	if err != nil {
		return nil, fmt.Errorf("load registry: %w", err)
	}

	// 4+5. Look up model ID and compare hashes.
	for _, e := range entries {
		if strings.EqualFold(e.ModelID, modelID) {
			if e.SHA256 == actualHash {
				return &Result{
					Status:       StatusPass,
					ModelID:      modelID,
					ActualHash:   actualHash,
					ExpectedHash: e.SHA256,
					Message:      "model integrity verified — hash matches signed registry",
				}, nil
			}
			return &Result{
				Status:       StatusBlock,
				ModelID:      modelID,
				ActualHash:   actualHash,
				ExpectedHash: e.SHA256,
				Message:      fmt.Sprintf("hash mismatch for known model %q — all LLM calls blocked", modelID),
			}, nil
		}
	}

	// Model not in registry → WARN.
	return &Result{
		Status:     StatusWarn,
		ModelID:    modelID,
		ActualHash: actualHash,
		Message:    fmt.Sprintf("model %q not in signed registry — LLM proceeds after user opt-in", modelID),
	}, nil
}
