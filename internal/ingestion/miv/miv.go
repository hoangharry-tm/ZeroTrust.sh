// Package miv implements the Model Integrity Verifier.
// At startup it hashes the local GGUF model file and verifies it against a
// cosign/Sigstore Rekor signed registry, blocking LLM calls on confirmed tampering.
package miv

import "context"

// Status is the tiered verification outcome.
type Status string

const (
	StatusPass  Status = "PASS"  // known model ID, hash matches registry
	StatusWarn  Status = "WARN"  // unrecognised model ID — user opt-in required
	StatusBlock Status = "BLOCK" // known model ID, hash mismatch — scan halted
)

// Result is returned by Verify.
type Result struct {
	Status  Status
	ModelID string
	Message string
}

// Verifier hashes the GGUF model file and compares it against the signed registry.
type Verifier struct {
	registryPath  string
	publicKeyPath string
}

// New returns a Verifier using the bundled registry and public key at the given paths.
func New(registryPath, publicKeyPath string) *Verifier {
	return &Verifier{
		registryPath:  registryPath,
		publicKeyPath: publicKeyPath,
	}
}

// Verify runs the integrity check for the model file at modelPath.
// WARN does not block; BLOCK stops all LLM invocations.
func (v *Verifier) Verify(ctx context.Context, modelPath string) (*Result, error) {
	// implemented in G2.M2.2
	return &Result{Status: StatusWarn, Message: "MIV not yet implemented"}, nil
}
