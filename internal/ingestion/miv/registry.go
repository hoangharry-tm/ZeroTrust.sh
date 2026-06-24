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

package miv

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// registryFile is the on-disk / embedded JSON format.
type registryFile struct {
	Version int             `json:"version"`
	Entries []RegistryEntry `json:"entries"`
}

// LoadRegistry reads the registry file, verifies its ECDSA signature (with
// Sigstore Rekor as a best-effort transparency check), and returns the entries.
//
// Verification order:
//  1. ECDSA P-256 against the embedded (or supplied) public key — always run.
//  2. Sigstore Rekor lookup (3-second timeout) — additive transparency proof;
//     failure is logged but never blocks the registry from being used.
//
// The ECDSA check is the authoritative gate. A Rekor failure means "entry not
// yet published or network unavailable" — the registry signature still holds.
//
// Parameters:
//   - ctx: cancellation context.
//
// Returns:
//   - []RegistryEntry: all entries in the verified registry.
//   - error: non-nil if the file is unreadable or the ECDSA signature fails.
func (v *Verifier) LoadRegistry(ctx context.Context) ([]RegistryEntry, error) {
	regBytes, sigBytes, pubKeyPEM, err := v.loadFiles()
	if err != nil {
		return nil, err
	}

	pubKey, err := parseECDSAPublicKey(pubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	// Primary security gate: ECDSA signature.
	if err := verifyECDSA(regBytes, sigBytes, pubKey); err != nil {
		return nil, fmt.Errorf("registry signature invalid: %w", err)
	}

	// Best-effort: Rekor transparency proof (3-second window).
	rekorCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if rekorErr := v.verifyWithRekor(rekorCtx, regBytes); rekorErr != nil {
		v.logger.Warn("miv: rekor transparency check failed (non-blocking; ECDSA gate passed)",
			"component", "miv",
			"err", rekorErr,
		)
	}

	var reg registryFile
	if err := json.Unmarshal(regBytes, &reg); err != nil {
		return nil, fmt.Errorf("parse registry: %w", err)
	}
	return reg.Entries, nil
}

// loadFiles returns (registry bytes, sig bytes, public key PEM).
// Falls back to embedded data when paths are empty.
func (v *Verifier) loadFiles() (regBytes, sigBytes, pubKeyPEM []byte, err error) {
	if v.registryPath != "" {
		regBytes, err = os.ReadFile(v.registryPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("read registry: %w", err)
		}
		sigBytes, err = os.ReadFile(v.registryPath + ".sig")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("read registry sig: %w", err)
		}
	} else {
		regBytes = embeddedRegistry
		sigBytes = embeddedRegistrySig
	}

	if v.publicKeyPath != "" {
		pubKeyPEM, err = os.ReadFile(v.publicKeyPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("read public key: %w", err)
		}
	} else {
		pubKeyPEM = embeddedPublicKey
	}
	return regBytes, sigBytes, pubKeyPEM, nil
}

// parseECDSAPublicKey decodes a PEM-encoded ECDSA public key.
func parseECDSAPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX key: %w", err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	return ecKey, nil
}

// verifyECDSA checks a base64-encoded DER ECDSA signature over SHA-256(data).
// The signature file produced by `openssl dgst -sha256 -sign` matches this format.
func verifyECDSA(data, sigBase64 []byte, pub *ecdsa.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigBase64)))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	hash := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(pub, hash[:], sig) {
		return errors.New("ECDSA signature verification failed")
	}
	return nil
}

// ─── Rekor (transparency log, best-effort) ───────────────────────────────────

// verifyWithRekor checks whether the SHA-256 hash of regBytes appears as an
// entry in the Sigstore Rekor transparency log. Returns nil if an entry is
// found, non-nil otherwise (including network failure or timeout).
//
// A Rekor miss is expected for newly signed registries that have not yet been
// published to the log; ECDSA verification is the authoritative gate.
func (v *Verifier) verifyWithRekor(ctx context.Context, regBytes []byte) error {
	hash := sha256.Sum256(regBytes)
	hexHash := fmt.Sprintf("%x", hash[:])

	indices, err := v.rekorSearchByHash(ctx, hexHash)
	if err != nil {
		return fmt.Errorf("rekor search: %w", err)
	}
	if len(indices) == 0 {
		return errors.New("registry hash not found in Rekor transparency log")
	}
	return nil
}

// rekorSearchByHash posts to the Rekor /api/v1/index/retrieve endpoint and
// returns the list of matching log indices.
func (v *Verifier) rekorSearchByHash(ctx context.Context, sha256hex string) ([]string, error) {
	body := []byte(`{"hash":"sha256:` + sha256hex + `"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		v.rekorURL+"/api/v1/index/retrieve", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read rekor response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rekor returned status %d", resp.StatusCode)
	}

	var indices []string
	if err := json.Unmarshal(respBody, &indices); err != nil {
		return nil, fmt.Errorf("decode rekor indices: %w", err)
	}
	return indices, nil
}
