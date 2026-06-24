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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// genKey generates a fresh ECDSA P-256 key pair and returns private key,
// PEM-encoded public key, and a registry JSON + base64-encoded DER signature.
func genKeyAndRegistry(t *testing.T, entries []RegistryEntry) (priv *ecdsa.PrivateKey, pubKeyPEM, regJSON, regSig []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	reg := registryFile{Version: 1, Entries: entries}
	regJSON, err = json.Marshal(reg)
	if err != nil {
		t.Fatalf("marshal registry: %v", err)
	}

	hash := sha256.Sum256(regJSON)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("sign registry: %v", err)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("marshal DER: %v", err)
	}
	regSig = []byte(base64.StdEncoding.EncodeToString(der))
	return
}

// writeRegistry writes reg.json, reg.json.sig, cosign.pub to a temp dir
// and returns a Verifier pointing at them, with Rekor disabled via offline server.
func writeRegistry(t *testing.T, entries []RegistryEntry) (v *Verifier, dir string) {
	t.Helper()

	_, pubKeyPEM, regJSON, regSig := genKeyAndRegistry(t, entries)
	dir = t.TempDir()

	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("registry.json", regJSON)
	write("registry.json.sig", regSig)
	write("cosign.pub", pubKeyPEM)

	// Point Rekor at a server that always returns 404 (offline).
	rekorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	t.Cleanup(rekorSrv.Close)

	v = New(filepath.Join(dir, "registry.json"), filepath.Join(dir, "cosign.pub"), nil)
	v.rekorURL = rekorSrv.URL
	return
}

// makeGGUF writes a minimal GGUF v2 file with the given model name to a temp
// file and returns its path.
func makeGGUF(t *testing.T, modelName string) string {
	t.Helper()

	var buf []byte

	write32 := func(v uint32) {
		buf = append(buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	write64 := func(v uint64) {
		buf = append(buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24),
			byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
	}
	writeStr := func(s string) {
		write64(uint64(len(s)))
		buf = append(buf, s...)
	}

	// GGUF header
	write32(ggufMagic) // magic
	write32(2)         // version
	write64(0)         // n_tensors
	write64(1)         // n_kv (one entry: general.name)

	// KV: "general.name" → STRING → modelName
	writeStr("general.name")
	write32(ggufTypeSTRING) // value_type
	writeStr(modelName)

	p := filepath.Join(t.TempDir(), "model.gguf")
	if err := os.WriteFile(p, buf, 0o600); err != nil {
		t.Fatalf("write GGUF: %v", err)
	}
	return p
}

// ─── hashGGUF ────────────────────────────────────────────────────────────────

func TestHashGGUFKnownFile(t *testing.T) {
	content := []byte("hello gguf")
	f, err := os.CreateTemp(t.TempDir(), "*.bin")
	if err != nil {
		t.Fatal(err)
	}
	f.Write(content)
	f.Close()

	h, err := hashGGUF(context.Background(), f.Name())
	if err != nil {
		t.Fatalf("hashGGUF: %v", err)
	}

	sum := sha256.Sum256(content)
	want := make([]byte, 32)
	want = sum[:]
	wantHex := ""
	for _, b := range want {
		wantHex += string([]byte{hexChar(b >> 4), hexChar(b & 0xf)})
	}
	if h != wantHex {
		t.Errorf("hash mismatch: got %s, want %s", h, wantHex)
	}
}

func hexChar(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

func TestHashGGUFMissingFile(t *testing.T) {
	_, err := hashGGUF(context.Background(), "/nonexistent/model.gguf")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestHashGGUFContextCancel(t *testing.T) {
	// Write a small file but cancel before hashing.
	f, _ := os.CreateTemp(t.TempDir(), "*.bin")
	f.Write(make([]byte, 1024))
	f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := hashGGUF(ctx, f.Name())
	if err == nil {
		t.Fatal("expected error when context is cancelled")
	}
}

// ─── readGGUFModelID ─────────────────────────────────────────────────────────

func TestReadGGUFModelIDSuccess(t *testing.T) {
	p := makeGGUF(t, "mymodel:7b-q4_K_M")
	id, err := readGGUFModelID(p)
	if err != nil {
		t.Fatalf("readGGUFModelID: %v", err)
	}
	if id != "mymodel:7b-q4_K_M" {
		t.Errorf("unexpected model ID: %q", id)
	}
}

func TestReadGGUFModelIDNotGGUF(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "*.bin")
	f.Write([]byte("not a gguf file"))
	f.Close()

	_, err := readGGUFModelID(f.Name())
	if !errors.Is(err, ErrNotGGUF) {
		t.Errorf("expected ErrNotGGUF, got %v", err)
	}
}

func TestReadGGUFModelIDMissingFile(t *testing.T) {
	_, err := readGGUFModelID("/nonexistent/model.gguf")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ─── LoadRegistry ────────────────────────────────────────────────────────────

func TestLoadRegistryEmbeddedPasses(t *testing.T) {
	// The embedded registry (data/registry.json) must load and verify correctly.
	// We test against a Rekor server that returns 404 (expected for new registries).
	rekorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer rekorSrv.Close()

	v := New("", "", nil)
	v.rekorURL = rekorSrv.URL

	entries, err := v.LoadRegistry(context.Background())
	if err != nil {
		t.Fatalf("LoadRegistry on embedded data: %v", err)
	}
	// Embedded registry is empty — just verify it loads without error.
	_ = entries
}

func TestLoadRegistryTamperedSignatureFails(t *testing.T) {
	_, pubKeyPEM, regJSON, _ := genKeyAndRegistry(t, nil)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "registry.json"), regJSON, 0o600)
	os.WriteFile(filepath.Join(dir, "registry.json.sig"), []byte("bm90YXNpZw=="), 0o600) // invalid sig
	os.WriteFile(filepath.Join(dir, "cosign.pub"), pubKeyPEM, 0o600)

	rekorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer rekorSrv.Close()

	v := New(filepath.Join(dir, "registry.json"), filepath.Join(dir, "cosign.pub"), nil)
	v.rekorURL = rekorSrv.URL

	_, err := v.LoadRegistry(context.Background())
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestLoadRegistryRekorHitDoesNotBlockOnECDSAFailure(t *testing.T) {
	// Rekor returns a hit but ECDSA still gates the decision.
	_, pubKeyPEM, regJSON, _ := genKeyAndRegistry(t, nil)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "registry.json"), regJSON, 0o600)
	os.WriteFile(filepath.Join(dir, "registry.json.sig"), []byte("bm90YXNpZw=="), 0o600)
	os.WriteFile(filepath.Join(dir, "cosign.pub"), pubKeyPEM, 0o600)

	rekorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Pretend Rekor found the entry.
		json.NewEncoder(w).Encode([]string{"12345"})
	}))
	defer rekorSrv.Close()

	v := New(filepath.Join(dir, "registry.json"), filepath.Join(dir, "cosign.pub"), nil)
	v.rekorURL = rekorSrv.URL

	_, err := v.LoadRegistry(context.Background())
	if err == nil {
		t.Fatal("ECDSA must reject tampered registry even when Rekor returns a hit")
	}
}

// ─── Verify ──────────────────────────────────────────────────────────────────

func TestVerifyPass(t *testing.T) {
	// Create a real GGUF, compute its hash, put it in the registry, verify.
	ggufPath := makeGGUF(t, "test-model:3b")
	hash, err := hashGGUF(context.Background(), ggufPath)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	entries := []RegistryEntry{{ModelID: "test-model:3b", SHA256: hash, Source: "test", AddedAt: "2026-06-17"}}
	v, _ := writeRegistry(t, entries)

	res, err := v.Verify(context.Background(), ggufPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != StatusPass {
		t.Errorf("expected PASS, got %s: %s", res.Status, res.Message)
	}
	if res.ModelID != "test-model:3b" {
		t.Errorf("unexpected model ID: %q", res.ModelID)
	}
}

func TestVerifyBlock(t *testing.T) {
	ggufPath := makeGGUF(t, "test-model:3b")

	// Put a wrong hash in the registry.
	entries := []RegistryEntry{{ModelID: "test-model:3b", SHA256: "deadbeef" + string(make([]byte, 56)), AddedAt: "2026-06-17"}}
	v, _ := writeRegistry(t, entries)

	res, err := v.Verify(context.Background(), ggufPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != StatusBlock {
		t.Errorf("expected BLOCK, got %s: %s", res.Status, res.Message)
	}
}

func TestVerifyWarnUnknownModel(t *testing.T) {
	ggufPath := makeGGUF(t, "unknown-model:7b")
	v, _ := writeRegistry(t, nil) // empty registry

	res, err := v.Verify(context.Background(), ggufPath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != StatusWarn {
		t.Errorf("expected WARN, got %s", res.Status)
	}
}

func TestVerifyWarnNotGGUF(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "*.bin")
	f.Write([]byte("not gguf"))
	f.Close()

	v, _ := writeRegistry(t, nil)

	res, err := v.Verify(context.Background(), f.Name())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != StatusWarn {
		t.Errorf("expected WARN for non-GGUF file, got %s", res.Status)
	}
}

func TestVerifyMissingFile(t *testing.T) {
	v, _ := writeRegistry(t, nil)
	_, err := v.Verify(context.Background(), "/nonexistent/model.gguf")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ─── Rekor fallback ──────────────────────────────────────────────────────────

func TestRekorTimeoutFallsBackToECDSA(t *testing.T) {
	_, pubKeyPEM, regJSON, regSig := genKeyAndRegistry(t, nil)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "registry.json"), regJSON, 0o600)
	os.WriteFile(filepath.Join(dir, "registry.json.sig"), regSig, 0o600)
	os.WriteFile(filepath.Join(dir, "cosign.pub"), pubKeyPEM, 0o600)

	// unblock is closed after LoadRegistry returns, allowing the handler to exit
	// cleanly before rekorSrv.Close() is called. Without this, Close() blocks
	// waiting for the hanging handler goroutine to finish.
	unblock := make(chan struct{})

	rekorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-unblock // hang until the test signals we're done
	}))

	v := New(filepath.Join(dir, "registry.json"), filepath.Join(dir, "cosign.pub"), nil)
	v.rekorURL = rekorSrv.URL

	// Even though Rekor hangs, ECDSA fallback should succeed.
	entries, err := v.LoadRegistry(context.Background())

	close(unblock)      // let the handler return
	rekorSrv.Close()    // now drains immediately

	if err != nil {
		t.Fatalf("LoadRegistry should succeed via ECDSA fallback: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected empty registry, got %d entries", len(entries))
	}
}
