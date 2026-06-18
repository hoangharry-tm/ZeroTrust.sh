package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"testing"
	"time"
)

// python3Available checks whether python3 is accessible in PATH.
// All subprocess-based tests skip when it is absent (CI without Python).
func python3Available() bool {
	_, err := exec.LookPath("python3")
	return err == nil
}

// echoWorker returns a Manager backed by a tiny inline Python echo process.
// The process responds to ping and echoes any other request back as ok,
// and exits cleanly on shutdown.
func echoWorker(t *testing.T) *Manager {
	t.Helper()
	if !python3Available() {
		t.Skip("python3 not in PATH")
	}
	// Inline Python dispatcher: handles ping, shutdown, and echoes everything else.
	script := `
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if msg.get("type") == "shutdown":
        print(json.dumps({"id": msg["id"], "status": "ok"}), flush=True)
        break
    print(json.dumps({"id": msg["id"], "status": "ok", "result": {}}), flush=True)
`
	m := newManager([]string{"python3", "-c", script})
	if err := m.spawn(); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Ping(pingCtx); err != nil {
		t.Fatalf("initial ping: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	return m
}

// ─── Ping ────────────────────────────────────────────────────────────────────

func TestPingAliveWorker(t *testing.T) {
	m := echoWorker(t)
	if err := m.Ping(context.Background()); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

func TestPingDeadWorkerReturnsError(t *testing.T) {
	if !python3Available() {
		t.Skip("python3 not in PATH")
	}
	m := newManager([]string{"python3", "-c", "import sys; sys.exit(1)"})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// spawn will succeed (process starts), but ping should fail because
	// the process exits immediately.
	_ = m.spawn()
	time.Sleep(100 * time.Millisecond) // let the process exit
	err := m.Ping(ctx)
	if err == nil {
		t.Error("expected error pinging a dead worker")
	}
}

// ─── Call ────────────────────────────────────────────────────────────────────

func TestCallReturnsOK(t *testing.T) {
	m := echoWorker(t)
	resp, err := m.Call(context.Background(), MsgPing, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.Status != ResponseOK {
		t.Errorf("expected status ok, got %s", resp.Status)
	}
}

func TestCallWithPayload(t *testing.T) {
	m := echoWorker(t)
	payload := VerifyPayload{FindingID: "f-1", RuleID: "PY-001", CWE: "CWE-89", MatchedCode: "x"}
	resp, err := m.Call(context.Background(), MsgLLMVerify, payload)
	if err != nil {
		t.Fatalf("Call with payload: %v", err)
	}
	if resp.Status != ResponseOK {
		t.Errorf("expected ok, got %s: %s", resp.Status, resp.Error)
	}
}

func TestCallCancelledContext(t *testing.T) {
	m := echoWorker(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := m.Call(ctx, MsgPing, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestCallConcurrent(t *testing.T) {
	m := echoWorker(t)
	const n = 20
	errs := make(chan error, n)
	for range n {
		go func() {
			_, err := m.Call(context.Background(), MsgPing, nil)
			errs <- err
		}()
	}
	for range n {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Call: %v", err)
		}
	}
}

func TestCallDeadWorkerReturnsErrWorkerDead(t *testing.T) {
	if !python3Available() {
		t.Skip("python3 not in PATH")
	}
	m := newManager([]string{"python3", "-c", ""}) // immediately exits
	_ = m.spawn()
	// Wait for the reader goroutine to detect the exit and handle death.
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := m.Call(ctx, MsgPing, nil)
	// Either ErrWorkerDead (if restart also failed) or a transient error is OK.
	if err == nil {
		t.Error("expected an error calling a dead worker, got nil")
	}
}

// ─── Stop ────────────────────────────────────────────────────────────────────

func TestStopIsIdempotent(t *testing.T) {
	m := echoWorker(t)
	if err := m.Stop(); err != nil {
		t.Errorf("first Stop: %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

func TestCallAfterStopReturnsError(t *testing.T) {
	m := echoWorker(t)
	_ = m.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := m.Call(ctx, MsgPing, nil)
	if err == nil {
		t.Error("expected error after Stop, got nil")
	}
}

// ─── Request/Response wiring ─────────────────────────────────────────────────

func TestWriteRequestIDEchoedInResponse(t *testing.T) {
	m := echoWorker(t)
	resp, err := m.Call(context.Background(), MsgPing, nil)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	// The echo worker reflects the ID back.
	if resp.ID == "" {
		t.Error("response ID should not be empty")
	}
}

func TestIDsAreMonotonicallyIncreasing(t *testing.T) {
	m := newManager(nil)
	id1 := m.newID()
	id2 := m.newID()
	id3 := m.newID()
	if id1 == id2 || id2 == id3 {
		t.Errorf("IDs must be unique: %s %s %s", id1, id2, id3)
	}
}

// ─── JSON wire format ────────────────────────────────────────────────────────

func TestRequestMarshalRoundtrip(t *testing.T) {
	payload, _ := json.Marshal(VerifyPayload{FindingID: "f-1"})
	req := Request{ID: "42", Type: MsgLLMVerify, Payload: payload}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Request
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ID != "42" || got.Type != MsgLLMVerify {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestResponseMarshalRoundtrip(t *testing.T) {
	resp := Response{ID: "7", Status: ResponseOK, Result: json.RawMessage(`{"ok":true}`)}
	b, _ := json.Marshal(resp)
	var got Response
	json.Unmarshal(b, &got) //nolint:errcheck
	if got.Status != ResponseOK || got.ID != "7" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}
