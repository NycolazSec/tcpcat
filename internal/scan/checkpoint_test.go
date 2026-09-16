package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.checkpoint")

	// First run: record two results.
	cp, err := openCheckpoint(path)
	if err != nil {
		t.Fatalf("openCheckpoint: %v", err)
	}
	if len(cp.priorResults()) != 0 {
		t.Errorf("fresh checkpoint has %d prior results, want 0", len(cp.priorResults()))
	}
	cp.record(TargetResult{IP: "10.0.0.1", Port: 22, State: StateOpen, Service: "ssh"})
	cp.record(TargetResult{IP: "10.0.0.1", Port: 80, State: StateClosed})
	if err := cp.close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Second run: the two are loaded and reported done, an unscanned one is not.
	cp2, err := openCheckpoint(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = cp2.close() })

	if got := len(cp2.priorResults()); got != 2 {
		t.Fatalf("priorResults = %d, want 2", got)
	}
	if !cp2.isDone("10.0.0.1", 22) || !cp2.isDone("10.0.0.1", 80) {
		t.Error("previously recorded pairs should report done")
	}
	if cp2.isDone("10.0.0.1", 443) {
		t.Error("an unscanned pair must not report done")
	}
	// The loaded result must round-trip its fields, not just its key.
	var ssh *TargetResult
	for i := range cp2.priorResults() {
		if cp2.priorResults()[i].Port == 22 {
			ssh = &cp2.priorResults()[i]
		}
	}
	if ssh == nil || ssh.Service != "ssh" || ssh.State != StateOpen {
		t.Errorf("loaded result = %+v, want ssh/OPEN preserved", ssh)
	}
}

func TestCheckpointAppendsAcrossRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.checkpoint")

	cp, _ := openCheckpoint(path)
	cp.record(TargetResult{IP: "10.0.0.1", Port: 22, State: StateOpen})
	_ = cp.close()

	cp2, _ := openCheckpoint(path)
	cp2.record(TargetResult{IP: "10.0.0.1", Port: 443, State: StateOpen})
	_ = cp2.close()

	cp3, err := openCheckpoint(path)
	if err != nil {
		t.Fatalf("openCheckpoint: %v", err)
	}
	t.Cleanup(func() { _ = cp3.close() })
	if got := len(cp3.priorResults()); got != 2 {
		t.Errorf("after two runs, priorResults = %d, want 2 (appended, not truncated)", got)
	}
}

func TestOpenCheckpointRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.checkpoint")
	if err := os.WriteFile(path, []byte("{not valid json\n"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := openCheckpoint(path); err == nil {
		t.Error("openCheckpoint accepted a corrupt file, want an error rather than a silent zero-progress restart")
	}
}

func TestNilCheckpointIsInert(t *testing.T) {
	// The engine leaves cp nil when --resume is unset; every method must be
	// safe on a nil receiver so the non-resume path needs no guards.
	var cp *checkpoint
	if cp.isDone("1.2.3.4", 80) {
		t.Error("nil checkpoint should report nothing done")
	}
	if cp.priorResults() != nil {
		t.Error("nil checkpoint should have no prior results")
	}
	cp.record(TargetResult{IP: "1.2.3.4", Port: 80})
	if err := cp.close(); err != nil {
		t.Errorf("nil checkpoint close = %v, want nil", err)
	}
}
