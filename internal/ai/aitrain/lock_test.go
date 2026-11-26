package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeRecog writes one small file per source aitrain reads.
func fakeRecog(t *testing.T, change string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "xml"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, src := range sources {
		body := "<fingerprints/>"
		if src.file == change {
			body = "<fingerprints><!-- edited --></fingerprints>"
		}
		if err := os.WriteFile(filepath.Join(dir, "xml", src.file), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLockPinsTheTrainingData(t *testing.T) {
	data := fakeRecog(t, "")
	lockPath := filepath.Join(t.TempDir(), "recog.lock")

	written, err := checkLock(lockPath, data, true)
	if err != nil {
		t.Fatal(err)
	}
	read, err := readLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if read != written || read.Go != runtime.Version() || len(read.SHA256) != 64 {
		t.Fatalf("lock round trip: wrote %+v, read %+v", written, read)
	}
	if _, err := checkLock(lockPath, data, false); err != nil {
		t.Fatalf("the locked data is refused: %v", err)
	}

	// One file changed: training must refuse it.
	_, err = checkLock(lockPath, fakeRecog(t, "ssh_banners.xml"), false)
	if err == nil || !strings.Contains(err.Error(), "differ from the locked training data") {
		t.Fatalf("changed data accepted: %v", err)
	}
	// A file missing: refused too.
	missing := fakeRecog(t, "")
	_ = os.Remove(filepath.Join(missing, "xml", sources[0].file))
	if _, err := checkLock(lockPath, missing, false); err == nil {
		t.Fatal("missing data accepted")
	}
}

func TestCommittedLockIsComplete(t *testing.T) {
	l, err := readLock("recog.lock")
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Commit) != 40 || len(l.SHA256) != 64 || l.Date == "" || l.Trained == "" || !strings.HasPrefix(l.Go, "go1.") {
		t.Fatalf("recog.lock: %+v", l)
	}
}
