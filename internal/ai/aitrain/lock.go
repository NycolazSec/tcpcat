package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// The banner model ships inside tcpcat, so it must be possible to check that
// the weights in the repository are what this trainer makes from public
// data, and nothing else. Training is deterministic for a given seed and
// data; the lock pins the data. aitrain trains only on the Recog files whose
// digest the lock records, and takes the provenance it writes into the model
// (commit, date) from the lock rather than from the clock or from git, so
// that training twice gives the same bytes. CI rebuilds the model with no
// network and compares (.github/workflows/ai-model.yml).

// trainingLock is the content of recog.lock.
type trainingLock struct {
	Repository string // recog_repository
	Commit     string // recog_commit: the full commit hash
	Date       string // recog_date: the commit's date
	SHA256     string // recog_sha256: digest of the files aitrain reads
	Trained    string // trained: the date the reference weights were made
	Go         string // go: the Go release the reference weights were made with
}

const lockHeader = `# The training data of tcpcat's banner model, pinned. aitrain trains only on
# the Recog files whose digest is recorded here, so that the weights in
# internal/ai/model can be rebuilt byte for byte and checked (CI does it with
# no network, see .github/workflows/ai-model.yml). To train on newer data:
#   go run ./internal/ai/aitrain -recog <clone> -update-lock
`

func readLock(path string) (trainingLock, error) {
	f, err := os.Open(path) // #nosec G304 -- the lock path is a flag the developer passes
	if err != nil {
		return trainingLock{}, err
	}
	defer func() { _ = f.Close() }()
	var l trainingLock
	fields := map[string]*string{
		"recog_repository": &l.Repository, "recog_commit": &l.Commit, "recog_date": &l.Date,
		"recog_sha256": &l.SHA256, "trained": &l.Trained, "go": &l.Go,
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return trainingLock{}, fmt.Errorf("%s: malformed line %q", path, line)
		}
		if p := fields[strings.TrimSpace(key)]; p != nil {
			*p = strings.TrimSpace(value)
		}
	}
	if err := sc.Err(); err != nil {
		return trainingLock{}, err
	}
	if l.SHA256 == "" || l.Trained == "" {
		return trainingLock{}, fmt.Errorf("%s: recog_sha256 and trained are required", path)
	}
	return l, nil
}

func writeLock(path string, l trainingLock) error {
	var b strings.Builder
	b.WriteString(lockHeader)
	fmt.Fprintf(&b, "recog_repository: %s\nrecog_commit: %s\nrecog_date: %s\nrecog_sha256: %s\ntrained: %s\ngo: %s\n",
		l.Repository, l.Commit, l.Date, l.SHA256, l.Trained, l.Go)
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// dataDigest is the SHA-256 of the list "file sha256" of every Recog file
// aitrain reads, in the order it reads them.
func dataDigest(recogDir string) (string, error) {
	h := sha256.New()
	for _, src := range sources {
		data, err := os.ReadFile(filepath.Join(recogDir, "xml", src.file)) // #nosec G304 -- files of the Recog clone the developer passed
		if err != nil {
			return "", err
		}
		_, _ = fmt.Fprintf(h, "%s %x\n", src.file, sha256.Sum256(data)) // a hash never fails to write
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// lockFor describes the data in recogDir, to accept it as the new lock.
func lockFor(recogDir, digest string) trainingLock {
	l := trainingLock{
		Repository: "https://github.com/rapid7/recog",
		Commit:     "unknown", Date: "unknown",
		SHA256:  digest,
		Trained: time.Now().UTC().Format("2006-01-02"),
		Go:      runtime.Version(),
	}
	out, err := exec.Command("git", "-C", recogDir, "log", "-1", "--format=%H %cs").Output() // #nosec G204 -- fixed arguments, no shell; recogDir is the -recog path the developer passed
	if f := strings.Fields(string(out)); err == nil && len(f) == 2 {
		l.Commit, l.Date = f[0], f[1]
	}
	return l
}

// checkLock reads the lock and verifies the data against it, or with
// update records the data as the new lock.
func checkLock(path, recogDir string, update bool) (trainingLock, error) {
	digest, err := dataDigest(recogDir)
	if err != nil {
		return trainingLock{}, err
	}
	if update {
		l := lockFor(recogDir, digest)
		return l, writeLock(path, l)
	}
	l, err := readLock(path)
	if err != nil {
		return trainingLock{}, err
	}
	if digest != l.SHA256 {
		return trainingLock{}, fmt.Errorf("the Recog files differ from the locked training data (%s, commit %s): "+
			"check out that commit, or run with -update-lock to train on this data", path, l.Commit)
	}
	if runtime.Version() != l.Go {
		fmt.Fprintf(os.Stderr, "aitrain: note: the reference weights were made with %s, this is %s; the result may differ by a few bits\n", l.Go, runtime.Version())
	}
	return l, nil
}

// short is a commit hash as people quote it.
func (l trainingLock) short() string {
	if len(l.Commit) > 7 {
		return l.Commit[:7]
	}
	return l.Commit
}
