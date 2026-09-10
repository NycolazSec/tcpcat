package vuln

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withIsolatedUserConfigDir redirects os.UserConfigDir() (and therefore
// getUserOfflineDBPath) to a fresh temp directory, so these tests never
// touch the real user's config directory.
func withIsolatedUserConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	return dir
}

func TestOfflineScannerSourceName(t *testing.T) {
	s, err := NewOfflineScanner()
	if err != nil {
		t.Fatalf("NewOfflineScanner() error = %v", err)
	}
	if got := s.SourceName(); got != "Offline DB" {
		t.Errorf("SourceName() = %q, want Offline DB", got)
	}
}

func TestOfflineScannerGetForSoftwareUnknown(t *testing.T) {
	s, err := NewOfflineScanner()
	if err != nil {
		t.Fatalf("NewOfflineScanner() error = %v", err)
	}

	vulns, err := s.GetForSoftware("totally-unknown-software", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vulns != nil {
		t.Errorf("got %v, want nil", vulns)
	}

	vulns, err = s.GetForSoftware("nginx", "99.99.99")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vulns != nil {
		t.Errorf("known software with unknown version: got %v, want nil", vulns)
	}
}

func TestGetUserOfflineDBPath(t *testing.T) {
	dir := withIsolatedUserConfigDir(t)

	got := getUserOfflineDBPath()
	if got == "" {
		t.Fatal("getUserOfflineDBPath() returned empty string")
	}
	if filepath.Base(got) != "offline_db.json" {
		t.Errorf("path %q does not end in offline_db.json", got)
	}
	if !filepathHasPrefix(got, dir) {
		t.Errorf("path %q is not rooted under the isolated HOME %q", got, dir)
	}
}

func filepathHasPrefix(path, prefix string) bool {
	rel, err := filepath.Rel(prefix, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func TestGetEmbeddedOfflineDB(t *testing.T) {
	data := GetEmbeddedOfflineDB()

	var db map[string]map[string][]Vulnerability
	if err := json.Unmarshal(data, &db); err != nil {
		t.Fatalf("embedded DB is not valid JSON: %v", err)
	}
	if _, ok := db["apache"]["2.4.49"]; !ok {
		t.Error("embedded DB missing known apache/2.4.49 entry")
	}
}

func TestUpdateOfflineDB(t *testing.T) {
	dir := withIsolatedUserConfigDir(t)

	newDB := `{"redis": {"6.0.0": [{"id": "CVE-2099-0001", "title": "made up", "cvss": 5.0}]}}`
	if err := UpdateOfflineDB([]byte(newDB)); err != nil {
		t.Fatalf("UpdateOfflineDB() error = %v", err)
	}

	dbPath := getUserOfflineDBPath()
	if !filepathHasPrefix(dbPath, dir) {
		t.Fatalf("db path %q escaped isolated HOME %q", dbPath, dir)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("written database not found: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}

	written, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read written database: %v", err)
	}
	var db map[string]map[string][]Vulnerability
	if err := json.Unmarshal(written, &db); err != nil {
		t.Fatalf("written database is not valid JSON: %v", err)
	}
	if _, ok := db["redis"]["6.0.0"]; !ok {
		t.Error("written database missing the new redis entry")
	}

	// NewOfflineScanner should now prefer this user database over the
	// embedded one.
	scanner, err := NewOfflineScanner()
	if err != nil {
		t.Fatalf("NewOfflineScanner() error = %v", err)
	}
	vulns, err := scanner.GetForSoftware("redis", "6.0.0")
	if err != nil {
		t.Fatalf("GetForSoftware() error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].ID != "CVE-2099-0001" {
		t.Errorf("got %+v, want the redis entry from the user database", vulns)
	}
}

func TestUpdateOfflineDBRejectsInvalidJSON(t *testing.T) {
	withIsolatedUserConfigDir(t)

	if err := UpdateOfflineDB([]byte("not json")); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

func TestAddSoftwareToOfflineDBSeedsFromEmbedded(t *testing.T) {
	withIsolatedUserConfigDir(t)

	newVulns := []Vulnerability{{ID: "CVE-2099-0002", Title: "custom entry", CVSS: 6.5}}
	if err := AddSoftwareToOfflineDB("MyCustomApp", "3.1.4", newVulns); err != nil {
		t.Fatalf("AddSoftwareToOfflineDB() error = %v", err)
	}

	dbPath := getUserOfflineDBPath()
	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read written database: %v", err)
	}
	var db map[string]map[string][]Vulnerability
	if err := json.Unmarshal(data, &db); err != nil {
		t.Fatalf("written database is not valid JSON: %v", err)
	}

	// The new entry is present, lowercased...
	if got := db["mycustomapp"]["3.1.4"]; len(got) != 1 || got[0].ID != "CVE-2099-0002" {
		t.Errorf("got %+v, want the new custom entry", got)
	}
	// ...and the embedded seed data survived the merge.
	if _, ok := db["apache"]["2.4.49"]; !ok {
		t.Error("expected the embedded apache entry to survive AddSoftwareToOfflineDB")
	}
}

func TestAddSoftwareToOfflineDBMergesWithExisting(t *testing.T) {
	withIsolatedUserConfigDir(t)

	first := []Vulnerability{{ID: "CVE-2099-0003", Title: "first", CVSS: 4.0}}
	if err := AddSoftwareToOfflineDB("appone", "1.0", first); err != nil {
		t.Fatalf("first AddSoftwareToOfflineDB() error = %v", err)
	}
	second := []Vulnerability{{ID: "CVE-2099-0004", Title: "second", CVSS: 5.0}}
	if err := AddSoftwareToOfflineDB("apptwo", "2.0", second); err != nil {
		t.Fatalf("second AddSoftwareToOfflineDB() error = %v", err)
	}

	data, err := os.ReadFile(getUserOfflineDBPath())
	if err != nil {
		t.Fatalf("read written database: %v", err)
	}
	var db map[string]map[string][]Vulnerability
	if err := json.Unmarshal(data, &db); err != nil {
		t.Fatalf("written database is not valid JSON: %v", err)
	}
	if _, ok := db["appone"]["1.0"]; !ok {
		t.Error("expected appone entry from the first call to survive the second call")
	}
	if _, ok := db["apptwo"]["2.0"]; !ok {
		t.Error("expected apptwo entry from the second call to be present")
	}
}
