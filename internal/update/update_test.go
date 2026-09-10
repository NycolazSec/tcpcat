package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyChecksum(t *testing.T) {
	data := []byte("tcpcat release binary")
	hash := sha256.Sum256(data)
	checksums := []byte(hex.EncodeToString(hash[:]) + "  tcpcat_1.0.1_linux_amd64.tar.gz\n")

	if err := verifyChecksum("tcpcat_1.0.1_linux_amd64.tar.gz", data, checksums); err != nil {
		t.Fatalf("verifyChecksum() error = %v", err)
	}
	if err := verifyChecksum("tcpcat_1.0.1_linux_amd64.tar.gz", []byte("tampered"), checksums); err == nil {
		t.Fatal("verifyChecksum() accepted tampered data")
	}
}

func TestExtractTarGz(t *testing.T) {
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	binary := []byte("fake tcpcat binary")
	if err := tarWriter.WriteHeader(&tar.Header{Name: "tcpcat", Mode: 0755, Size: int64(len(binary))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := extractTarGz(archive.Bytes(), "tcpcat")
	if err != nil {
		t.Fatalf("extractTarGz() error = %v", err)
	}
	if !bytes.Equal(got, binary) {
		t.Fatalf("extractTarGz() = %q, want %q", got, binary)
	}
}

func TestExtractTarGzBinaryNotFound(t *testing.T) {
	var archive bytes.Buffer
	gzipWriter := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "README.md", Mode: 0644, Size: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write([]byte("docs")); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := extractTarGz(archive.Bytes(), "tcpcat"); err == nil {
		t.Fatal("expected an error when the binary isn't in the archive")
	}
}

func TestExtractZip(t *testing.T) {
	var archive bytes.Buffer
	zipWriter := zip.NewWriter(&archive)
	binary := []byte("fake tcpcat.exe binary")
	w, err := zipWriter.Create("tcpcat.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := extractZip(archive.Bytes(), "tcpcat.exe")
	if err != nil {
		t.Fatalf("extractZip() error = %v", err)
	}
	if !bytes.Equal(got, binary) {
		t.Fatalf("extractZip() = %q, want %q", got, binary)
	}
}

func TestExtractZipBinaryNotFound(t *testing.T) {
	var archive bytes.Buffer
	zipWriter := zip.NewWriter(&archive)
	w, err := zipWriter.Create("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("docs")); err != nil {
		t.Fatal(err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := extractZip(archive.Bytes(), "tcpcat.exe"); err == nil {
		t.Fatal("expected an error when the binary isn't in the archive")
	}
}

func TestExtractBinaryDispatchesOnExtension(t *testing.T) {
	var tarArchive bytes.Buffer
	gzipWriter := gzip.NewWriter(&tarArchive)
	tarWriter := tar.NewWriter(gzipWriter)
	binary := []byte("tar binary")
	_ = tarWriter.WriteHeader(&tar.Header{Name: "tcpcat", Mode: 0755, Size: int64(len(binary))})
	_, _ = tarWriter.Write(binary)
	_ = tarWriter.Close()
	_ = gzipWriter.Close()

	got, err := extractBinary("tcpcat_1.0.0_linux_amd64.tar.gz", tarArchive.Bytes(), "tcpcat")
	if err != nil || !bytes.Equal(got, binary) {
		t.Fatalf("extractBinary(.tar.gz) = (%q, %v), want (%q, nil)", got, err, binary)
	}

	var zipArchive bytes.Buffer
	zipWriter := zip.NewWriter(&zipArchive)
	zipBinary := []byte("zip binary")
	w, _ := zipWriter.Create("tcpcat.exe")
	_, _ = w.Write(zipBinary)
	_ = zipWriter.Close()

	got, err = extractBinary("tcpcat_1.0.0_windows_amd64.zip", zipArchive.Bytes(), "tcpcat.exe")
	if err != nil || !bytes.Equal(got, zipBinary) {
		t.Fatalf("extractBinary(.zip) = (%q, %v), want (%q, nil)", got, err, zipBinary)
	}
}

func TestFindAsset(t *testing.T) {
	assets := []asset{{Name: "a.tar.gz", DownloadURL: "https://example.com/a"}, {Name: "checksums.txt", DownloadURL: "https://example.com/b"}}

	got, ok := findAsset(assets, "checksums.txt")
	if !ok || got.DownloadURL != "https://example.com/b" {
		t.Fatalf("findAsset() = (%+v, %v), want the checksums.txt asset", got, ok)
	}

	if _, ok := findAsset(assets, "does-not-exist"); ok {
		t.Fatal("findAsset() found a non-existent asset")
	}
}

func TestReplaceExecutable(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tcpcat")
	if err := os.WriteFile(target, []byte("old binary"), 0755); err != nil {
		t.Fatalf("seed existing binary: %v", err)
	}

	newData := []byte("new binary contents")
	if err := replaceExecutable(target, newData); err != nil {
		t.Fatalf("replaceExecutable() error = %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read replaced binary: %v", err)
	}
	if !bytes.Equal(got, newData) {
		t.Fatalf("replaced binary = %q, want %q", got, newData)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat replaced binary: %v", err)
	}
	if info.Mode().Perm()&0100 == 0 {
		t.Errorf("replaced binary is not executable: mode = %v", info.Mode())
	}

	// No leftover .tcpcat-update-* temp file should remain in the directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "tcpcat" {
		t.Errorf("directory contains unexpected leftovers: %v", entries)
	}
}

// rewriteTransport redirects every request to target's host, so update.Run's
// hardcoded GitHub API URL can be exercised against an httptest.Server.
type rewriteTransport struct {
	target *url.URL
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = t.target.Scheme
	req.URL.Host = t.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func newTestClient(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return &http.Client{Transport: rewriteTransport{target: target}, Timeout: 5 * time.Second}
}

func TestGetRelease(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name": "v1.2.3", "assets": [{"name": "a.tar.gz", "browser_download_url": "https://example.com/a"}]}`))
	})

	got, err := getRelease(client, "NycolazSec", "tcpcat")
	if err != nil {
		t.Fatalf("getRelease() error = %v", err)
	}
	if got.TagName != "v1.2.3" || len(got.Assets) != 1 {
		t.Errorf("got %+v, want tag v1.2.3 with 1 asset", got)
	}
}

func TestGetReleaseNoTag(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"assets": []}`))
	})

	if _, err := getRelease(client, "NycolazSec", "tcpcat"); err == nil {
		t.Fatal("expected an error when the release has no tag")
	}
}

func TestGetReleaseNon200(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	if _, err := getRelease(client, "NycolazSec", "tcpcat"); err == nil {
		t.Fatal("expected an error for a non-200 response")
	}
}

func TestDownload(t *testing.T) {
	want := []byte("archive bytes")
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(want)
	})

	got, err := download(client, "https://example.com/asset")
	if err != nil {
		t.Fatalf("download() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("download() = %q, want %q", got, want)
	}
}

func TestDownloadNon200(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	if _, err := download(client, "https://example.com/asset"); err == nil {
		t.Fatal("expected an error for a non-200 download response")
	}
}
