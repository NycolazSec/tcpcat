package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"testing"
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
