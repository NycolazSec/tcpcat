package update

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const apiURL = "https://api.github.com/repos/%s/%s/releases/latest"

type release struct {
	TagName string  `json:"tag_name"`
	Assets  []asset `json:"assets"`
}

type asset struct {
	Name        string `json:"name"`
	DownloadURL string `json:"browser_download_url"`
}

func Run(commandPath, owner, repository string) error {
	client := &http.Client{Timeout: 20 * time.Second}
	latest, err := getRelease(client, owner, repository)
	if err != nil {
		return err
	}
	archiveName := fmt.Sprintf("%s_%s_%s_%s.tar.gz", repository, strings.TrimPrefix(latest.TagName, "v"), runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		archiveName = strings.TrimSuffix(archiveName, ".tar.gz") + ".zip"
	}
	archiveAsset, ok := findAsset(latest.Assets, archiveName)
	if !ok {
		return fmt.Errorf("release %s has no asset for %s/%s", latest.TagName, runtime.GOOS, runtime.GOARCH)
	}
	checksumAsset, ok := findAsset(latest.Assets, "checksums.txt")
	if !ok {
		return fmt.Errorf("release %s has no checksums.txt", latest.TagName)
	}

	archiveData, err := download(client, archiveAsset.DownloadURL)
	if err != nil {
		return fmt.Errorf("download %s: %w", archiveName, err)
	}
	checksums, err := download(client, checksumAsset.DownloadURL)
	if err != nil {
		return fmt.Errorf("download checksums.txt: %w", err)
	}
	if err := verifyChecksum(archiveName, archiveData, checksums); err != nil {
		return err
	}
	binaryData, err := extractBinary(archiveName, archiveData, repository)
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current binary: %w", err)
	}
	if commandPath != "" && filepath.Base(commandPath) != filepath.Base(executable) {
		executable = commandPath
	}
	if err := replaceExecutable(executable, binaryData); err != nil {
		return err
	}
	fmt.Printf("[+] Updated tcpcat to %s from %s\n", latest.TagName, archiveName)
	return nil
}

func getRelease(client *http.Client, owner, repository string) (release, error) {
	url := fmt.Sprintf(apiURL, owner, repository)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return release{}, fmt.Errorf("query latest release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return release{}, fmt.Errorf("GitHub returned %s", resp.Status)
	}
	var result release
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return release{}, fmt.Errorf("decode release metadata: %w", err)
	}
	if result.TagName == "" {
		return release{}, fmt.Errorf("GitHub release has no tag")
	}
	return result, nil
}

func findAsset(assets []asset, name string) (asset, bool) {
	for _, candidate := range assets {
		if candidate.Name == name {
			return candidate, true
		}
	}
	return asset{}, false
}

func download(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

func verifyChecksum(name string, data, checksums []byte) error {
	hash := sha256.Sum256(data)
	want := hex.EncodeToString(hash[:])
	scanner := bufio.NewScanner(strings.NewReader(string(checksums)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && filepath.Base(fields[len(fields)-1]) == name {
			if !strings.EqualFold(fields[0], want) {
				return fmt.Errorf("checksum mismatch for %s", name)
			}
			return nil
		}
	}
	return fmt.Errorf("checksum for %s not found", name)
}

func extractBinary(archiveName string, data []byte, repository string) ([]byte, error) {
	if strings.HasSuffix(archiveName, ".zip") {
		return extractZip(data, repository)
	}
	return extractTarGz(data, repository)
}

func extractTarGz(data []byte, repository string) ([]byte, error) {
	gz, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		if filepath.Base(header.Name) == repository && header.Typeflag == tar.TypeReg {
			return io.ReadAll(io.LimitReader(reader, 128<<20))
		}
	}
	return nil, fmt.Errorf("binary %s not found in archive", repository)
}

func extractZip(data []byte, repository string) ([]byte, error) {
	temp, err := os.CreateTemp("", "tcpcat-update-*.zip")
	if err != nil {
		return nil, err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return nil, err
	}
	if err := temp.Close(); err != nil {
		return nil, err
	}
	archive, err := zip.OpenReader(name)
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer archive.Close()
	for _, file := range archive.File {
		if filepath.Base(file.Name) == repository {
			reader, err := file.Open()
			if err != nil {
				return nil, err
			}
			defer reader.Close()
			return io.ReadAll(io.LimitReader(reader, 128<<20))
		}
	}
	return nil, fmt.Errorf("binary %s not found in archive", repository)
}

func replaceExecutable(path string, data []byte) error {
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".tcpcat-update-*")
	if err != nil {
		return fmt.Errorf("create replacement: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0755); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace %s: %w (try running with appropriate permissions)", path, err)
	}
	return nil
}
