// Package scripthub manages tcpcat's library of WebAssembly detection modules
// (dissectors): discovering them from an index, installing them with integrity
// verification, and listing/removing the installed set. It is the distribution
// layer around the WASM scripting engine -- tcpcat's equivalent of Nmap's NSE
// scripts, but sandboxed, and shareable.
//
// A hub is just a static index.json (served over HTTPS, e.g. a GitHub repo)
// that lists each dissector with the SHA-256 of its .wasm. Installs are pinned
// to that digest, so a tampered or corrupted module is rejected before it ever
// reaches the scanner.
package scripthub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DefaultIndexURL is the canonical community hub. Override with --index or the
// TCPCAT_SCRIPTS_INDEX environment variable (a URL or a local path), e.g. for a
// private/internal hub or for testing.
const DefaultIndexURL = "https://raw.githubusercontent.com/NycolazSec/tcpcat-scripts/main/index.json"

// Index is the on-disk/on-wire hub format.
type Index struct {
	SchemaVersion int         `json:"schema_version"`
	Dissectors    []Dissector `json:"dissectors"`
}

// Dissector is one entry in the index.
type Dissector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Author      string `json:"author,omitempty"`
	License     string `json:"license,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
	Ports       []int  `json:"ports,omitempty"`
	// URL is where the .wasm is fetched from. It may be absolute, or relative
	// to the index's own location (so a hub repo stays self-contained).
	URL string `json:"url"`
	// SHA256 is the lowercase hex digest the downloaded module must match.
	SHA256 string `json:"sha256"`
}

// safeName accepts only the characters a dissector name may contain, which also
// makes it safe to use directly as a filename (no path traversal).
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ScriptsDir is where installed modules live: the same per-user config root
// tcpcat already uses for its offline DB. Point the scanner at it with
// `--scripts "$(tcpcat scripts dir)"`.
func ScriptsDir() (string, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locating user config dir: %w", err)
	}
	return filepath.Join(cfg, "tcpcat", "scripts"), nil
}

// IndexSource resolves which hub to use: an explicit flag wins, then the
// environment, then the default.
func IndexSource(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("TCPCAT_SCRIPTS_INDEX"); env != "" {
		return env
	}
	return DefaultIndexURL
}

// FetchIndex loads the index from a URL or a local path. It returns the parsed
// index and the base location, against which relative download URLs resolve.
func FetchIndex(src string) (*Index, string, error) {
	data, err := fetch(src)
	if err != nil {
		return nil, "", fmt.Errorf("fetching index from %s: %w", src, err)
	}
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, "", fmt.Errorf("parsing index %s: %w", src, err)
	}
	return &idx, src, nil
}

// Find returns the named dissector from the index.
func (idx *Index) Find(name string) (*Dissector, bool) {
	for i := range idx.Dissectors {
		if idx.Dissectors[i].Name == name {
			return &idx.Dissectors[i], true
		}
	}
	return nil, false
}

// Search returns dissectors whose name or description contains query
// (case-insensitive); an empty query returns all, sorted by name.
func (idx *Index) Search(query string) []Dissector {
	q := strings.ToLower(query)
	var out []Dissector
	for _, d := range idx.Dissectors {
		if q == "" || strings.Contains(strings.ToLower(d.Name), q) ||
			strings.Contains(strings.ToLower(d.Description), q) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Install downloads a dissector's module, verifies its SHA-256 against the
// index entry, and writes it to destDir as "<name>.wasm". It returns the path
// written. A digest mismatch aborts before anything is written.
func Install(d *Dissector, indexBase, destDir string) (string, error) {
	if !safeName.MatchString(d.Name) {
		return "", fmt.Errorf("refusing unsafe dissector name %q", d.Name)
	}
	want := strings.ToLower(strings.TrimSpace(d.SHA256))
	if len(want) != 64 {
		return "", fmt.Errorf("%s: index entry has no valid sha256", d.Name)
	}

	src, err := resolveRef(indexBase, d.URL)
	if err != nil {
		return "", fmt.Errorf("%s: %w", d.Name, err)
	}
	data, err := fetch(src)
	if err != nil {
		return "", fmt.Errorf("%s: downloading %s: %w", d.Name, src, err)
	}

	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != want {
		return "", fmt.Errorf("%s: integrity check failed (index expects %s, got %s) -- not installed",
			d.Name, want, got)
	}

	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", destDir, err)
	}
	out := filepath.Join(destDir, d.Name+".wasm")
	// Write to a temp file in the same dir, then rename, so a partial write
	// never leaves a half-written module the scanner would try to load.
	tmp, err := os.CreateTemp(destDir, "."+d.Name+"-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, out); err != nil {
		return "", err
	}
	return out, nil
}

// InstalledScript is a module present in the scripts dir.
type InstalledScript struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Installed lists the .wasm modules in destDir.
func Installed(destDir string) ([]InstalledScript, error) {
	entries, err := os.ReadDir(destDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []InstalledScript
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".wasm") {
			continue
		}
		p := filepath.Join(destDir, e.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(data)
		out = append(out, InstalledScript{
			Name:   strings.TrimSuffix(e.Name(), ".wasm"),
			Path:   p,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(data)),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Remove deletes an installed module by name.
func Remove(name, destDir string) error {
	if !safeName.MatchString(name) {
		return fmt.Errorf("refusing unsafe dissector name %q", name)
	}
	p := filepath.Join(destDir, name+".wasm")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return fmt.Errorf("%s is not installed", name)
	}
	return os.Remove(p)
}

// fetch reads bytes from an http(s) URL or a local path/file:// URL.
func fetch(src string) ([]byte, error) {
	if p, ok := localPath(src); ok {
		return os.ReadFile(p)
	}
	u, err := url.Parse(src)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "http", "https":
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(src)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %s", resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // 32 MiB cap
	default:
		return nil, fmt.Errorf("unsupported source scheme %q", u.Scheme)
	}
}

// localPath reports whether src names a local file (a plain path or a file://
// URL) and returns that path.
func localPath(src string) (string, bool) {
	if strings.HasPrefix(src, "file://") {
		if u, err := url.Parse(src); err == nil {
			return u.Path, true
		}
	}
	if !strings.Contains(src, "://") {
		return src, true
	}
	return "", false
}

// resolveRef resolves a (possibly relative) download URL against the index's
// location, so a hub can list its modules by relative path.
func resolveRef(indexSrc, ref string) (string, error) {
	// Absolute URL or absolute file path: use as-is.
	if strings.Contains(ref, "://") || filepath.IsAbs(ref) {
		return ref, nil
	}
	if p, ok := localPath(indexSrc); ok {
		return filepath.Join(filepath.Dir(p), ref), nil
	}
	u, err := url.Parse(indexSrc)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(path.Dir(u.Path), ref)
	return u.String(), nil
}
