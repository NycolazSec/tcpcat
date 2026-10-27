package scripthub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeHub creates a temp hub: a module file plus an index.json that references
// it by relative path, and returns the index path and the module's real digest.
func writeHub(t *testing.T, moduleBytes []byte, indexSHA string) (indexPath string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "dissectors"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dissectors", "demo.wasm"), moduleBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	idx := Index{
		SchemaVersion: 1,
		Dissectors: []Dissector{{
			Name:        "demo",
			Description: "a demo dissector",
			Version:     "1.0.0",
			URL:         "dissectors/demo.wasm",
			SHA256:      indexSHA,
		}},
	}
	b, _ := json.Marshal(idx)
	indexPath = filepath.Join(dir, "index.json")
	if err := os.WriteFile(indexPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return indexPath
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestInstallVerifiesDigest(t *testing.T) {
	module := []byte("\x00asm\x01\x00\x00\x00 pretend module")
	good := digest(module)

	t.Run("matching digest installs", func(t *testing.T) {
		indexPath := writeHub(t, module, good)
		idx, base, err := FetchIndex(indexPath)
		if err != nil {
			t.Fatal(err)
		}
		d, ok := idx.Find("demo")
		if !ok {
			t.Fatal("demo not found in index")
		}
		dest := t.TempDir()
		out, err := Install(d, base, dest)
		if err != nil {
			t.Fatalf("install: %v", err)
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if digest(got) != good {
			t.Fatal("installed file does not match the source module")
		}
	})

	t.Run("mismatched digest is refused and writes nothing", func(t *testing.T) {
		// Index claims a digest that does not match the file on disk.
		indexPath := writeHub(t, module, digest([]byte("different")))
		idx, base, _ := FetchIndex(indexPath)
		d, _ := idx.Find("demo")
		dest := t.TempDir()
		if _, err := Install(d, base, dest); err == nil {
			t.Fatal("expected integrity failure, got nil")
		}
		if entries, _ := os.ReadDir(dest); len(entries) != 0 {
			t.Fatalf("a rejected install left %d file(s) behind", len(entries))
		}
	})
}

func TestInstallRejectsUnsafeName(t *testing.T) {
	d := &Dissector{Name: "../evil", URL: "x", SHA256: digest([]byte("x"))}
	if _, err := Install(d, t.TempDir(), t.TempDir()); err == nil {
		t.Fatal("expected unsafe-name rejection")
	}
}

func TestSearchAndRemove(t *testing.T) {
	idx := &Index{Dissectors: []Dissector{
		{Name: "redis", Description: "key-value store"},
		{Name: "http", Description: "web server"},
	}}
	if got := idx.Search("key"); len(got) != 1 || got[0].Name != "redis" {
		t.Fatalf("search by description failed: %+v", got)
	}
	if got := idx.Search(""); len(got) != 2 {
		t.Fatalf("empty query should return all, got %d", len(got))
	}

	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "redis.wasm"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Remove("redis", dest); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := Remove("redis", dest); err == nil {
		t.Fatal("removing a missing module should error")
	}
}
