package target

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadFromFile(t *testing.T) {
	content := "192.168.1.1\n# a comment line\n\n10.0.0.1 10.0.0.2\nnot-a-real-hostname-at-all.invalid\n"
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	got, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}
	want := []string{"192.168.1.1", "10.0.0.1", "10.0.0.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (comments/blank lines skipped, unresolvable hostname silently dropped)", got, want)
	}
}

func TestLoadFromFileMissing(t *testing.T) {
	if _, err := LoadFromFile(filepath.Join(t.TempDir(), "does-not-exist.txt")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestLoadFromFileEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	got, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
