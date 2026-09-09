package target

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFilterByScopeAllowsOnlyAuthorizedIPs(t *testing.T) {
	scopeFile := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(scopeFile, []byte("127.0.0.0/8\n192.0.2.5\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := FilterByScope([]string{"127.0.0.1", "192.0.2.5", "198.51.100.8"}, scopeFile)
	if err != nil {
		t.Fatalf("FilterByScope() error = %v", err)
	}
	want := []string{"127.0.0.1", "192.0.2.5"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FilterByScope() = %v, want %v", got, want)
	}
}
