package service

import "testing"

func TestLookupJARM(t *testing.T) {
	for hash, label := range knownJARMHashes {
		if len(hash) != 62 {
			t.Errorf("knownJARMHashes has a %d-char key %q, want 62 (a JARM hash is always 62 hex chars)", len(hash), hash)
		}
		if got := lookupJARM(hash); got != label {
			t.Errorf("lookupJARM(%q) = %q, want %q", hash, got, label)
		}
	}

	if got := lookupJARM("not-a-real-hash"); got != "" {
		t.Errorf("lookupJARM(unknown) = %q, want empty", got)
	}
}
