package vuln

import (
	"encoding/json"
	"os"
	"testing"
)

func TestTokenizer(t *testing.T) {
	tests := []struct {
		version string
		want    []string
	}{
		{"1.2.3", []string{"1", "2", "3"}},
		{"8.9p1", []string{"8", "9", "p", "1"}},
		{"", nil},
		{"v2.4.41", []string{"v", "2", "4", "41"}},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := tokenizer(tt.version)
			if len(got) != len(tt.want) {
				t.Fatalf("tokenizer(%q) = %v, want %v", tt.version, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("tokenizer(%q)[%d] = %q, want %q", tt.version, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		{"1.2.3", "1.2.4", -1},
		{"1.2.4", "1.2.3", 1},
		{"1.2.3", "1.2.3", 0},
		{"1.10", "1.9", 1}, // numeric-aware: 10 > 9, not lexicographic
		{"1.9", "1.10", -1},
		{"8.9p1", "8.9p2", -1},
		{"2.0", "1.9.9", 1},
		{"1.0-beta", "1.0", 1}, // tokenizer yields ["1","0","beta"] vs ["1","0"]; trailing "beta" > "" (missing token)
	}
	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			if got := CompareVersions(tt.v1, tt.v2); got != tt.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestIsVersionAffected(t *testing.T) {
	tests := []struct {
		name    string
		version string
		ranges  []osvAffected
		want    bool
	}{
		{
			name:    "no affected entries means affected (unknown range = assume vulnerable)",
			version: "1.0.0",
			ranges:  nil,
			want:    true,
		},
		{
			name:    "version at or after introduced, no fixed event",
			version: "2.0.0",
			ranges: []osvAffected{{Ranges: []osvRange{{Type: "SEMVER", Events: []osvEvent{
				{Introduced: "1.0.0"},
			}}}}},
			want: true,
		},
		{
			name:    "version before introduced is not affected",
			version: "0.9.0",
			ranges: []osvAffected{{Ranges: []osvRange{{Type: "SEMVER", Events: []osvEvent{
				{Introduced: "1.0.0"},
			}}}}},
			want: false,
		},
		{
			name:    "version within [introduced, fixed) is affected",
			version: "1.5.0",
			ranges: []osvAffected{{Ranges: []osvRange{{Type: "SEMVER", Events: []osvEvent{
				{Introduced: "1.0.0"},
				{Fixed: "2.0.0"},
			}}}}},
			want: true,
		},
		{
			name:    "version at or after fixed is not affected",
			version: "2.0.0",
			ranges: []osvAffected{{Ranges: []osvRange{{Type: "SEMVER", Events: []osvEvent{
				{Introduced: "1.0.0"},
				{Fixed: "2.0.0"},
			}}}}},
			want: false,
		},
		{
			// ECOSYSTEM is Debian/Ubuntu's own range type (dpkg version
			// strings) and is handled the same way SEMVER is -- verified
			// against a real Debian OSV entry (DEBIAN-CVE-2024-21096) in
			// TestIsVersionAffectedHandlesRealDebianEcosystemEntry below.
			name:    "ECOSYSTEM ranges are handled like SEMVER",
			version: "1.5.0",
			ranges: []osvAffected{{Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{
				{Introduced: "1.0.0"},
			}}}}},
			want: true,
		},
		{
			name:    "an unrecognised range type is ignored",
			version: "1.5.0",
			ranges: []osvAffected{{Ranges: []osvRange{{Type: "GIT", Events: []osvEvent{
				{Introduced: "1.0.0"},
			}}}}},
			want: false,
		},
		{
			name:    "an exact hit in the versions list wins even without a matching range",
			version: "1:10.11.6-0+deb12u1",
			ranges:  []osvAffected{{Versions: []string{"1:10.11.6-0+deb12u1", "1:10.11.7-1"}}},
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsVersionAffected(tt.version, tt.ranges); got != tt.want {
				t.Errorf("IsVersionAffected(%q, ...) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// TestIsVersionAffectedHandlesRealDebianEcosystemEntry replays a real
// capture (internal/vuln/testdata/debian-cve-2024-21096.json, fetched
// from api.osv.dev/v1/vulns/DEBIAN-CVE-2024-21096) rather than a
// hand-built fixture, since Debian's OSV export's exact shape -- "type":
// "ECOSYSTEM" ranges, dpkg version strings with an epoch prefix, plus a
// parallel exact "versions" enumeration -- is exactly what a hand-rolled
// fixture would be tempted to oversimplify.
func TestIsVersionAffectedHandlesRealDebianEcosystemEntry(t *testing.T) {
	data, err := os.ReadFile("testdata/debian-cve-2024-21096.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var vuln osvVulnerability
	if err := json.Unmarshal(data, &vuln); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(vuln.Affected) == 0 {
		t.Fatal("fixture has no affected entries -- did the capture change shape?")
	}

	tests := []struct {
		version string
		want    bool
	}{
		{"1:10.11.6-0+deb12u1", true},   // in both the range and the exact versions list
		{"1:10.11.11-0+deb12u1", false}, // exactly the fixed version -- no longer affected
		{"1:10.11.12-1", false},         // past the fixed version
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := IsVersionAffected(tt.version, vuln.Affected); got != tt.want {
				t.Errorf("IsVersionAffected(%q, ...) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
