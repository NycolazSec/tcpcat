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

func TestIsVersionAffectedLastAffectedIsInclusive(t *testing.T) {
	ranges := []osvAffected{{Ranges: []osvRange{{Type: "SEMVER", Events: []osvEvent{
		{Introduced: "1.0.0"},
		{LastAffected: "1.4.0"},
	}}}}}
	for version, want := range map[string]bool{"1.2.0": true, "1.4.0": true, "1.4.1": false, "0.9.0": false} {
		if got := IsVersionAffected(version, ranges); got != want {
			t.Errorf("IsVersionAffected(%q) = %v, want %v", version, got, want)
		}
	}
}

func TestCompareDistroVersionsAdoptsTheBoundaryEpoch(t *testing.T) {
	tests := []struct {
		target, boundary string
		want             int
	}{
		{"10.0p2-7+deb13u4", "1:9.3p2-1", 1},           // without the epoch this read 10 vs 1
		{"10.0p2-7+deb13u4", "1:10.0p2-7+deb13u4", 0},  // the exact fixed version
		{"10.0p2-7+deb13u3", "1:10.0p2-7+deb13u4", -1}, // one backport behind
		{"1:10.0p2-7", "1:9.3p2-1", 1},                 // target already has one
	}
	for _, tt := range tests {
		if got := compareDistroVersions(tt.target, tt.boundary); got != tt.want {
			t.Errorf("compareDistroVersions(%q, %q) = %d, want %d", tt.target, tt.boundary, got, tt.want)
		}
	}
}

func TestUpstreamPart(t *testing.T) {
	for in, want := range map[string]string{
		"1:9.3p2-1":           "9.3p2",
		"1:10.0p2-7+deb13u4":  "10.0p2",
		"9.3_p2-r0":           "9.3_p2",
		"1.24.0+dfsg-1":       "1.24.0",
		"5:7.0.15-1~deb12u4":  "7.0.15",
		"8.7p1-38.el9":        "8.7p1",
		"9.6p1":               "9.6p1",
		"1:8.9p1-3ubuntu0.10": "8.9p1",
	} {
		if got := upstreamPart(in); got != want {
			t.Errorf("upstreamPart(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsUpstreamVersionAffected(t *testing.T) {
	ubuntuOpen := osvAffected{Package: osvPackage{Name: "openssh", Ecosystem: "Ubuntu:24.04:LTS"},
		Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "0"}}}}}
	ubuntuBackport := osvAffected{Package: osvPackage{Name: "openssh", Ecosystem: "Ubuntu:22.04:LTS"},
		Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "0"}, {Fixed: "1:8.9p1-3ubuntu0.3"}}}}}
	debianFix := osvAffected{Package: osvPackage{Name: "openssh", Ecosystem: "Debian:13"},
		Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "0"}, {Fixed: "1:9.3p2-1"}}}}}
	pypi := osvAffected{Package: osvPackage{Name: "redis", Ecosystem: "PyPI"},
		Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "0"}}}}}
	upstreamSemver := osvAffected{Ranges: []osvRange{{Type: "SEMVER", Events: []osvEvent{{Introduced: "2.0.0"}, {Fixed: "2.4.0"}}}}}

	tests := []struct {
		name     string
		version  string
		affected []osvAffected
		want     bool
	}{
		{"fixed upstream before this version, open in an Ubuntu release", "10.0p2", []osvAffected{ubuntuOpen, ubuntuBackport, debianFix}, false},
		{"older than the upstream fix", "9.2p1", []osvAffected{ubuntuOpen, ubuntuBackport, debianFix}, true},
		{"a backport's older upstream number is not the upstream fix", "9.0p1", []osvAffected{ubuntuBackport, debianFix}, true},
		{"no fix anywhere yet: every version", "10.0p2", []osvAffected{ubuntuOpen}, true},
		{"a language package with the same name is another product", "7.4.12", []osvAffected{pypi}, false},
		{"the CVE's own SEMVER range still applies", "2.1.0", []osvAffected{upstreamSemver}, true},
		{"the CVE's own SEMVER range, past the fix", "2.4.0", []osvAffected{upstreamSemver}, false},
		{"no affected data: assume affected", "1.0", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUpstreamVersionAffected(tt.version, tt.affected); got != tt.want {
				t.Errorf("IsUpstreamVersionAffected(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// TestUpstreamAndDistroMatchingOnRealOpenSSHRecords replays OSV's real
// records for CVE-2023-38408 (fixed upstream in OpenSSH 9.3p2): the CVE
// record, Debian's and Ubuntu's, as returned to a lookup by name alone
// (testdata/osv-openssh-cve-2023-38408.json, trimmed from api.osv.dev).
// Before upstream matching ignored open distro entries, every OpenSSH
// version matched, 10.0p2 included.
func TestUpstreamAndDistroMatchingOnRealOpenSSHRecords(t *testing.T) {
	data, err := os.ReadFile("testdata/osv-openssh-cve-2023-38408.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var resp osvResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	upstream := func(version string) bool {
		for _, v := range resp.Vulns {
			if affects(osvPackage{Name: "openssh"}, version, v.Affected) {
				return true
			}
		}
		return false
	}
	for version, want := range map[string]bool{"10.0p2": false, "9.7": false, "9.3p2": false, "9.3p1": true, "6.6.1p1": true} {
		if got := upstream(version); got != want {
			t.Errorf("upstream %s affected = %v, want %v", version, got, want)
		}
	}
	debian13 := func(version string) bool {
		for _, v := range resp.Vulns {
			if affects(osvPackage{Name: "openssh", Ecosystem: "Debian:13"}, version, v.Affected) {
				return true
			}
		}
		return false
	}
	// what DetectDistroPackage rebuilds from "OpenSSH_10.0p2 Debian-7+deb13u4": no epoch
	for version, want := range map[string]bool{"10.0p2-7+deb13u4": false, "9.2p1-2": true, "9.3p2-1": false} {
		if got := debian13(version); got != want {
			t.Errorf("Debian:13 %s affected = %v, want %v", version, got, want)
		}
	}
}
