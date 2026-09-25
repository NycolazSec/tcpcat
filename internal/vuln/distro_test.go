package vuln

import "testing"

func TestDetectDistroPackage(t *testing.T) {
	tests := []struct {
		name            string
		software        string
		upstreamVersion string
		banner          string
		wantEcosystem   string
		wantPkgName     string
		wantVersion     string
		wantOK          bool
	}{
		{
			name:            "Debian backport suffix",
			software:        "mariadb",
			upstreamVersion: "11.8.6",
			banner:          "11.8.6-MariaDB-0+deb13u1",
			wantEcosystem:   "Debian:13",
			wantPkgName:     "mariadb",
			wantVersion:     "11.8.6-0+deb13u1",
			wantOK:          true,
		},
		{
			name:            "Ubuntu ~ubuYYMM suffix, full dpkg version already restated",
			software:        "mariadb",
			upstreamVersion: "10.6.12",
			banner:          "10.6.12-MariaDB-1:10.6.12+maria~ubu2004-log",
			wantEcosystem:   "Ubuntu:20.04",
			wantPkgName:     "mariadb",
			wantVersion:     "1:10.6.12+maria~ubu2004-log",
			wantOK:          true,
		},
		{
			name:            "apache maps to the apache2 Debian source package",
			software:        "apache",
			upstreamVersion: "2.4.41",
			banner:          "2.4.41-4+deb11u1",
			wantEcosystem:   "Debian:11",
			wantPkgName:     "apache2",
			wantVersion:     "2.4.41-4+deb11u1",
			wantOK:          true,
		},
		{
			name:            "generic Ubuntu dpkg revision has no extractable release number",
			software:        "openssh",
			upstreamVersion: "8.9p1",
			banner:          "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
			wantOK:          false,
		},
		{
			name:            "no distro suffix at all (plain upstream banner)",
			software:        "nginx",
			upstreamVersion: "1.24.0",
			banner:          "nginx/1.24.0",
			wantOK:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, ok := DetectDistroPackage(tt.software, tt.upstreamVersion, tt.banner)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (pkg=%+v)", ok, tt.wantOK, pkg)
			}
			if !ok {
				return
			}
			if pkg.Ecosystem != tt.wantEcosystem {
				t.Errorf("Ecosystem = %q, want %q", pkg.Ecosystem, tt.wantEcosystem)
			}
			if pkg.Name != tt.wantPkgName {
				t.Errorf("Name = %q, want %q", pkg.Name, tt.wantPkgName)
			}
			if pkg.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", pkg.Version, tt.wantVersion)
			}
		})
	}
}
