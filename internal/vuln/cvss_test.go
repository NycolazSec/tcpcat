package vuln

import "testing"

func TestParseAndCalculateCVSSv3(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
	}{
		{
			name:   "unchanged scope, all high impact, no privileges",
			vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want:   9.8,
		},
		{
			name:   "changed scope, all high impact, no privileges (log4shell-style)",
			vector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			want:   10.0,
		},
		{
			name:   "real-world vector with CVSS:3.1 prefix parses identically",
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			want:   9.8,
		},
		{
			name:   "empty vector has no impact",
			vector: "",
			want:   0.0,
		},
		{
			name:   "no confidentiality/integrity/availability impact scores zero",
			vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			want:   0.0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseAndCalculateCVSSv3(tt.vector); got != tt.want {
				t.Errorf("ParseAndCalculateCVSSv3(%q) = %v, want %v", tt.vector, got, tt.want)
			}
		})
	}
}
