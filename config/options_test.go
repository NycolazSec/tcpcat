package config

import (
	"strings"
	"testing"
)

func TestValidateScanCompatibility(t *testing.T) {
	tests := []struct {
		name    string
		opts    *Options
		wantErr bool
	}{
		{
			name: "TCP Connect with fragment should warn but not error",
			opts: &Options{
				ConnectScan: true,
				Fragment:    true,
			},
			wantErr: false,
		},
		{
			name: "TCP Connect with decoy should warn but not error",
			opts: &Options{
				ConnectScan: true,
				DecoyIPs:    "1.1.1.1,2.2.2.2",
			},
			wantErr: false,
		},
		{
			name: "TCP Connect with smart-bypass should disable it",
			opts: &Options{
				ConnectScan: true,
				SmartBypass: true,
			},
			wantErr: false,
		},
		{
			name: "TCP Connect with ttl-jitter should warn",
			opts: &Options{
				ConnectScan: true,
				TTLJitter:   true,
			},
			wantErr: false,
		},
		{
			name: "SYN scan with fragment is valid",
			opts: &Options{
				SynScan:  true,
				Fragment: true,
			},
			wantErr: false,
		},
		{
			name: "UDP scan with fragment is valid",
			opts: &Options{
				UdpScan:  true,
				Fragment: true,
			},
			wantErr: false,
		},
		{
			name: "TCP Connect with evasion mode should warn",
			opts: &Options{
				ConnectScan: true,
				EvasionMode: "aggressive",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateScanCompatibility(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateScanCompatibility() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateScanCompatibilityDisablesSmartBypass(t *testing.T) {
	opts := &Options{
		ConnectScan: true,
		SmartBypass: true,
	}

	err := ValidateScanCompatibility(opts)
	if err != nil {
		t.Fatalf("ValidateScanCompatibility() error = %v", err)
	}

	if opts.SmartBypass {
		t.Error("Expected SmartBypass to be disabled for TCP Connect scan")
	}
}

func TestApplySafeProductionProfile(t *testing.T) {
	opts := &Options{
		Profile:        "safe-production",
		Timing:         5,
		RateLimit:      10000,
		UnsafeNoLimits: true,
		EvasionMode:    "aggressive",
		Fragment:       true,
		DecoyIPs:       "192.0.2.1",
	}

	ApplyProfile(opts)

	if opts.Timing != 2 || opts.RateLimit != 300 || !opts.ServiceDetect {
		t.Fatalf("safe-production profile was not applied: %+v", opts)
	}
	if opts.UnsafeNoLimits || opts.EvasionMode != "off" || opts.Fragment || opts.DecoyIPs != "" {
		t.Fatalf("safe-production left unsafe options enabled: %+v", opts)
	}
}

func TestApplyOTProfileIsGentle(t *testing.T) {
	// Start from an aggressive, fast configuration -- the OT profile must
	// override every knob that could stress fragile industrial gear.
	opts := &Options{
		Profile:     "ot",
		SynScan:     true,
		UdpScan:     true,
		UseXDP:      true,
		MaxWorkers:  256,
		BatchSize:   1000,
		Timing:      5,
		RateLimit:   25000,
		MaxRetries:  4,
		EvasionMode: "aggressive",
		Fragment:    true,
		Jitter:      0.8,
		DecoyIPs:    "192.0.2.1",
		SmartBypass: true,
	}

	ApplyProfile(opts)

	if !opts.ConnectScan || opts.SynScan || opts.UdpScan || opts.UseXDP {
		t.Fatalf("ot profile must use TCP connect only, no SYN/UDP/XDP: %+v", opts)
	}
	if opts.MaxWorkers != 1 || opts.BatchSize != 1 {
		t.Fatalf("ot profile must serialize to one connection at a time: %+v", opts)
	}
	if opts.RateLimit != 5 || opts.Timing != 1 {
		t.Fatalf("ot profile must scan slowly: %+v", opts)
	}
	if opts.EvasionMode != "off" || opts.Fragment || opts.Jitter != 0 || opts.DecoyIPs != "" || opts.SmartBypass {
		t.Fatalf("ot profile must send nothing crafted: %+v", opts)
	}
	if !opts.ServiceDetect {
		t.Fatalf("ot profile should enable passive service detection: %+v", opts)
	}
	if opts.Ports != OTDefaultPorts {
		t.Fatalf("ot profile should default to the OT port set, got %q", opts.Ports)
	}
}

func TestApplyOTProfileKeepsExplicitPorts(t *testing.T) {
	opts := &Options{Profile: "ot", Ports: "502"}
	ApplyProfile(opts)
	if opts.Ports != "502" {
		t.Fatalf("an explicit -p must win over the OT default, got %q", opts.Ports)
	}
}

func TestRenderBannerEmptyFallsBackToEth0(t *testing.T) {
	if got := RenderBanner(""); !strings.Contains(got, "[eth0]") {
		t.Errorf("RenderBanner(\"\") = %q, want it to fall back to the eth0 placeholder", got)
	}
}
