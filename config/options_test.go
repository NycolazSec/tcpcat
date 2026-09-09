package config

import (
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
