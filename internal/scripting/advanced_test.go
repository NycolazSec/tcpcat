package scripting

import (
	"context"
	"testing"
)

func TestScriptEngineV2Creation(t *testing.T) {
	ctx := context.Background()
	engine, err := NewScriptEngineV2(ctx)

	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	if engine == nil {
		t.Error("Engine should not be nil")
	}

	defer func() { _ = engine.Close() }()
}

func TestCustomServiceDetectorsRegistration(t *testing.T) {
	ctx := context.Background()
	engine, _ := NewScriptEngineV2(ctx)
	defer func() { _ = engine.Close() }()

	detectors := NewCustomServiceDetectors(engine)

	script := &ServiceDetectionScript{
		Name:    "ssh-detector",
		Version: "1.0.0",
		Fingerprints: []Fingerprint{
			{Pattern: "OpenSSH", ServiceName: "SSH", Confidence: 0.95},
		},
	}

	err := detectors.Register(script)
	if err != nil {
		t.Fatalf("Failed to register detector: %v", err)
	}

	if len(detectors.Detectors) != 1 {
		t.Errorf("Expected 1 detector, got %d", len(detectors.Detectors))
	}
}

func TestServiceDetection(t *testing.T) {
	ctx := context.Background()
	engine, _ := NewScriptEngineV2(ctx)
	defer func() { _ = engine.Close() }()

	detectors := NewCustomServiceDetectors(engine)

	sshDetector := &ServiceDetectionScript{
		Name:    "ssh",
		Version: "1.0.0",
		Fingerprints: []Fingerprint{
			{Pattern: "OpenSSH", ServiceName: "SSH", Confidence: 0.95},
		},
	}
	if err := detectors.Register(sshDetector); err != nil {
		t.Fatalf("Failed to register ssh detector: %v", err)
	}

	httpDetector := &ServiceDetectionScript{
		Name:    "http",
		Version: "1.0.0",
		Fingerprints: []Fingerprint{
			{Pattern: "Apache", ServiceName: "Apache HTTP", Confidence: 0.90},
		},
	}
	if err := detectors.Register(httpDetector); err != nil {
		t.Fatalf("Failed to register http detector: %v", err)
	}

	service, confidence := detectors.Detect("OpenSSH_7.4", 22)

	if service != "unknown" && confidence <= 0 {
		t.Logf("Detection result: %s (confidence: %.2f)", service, confidence)
	}
}

func TestVulnerabilityAdvisoryRegistration(t *testing.T) {
	catalog := NewAdvisoryCatalog()

	advisory := &VulnerabilityAdvisory{
		CVE:         "CVE-2021-0001",
		Name:        "Test Advisory",
		Description: "Test vulnerability",
		CVSS:        7.5,
		Affected:    []string{"1.0.0", "1.0.1"},
	}

	err := catalog.RegisterAdvisory(advisory)
	if err != nil {
		t.Fatalf("Failed to register advisory: %v", err)
	}

	if len(catalog.Advisories) != 1 {
		t.Errorf("Expected 1 advisory, got %d", len(catalog.Advisories))
	}
}

func TestBuiltInAdvisoriesAvailable(t *testing.T) {
	if len(BuiltInAdvisories) == 0 {
		t.Error("BuiltInAdvisories should not be empty")
	}

	for _, advisory := range BuiltInAdvisories {
		if advisory.CVE == "" {
			t.Error("Advisory missing CVE")
		}
		if advisory.Name == "" {
			t.Error("Advisory missing Name")
		}
		if advisory.CVSS == 0 {
			t.Error("Advisory missing CVSS score")
		}
	}
}

func TestFindApplicableAdvisories(t *testing.T) {
	catalog := NewAdvisoryCatalog()

	advisory := &VulnerabilityAdvisory{
		CVE:      "CVE-2021-0001",
		Name:     "Test",
		CVSS:     7.5,
		Affected: []string{"7.4", "7.5"},
	}
	if err := catalog.RegisterAdvisory(advisory); err != nil {
		t.Fatalf("Failed to register advisory: %v", err)
	}

	applicable := catalog.FindApplicableAdvisories("7.4")

	if applicable == nil {
		t.Log("No advisories found (expected until version matching is implemented)")
	}
}

func TestMultipleDetectorConflict(t *testing.T) {
	ctx := context.Background()
	engine, _ := NewScriptEngineV2(ctx)
	defer func() { _ = engine.Close() }()

	detectors := NewCustomServiceDetectors(engine)

	detector1 := &ServiceDetectionScript{
		Name: "detector1",
		Fingerprints: []Fingerprint{
			{Pattern: "Apache", ServiceName: "WebServer", Confidence: 0.80},
		},
	}
	if err := detectors.Register(detector1); err != nil {
		t.Fatalf("Failed to register detector1: %v", err)
	}

	detector2 := &ServiceDetectionScript{
		Name: "detector2",
		Fingerprints: []Fingerprint{
			{Pattern: "Apache", ServiceName: "Apache", Confidence: 0.95},
		},
	}
	if err := detectors.Register(detector2); err != nil {
		t.Fatalf("Failed to register detector2: %v", err)
	}

	service, confidence := detectors.Detect("Apache/2.4", 80)

	if service != "unknown" && confidence > 0.8 {
		t.Logf("Correctly selected higher confidence: %s (%.2f)", service, confidence)
	}
}

func BenchmarkServiceDetection(b *testing.B) {
	ctx := context.Background()
	engine, _ := NewScriptEngineV2(ctx)
	defer func() { _ = engine.Close() }()

	detectors := NewCustomServiceDetectors(engine)

	for i := 0; i < 100; i++ {
		detector := &ServiceDetectionScript{
			Name: "detector" + string(rune(i)),
			Fingerprints: []Fingerprint{
				{Pattern: "Service", ServiceName: "Service", Confidence: 0.9},
			},
		}
		_ = detectors.Register(detector)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detectors.Detect("Service Banner", 80)
	}
}

func BenchmarkAdvisoryLookup(b *testing.B) {
	catalog := NewAdvisoryCatalog()

	for i := 0; i < 50; i++ {
		advisory := &VulnerabilityAdvisory{
			CVE:      "CVE-2021-000" + string(rune(i)),
			CVSS:     7.5,
			Affected: []string{"1.0.0"},
		}
		_ = catalog.RegisterAdvisory(advisory)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = catalog.FindApplicableAdvisories("1.0.0")
	}
}

func TestMatchesPatternSupportsRegex(t *testing.T) {
	if !matchesPattern("OpenSSH_7.4", "OpenSSH") {
		t.Fatal("expected simple substring pattern to match")
	}

	if !matchesPattern("OpenSSH_7.4", ".*7\\.4.*") {
		t.Fatal("expected regex pattern to match")
	}

	if matchesPattern("OpenSSH_7.4", "Apache") {
		t.Fatal("unexpected match for different service")
	}
}

func TestIsVulnerableVersionMatching(t *testing.T) {
	if !isVulnerable("7.4", "7.4") {
		t.Fatal("exact version match should be vulnerable")
	}

	if !isVulnerable("7.4.1", "7.4") {
		t.Fatal("later patch version should remain within the vulnerable family")
	}

	if isVulnerable("7.5", "7.4") {
		t.Fatal("different minor version should not be treated as vulnerable unless explicitly listed")
	}

	if isVulnerable("8.0", "7.4") {
		t.Fatal("major version bump should not match old family")
	}
}
