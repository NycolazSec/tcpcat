package scripting

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type ScriptEngineV2 struct {
	runtime wazero.Runtime
	modules map[string]api.Module
	ctx     context.Context
}

type ServiceDetectionScript struct {
	Name         string
	Version      string
	Fingerprints []Fingerprint
	CVEs         map[string]CVEData
}

type Fingerprint struct {
	Pattern     string
	ServiceName string
	Confidence  float64
}

type CVEData struct {
	CVE         string
	CVSS        float64
	Description string
	FixVersion  string
}

func NewScriptEngineV2(ctx context.Context) (*ScriptEngineV2, error) {
	runtime := wazero.NewRuntime(ctx)

	return &ScriptEngineV2{
		runtime: runtime,
		modules: make(map[string]api.Module),
		ctx:     ctx,
	}, nil
}

func (se *ScriptEngineV2) LoadDetectionScript(name string, wasmBinary []byte) error {
	mod, err := se.runtime.Instantiate(se.ctx, wasmBinary)
	if err != nil {
		return fmt.Errorf("failed to load script %s: %w", name, err)
	}

	se.modules[name] = mod
	log.Printf("Loaded detection script: %s", name)
	return nil
}

type CustomServiceDetectors struct {
	Detectors map[string]*ServiceDetectionScript
	Engine    *ScriptEngineV2
}

func NewCustomServiceDetectors(engine *ScriptEngineV2) *CustomServiceDetectors {
	return &CustomServiceDetectors{
		Detectors: make(map[string]*ServiceDetectionScript),
		Engine:    engine,
	}
}

func (csd *CustomServiceDetectors) Register(script *ServiceDetectionScript) error {
	csd.Detectors[script.Name] = script
	log.Printf("Registered service detector: %s v%s", script.Name, script.Version)
	return nil
}

func (csd *CustomServiceDetectors) Detect(banner string, port int) (string, float64) {
	bestMatch := "unknown"
	bestConfidence := 0.0

	for _, detector := range csd.Detectors {
		for _, fp := range detector.Fingerprints {

			if matchesPattern(banner, fp.Pattern) && fp.Confidence > bestConfidence {
				bestMatch = fp.ServiceName
				bestConfidence = fp.Confidence
			}
		}
	}

	return bestMatch, bestConfidence
}

// VulnerabilityAdvisory is a piece of CVE metadata used for correlating a
// detected service/version against known vulnerabilities. It is pure data:
// it carries no executable payload and never runs anything against a target.
type VulnerabilityAdvisory struct {
	CVE         string
	Name        string
	Description string
	CVSS        float64
	Affected    []string
}

// AdvisoryCatalog looks up which known CVEs apply to a given service version.
// It only ever compares version strings; it does not connect to, or execute
// code against, any host.
type AdvisoryCatalog struct {
	Advisories map[string]*VulnerabilityAdvisory
}

func NewAdvisoryCatalog() *AdvisoryCatalog {
	return &AdvisoryCatalog{
		Advisories: make(map[string]*VulnerabilityAdvisory),
	}
}

func (ac *AdvisoryCatalog) RegisterAdvisory(advisory *VulnerabilityAdvisory) error {
	if advisory.CVE == "" {
		return fmt.Errorf("advisory missing CVE identifier")
	}

	ac.Advisories[advisory.CVE] = advisory
	log.Printf("Registered vulnerability advisory: %s (CVSS: %.1f)", advisory.CVE, advisory.CVSS)
	return nil
}

func (ac *AdvisoryCatalog) FindApplicableAdvisories(serviceVersion string) []*VulnerabilityAdvisory {
	var applicable []*VulnerabilityAdvisory

	for _, advisory := range ac.Advisories {
		for _, affected := range advisory.Affected {
			if isVulnerable(serviceVersion, affected) {
				applicable = append(applicable, advisory)
			}
		}
	}

	return applicable
}

var BuiltInAdvisories = []*VulnerabilityAdvisory{
	{
		CVE:         "CVE-2018-15473",
		Name:        "OpenSSH Username Enumeration",
		Description: "Allows remote attacker to enumerate valid usernames",
		CVSS:        7.5,
		Affected:    []string{"OpenSSH 7.4", "OpenSSH 7.5", "OpenSSH 7.6"},
	},
	{
		CVE:         "CVE-2021-2109",
		Name:        "MySQL Authentication Bypass",
		Description: "Improper validation allows authentication bypass",
		CVSS:        8.8,
		Affected:    []string{"MySQL 5.7.30", "MySQL 5.7.31"},
	},
	{
		CVE:         "CVE-2016-5007",
		Name:        "Apache Header Injection",
		Description: "HTTP Response Splitting allows header injection",
		CVSS:        5.0,
		Affected:    []string{"Apache 2.4.6", "Apache 2.4.7"},
	},
}

func matchesPattern(text, pattern string) bool {
	text = strings.TrimSpace(text)
	pattern = strings.TrimSpace(pattern)
	if text == "" || pattern == "" {
		return false
	}

	if matched, err := regexp.MatchString(pattern, text); err == nil && matched {
		return true
	}

	if matched, err := regexp.MatchString("(?i)"+regexp.QuoteMeta(pattern), text); err == nil && matched {
		return true
	}

	return strings.Contains(strings.ToLower(text), strings.ToLower(pattern))
}

func isVulnerable(version, affectedVersion string) bool {
	versionNorm := normalizeVersion(version)
	affectedNorm := normalizeVersion(affectedVersion)
	if versionNorm == "" || affectedNorm == "" {
		return version == affectedVersion
	}

	if versionNorm == affectedNorm {
		return true
	}

	versionParts := parseVersionParts(versionNorm)
	affectedParts := parseVersionParts(affectedNorm)
	if len(versionParts) == 0 || len(affectedParts) == 0 {
		return version == affectedVersion
	}

	if len(versionParts) >= 2 && len(affectedParts) >= 2 &&
		versionParts[0] == affectedParts[0] && versionParts[1] == affectedParts[1] {
		return true
	}

	if len(versionParts) >= 1 && len(affectedParts) >= 1 &&
		versionParts[0] == affectedParts[0] && len(affectedParts) == 1 {
		return true
	}

	return false
}

func normalizeVersion(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "_", ".")
	value = strings.ReplaceAll(value, "/", ".")
	value = strings.ReplaceAll(value, "-", ".")
	value = strings.ReplaceAll(value, " ", ".")

	for strings.Contains(value, "..") {
		value = strings.ReplaceAll(value, "..", ".")
	}

	if match := regexp.MustCompile(`\d+(?:\.\d+)+`).FindString(value); match != "" {
		return match
	}
	if match := regexp.MustCompile(`\d+`).FindString(value); match != "" {
		return match
	}
	return ""
}

func parseVersionParts(version string) []int {
	parts := strings.Split(version, ".")
	res := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		res = append(res, v)
	}
	return res
}

func (se *ScriptEngineV2) Close() error {
	if se.runtime != nil {
		return se.runtime.Close(se.ctx)
	}
	return nil
}
