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

type ExploitModule struct {
	CVE         string
	Name        string
	Description string
	CVSS        float64
	Affected    []string
	Code        []byte
}

type ExploitFrameworkV2 struct {
	Exploits map[string]*ExploitModule
	Engine   *ScriptEngineV2
}

func NewExploitFrameworkV2(engine *ScriptEngineV2) *ExploitFrameworkV2 {
	return &ExploitFrameworkV2{
		Exploits: make(map[string]*ExploitModule),
		Engine:   engine,
	}
}

func (ef *ExploitFrameworkV2) RegisterExploit(exploit *ExploitModule) error {
	if exploit.CVE == "" {
		return fmt.Errorf("exploit missing CVE identifier")
	}

	ef.Exploits[exploit.CVE] = exploit

	if exploit.Code != nil && ef.Engine != nil {
		if err := ef.Engine.LoadDetectionScript(exploit.CVE, exploit.Code); err != nil {
			log.Printf("Warning: failed to load exploit code for %s: %v", exploit.CVE, err)
		}
	}

	log.Printf("Registered exploit: %s (CVSS: %.1f)", exploit.CVE, exploit.CVSS)
	return nil
}

func (ef *ExploitFrameworkV2) FindApplicableExploits(serviceVersion string) []*ExploitModule {
	var applicable []*ExploitModule

	for _, exploit := range ef.Exploits {
		for _, affected := range exploit.Affected {
			if isVulnerable(serviceVersion, affected) {
				applicable = append(applicable, exploit)
			}
		}
	}

	return applicable
}

var BuiltInExploits = []*ExploitModule{
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

type PayloadGenerator struct {
	Templates map[string]string
}

func NewPayloadGenerator() *PayloadGenerator {
	return &PayloadGenerator{
		Templates: make(map[string]string),
	}
}

func (pg *PayloadGenerator) Generate(templateName string, params map[string]interface{}) ([]byte, error) {
	_, ok := pg.Templates[templateName]
	if !ok {
		return nil, fmt.Errorf("template %s not found", templateName)
	}

	return nil, nil
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
