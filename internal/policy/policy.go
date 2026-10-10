// Package policy checks network segmentation against a declared policy.
//
// A policy file names zones (sets of hosts/CIDRs) and rules saying, for a
// given vantage point ("from"), which TCP ports of a zone ("to") may be
// reachable. tcpcat runs from one vantage at a time: `tcpcat policy check
// file.yaml --from guest-wifi` evaluates only the rules whose `from` is
// guest-wifi, scans their targets, and reports every reachable port the
// policy does not allow (and, optionally, every required port that is not
// reachable). Running the same file from each vantage and merging the
// reports gives the full segmentation matrix.
package policy

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/NycolazSec/tcpcat/internal/ports"
)

// DefaultPorts is what a rule scans when it doesn't say: the 1000 most
// common ports, the same default scope as a plain scan.
const DefaultPorts = "top-1000"

type Policy struct {
	Version int                 `yaml:"version"`
	Name    string              `yaml:"name"`
	Zones   map[string][]string `yaml:"zones"`
	Rules   []Rule              `yaml:"rules"`
}

type Rule struct {
	Name string `yaml:"name"`
	// From is the vantage this rule is checked from (a free-form label the
	// operator passes as --from, e.g. "internet", "guest-wifi").
	From string `yaml:"from"`
	// To is a zone name, or a literal host/CIDR when no zone has that name.
	To string `yaml:"to"`
	// Ports to probe: "22,80,443", "1-1024", or "top-N". Defaults to top-1000.
	Ports string `yaml:"ports"`
	// Allow lists the ports that may be reachable ("443" or "443/tcp").
	// Anything else found open is a violation. Empty means nothing may be.
	Allow []string `yaml:"allow"`
	// Require lists ports that must be reachable; one that isn't is a
	// violation too (catches a rule change that broke a needed flow).
	Require []string `yaml:"require"`
}

// Check is one rule resolved for execution: concrete ports and targets.
type Check struct {
	Rule    Rule
	Targets []string
	Ports   []int
	allow   map[int]bool
	require []int
}

// Load reads and validates a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(data)
}

// Parse decodes and validates a policy document. Unknown keys are an error:
// a typo such as "alow:" must not silently turn a rule into "allow nothing".
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) validate() error {
	if p.Version != 1 {
		return fmt.Errorf("policy: unsupported version %d (expected 1)", p.Version)
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy: no rules")
	}
	for name, members := range p.Zones {
		if len(members) == 0 {
			return fmt.Errorf("policy: zone %q is empty", name)
		}
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Name == "" {
			r.Name = fmt.Sprintf("%s -> %s", r.From, r.To)
		}
		if r.From == "" || r.To == "" {
			return fmt.Errorf("policy: rule %d (%s): `from` and `to` are required", i+1, r.Name)
		}
		if r.Ports == "" {
			r.Ports = DefaultPorts
		}
		if _, err := parseRulePorts(r.Ports); err != nil {
			return fmt.Errorf("policy: rule %q: %w", r.Name, err)
		}
		for _, list := range [][]string{r.Allow, r.Require} {
			if _, err := parsePortList(list); err != nil {
				return fmt.Errorf("policy: rule %q: %w", r.Name, err)
			}
		}
	}
	return nil
}

// Vantages lists the distinct `from` labels, for a helpful error when
// --from matches none of them.
func (p *Policy) Vantages() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range p.Rules {
		if !seen[r.From] {
			seen[r.From] = true
			out = append(out, r.From)
		}
	}
	sort.Strings(out)
	return out
}

// Plan resolves the rules that apply to vantage into checks. resolve turns
// a list of host/CIDR/name entries into IP addresses (target.ParseTargets in
// production; a stub in tests).
func (p *Policy) Plan(vantage string, resolve func([]string) ([]string, error)) ([]Check, error) {
	var checks []Check
	for _, r := range p.Rules {
		if r.From != vantage {
			continue
		}
		members, ok := p.Zones[r.To]
		if !ok {
			members = []string{r.To}
		}
		targets, err := resolve(members)
		if err != nil {
			return nil, fmt.Errorf("rule %q: resolve %q: %w", r.Name, r.To, err)
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("rule %q: %q resolves to no address", r.Name, r.To)
		}
		portList, _ := parseRulePorts(r.Ports) // validated in Parse
		allow, _ := parsePortList(r.Allow)
		require, _ := parsePortList(r.Require)
		allowSet := make(map[int]bool, len(allow))
		for _, port := range allow {
			allowSet[port] = true
		}
		// A required port must actually be probed, even if the rule's port
		// range wouldn't otherwise include it.
		portList = mergePorts(portList, require)
		checks = append(checks, Check{Rule: r, Targets: targets, Ports: portList, allow: allowSet, require: require})
	}
	return checks, nil
}

// Endpoint is one reachable host:port.
type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

const (
	ViolationUnexpectedOpen = "unexpected-open"
	ViolationRequiredClosed = "required-unreachable"
)

type Violation struct {
	Kind string `json:"kind"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Evaluate compares the open endpoints found for a check against its rule.
func (c Check) Evaluate(open []Endpoint) []Violation {
	var violations []Violation
	openSet := map[Endpoint]bool{}
	for _, ep := range open {
		openSet[ep] = true
		if !c.allow[ep.Port] {
			violations = append(violations, Violation{Kind: ViolationUnexpectedOpen, IP: ep.IP, Port: ep.Port})
		}
	}
	for _, ip := range c.Targets {
		for _, port := range c.require {
			if !openSet[Endpoint{IP: ip, Port: port}] {
				violations = append(violations, Violation{Kind: ViolationRequiredClosed, IP: ip, Port: port})
			}
		}
	}
	sort.Slice(violations, func(i, j int) bool {
		a, b := violations[i], violations[j]
		if a.Kind != b.Kind {
			return a.Kind > b.Kind // unexpected-open first
		}
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		return a.Port < b.Port
	})
	return violations
}

func parseRulePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if strings.HasPrefix(spec, "top-") {
		n, err := strconv.Atoi(strings.TrimPrefix(spec, "top-"))
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid ports %q", spec)
		}
		return ports.ParsePorts("", n)
	}
	list, err := ports.ParsePorts(spec, 0)
	if err != nil {
		return nil, fmt.Errorf("invalid ports %q: %w", spec, err)
	}
	return list, nil
}

// parsePortList accepts "443" and "443/tcp". UDP isn't supported: a TCP
// connect check can't tell whether a UDP port is reachable.
func parsePortList(entries []string) ([]int, error) {
	var out []int
	for _, entry := range entries {
		value := strings.TrimSpace(entry)
		if strings.Contains(value, "/") {
			parts := strings.SplitN(value, "/", 2)
			if !strings.EqualFold(parts[1], "tcp") {
				return nil, fmt.Errorf("port %q: only TCP is supported", entry)
			}
			value = parts[0]
		}
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", entry)
		}
		out = append(out, port)
	}
	return out, nil
}

func mergePorts(base, extra []int) []int {
	seen := make(map[int]bool, len(base)+len(extra))
	var out []int
	for _, list := range [][]int{base, extra} {
		for _, port := range list {
			if !seen[port] {
				seen[port] = true
				out = append(out, port)
			}
		}
	}
	sort.Ints(out)
	return out
}
