// Package kb is tcpcat's dictionary of network services: what each service
// is, whether it belongs on the internet, why exposing it is dangerous and
// how to stop. The data lives in services.yaml, embedded in the binary, so
// the dictionary works offline and is reviewed like code.
package kb

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed services.yaml
var servicesYAML []byte

// Exposure says what is acceptable from the internet.
const (
	Public     = "public"
	Restricted = "restricted"
	Private    = "private"
)

// Severities, from least to most serious.
var Severities = []string{"info", "low", "medium", "high", "critical"}

// SeverityRank orders severities; an unknown value ranks below "info".
func SeverityRank(s string) int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return -1
}

// Text is a sentence in each language the dictionary is written in.
type Text struct {
	EN string `yaml:"en"`
	FR string `yaml:"fr"`
}

// In returns the text in lang ("fr" or "en"), falling back to English.
func (t Text) In(lang string) string {
	if lang == "fr" && t.FR != "" {
		return t.FR
	}
	return t.EN
}

func (t Text) empty() bool { return t.EN == "" && t.FR == "" }

// Service is one dictionary entry, with its parent's fields already merged
// in (see Dictionary.resolve).
type Service struct {
	ID       string   `yaml:"id"`
	Name     string   `yaml:"name"`
	NameFR   string   `yaml:"name_fr"`
	Parent   string   `yaml:"parent"`
	Abstract bool     `yaml:"abstract"`
	Category string   `yaml:"category"`
	Ports    []int    `yaml:"ports"`
	UDP      []int    `yaml:"udp"`
	Aliases  []string `yaml:"aliases"`
	Products []string `yaml:"products"`
	Exposure string   `yaml:"exposure"`
	Risk     string   `yaml:"risk"`
	Insecure *bool    `yaml:"insecure"`
	HTTP     *bool    `yaml:"http"`
	What     Text     `yaml:"what"`
	Why      Text     `yaml:"why"`
	Hint     Text     `yaml:"hint"`
	Banners  []string `yaml:"banners"`

	protocol string // top non-abstract ancestor, set by resolve
}

// DisplayName is the entry's name in lang ("fr" or "en").
func (s *Service) DisplayName(lang string) string {
	if lang == "fr" && s.NameFR != "" {
		return s.NameFR
	}
	return s.Name
}

// SpeaksHTTP reports whether the service is an HTTP(S) API or site.
func (s *Service) SpeaksHTTP() bool { return s.HTTP != nil && *s.HTTP }

// IsInsecure reports whether the protocol sends data in clear text.
func (s *Service) IsInsecure() bool { return s.Insecure != nil && *s.Insecure }

// Protocol is the top non-abstract ancestor's ID: "ssh" for "openssh".
func (s *Service) Protocol() string { return s.protocol }

// Dictionary is the loaded, validated set of services.
type Dictionary struct {
	services map[string]*Service
	order    []string            // IDs in file order
	byName   map[string][]string // lower-cased id/alias/product -> IDs
	byPort   map[int][]string    // TCP port -> IDs
	byUDP    map[int][]string    // UDP port -> IDs
}

type file struct {
	Version  int        `yaml:"version"`
	Services []*Service `yaml:"services"`
}

var defaultDict *Dictionary

// Default returns the embedded dictionary. It panics if the embedded file is
// invalid, which the package tests rule out.
func Default() *Dictionary {
	if defaultDict == nil {
		d, err := Parse(servicesYAML)
		if err != nil {
			panic("tcpcat dictionary: " + err.Error())
		}
		defaultDict = d
	}
	return defaultDict
}

// Parse loads and validates a dictionary.
func Parse(data []byte) (*Dictionary, error) {
	var f file
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse dictionary: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("dictionary version %d is not supported", f.Version)
	}
	d := &Dictionary{
		services: map[string]*Service{},
		byName:   map[string][]string{},
		byPort:   map[int][]string{},
		byUDP:    map[int][]string{},
	}
	raw := map[string]*Service{}
	for _, s := range f.Services {
		if s.ID == "" {
			return nil, fmt.Errorf("an entry has no id")
		}
		if _, dup := raw[s.ID]; dup {
			return nil, fmt.Errorf("duplicate id %q", s.ID)
		}
		raw[s.ID] = s
		d.order = append(d.order, s.ID)
	}
	for _, id := range d.order {
		s, err := resolve(raw, id, map[string]bool{})
		if err != nil {
			return nil, err
		}
		d.services[id] = s
	}
	for _, id := range d.order {
		s := d.services[id]
		if s.Abstract {
			continue
		}
		if err := validate(s); err != nil {
			return nil, err
		}
		d.index(s)
	}
	return d, nil
}

// resolve merges an entry with its ancestors: every empty field is taken
// from the parent. Ports, aliases, products and banners are not inherited
// (a product does not listen on every port its protocol uses).
func resolve(raw map[string]*Service, id string, seen map[string]bool) (*Service, error) {
	s, ok := raw[id]
	if !ok {
		return nil, fmt.Errorf("unknown parent %q", id)
	}
	if seen[id] {
		return nil, fmt.Errorf("parent loop at %q", id)
	}
	seen[id] = true
	out := *s
	out.protocol = id
	if s.Parent == "" {
		return &out, nil
	}
	p, err := resolve(raw, s.Parent, seen)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	if !p.Abstract {
		out.protocol = p.protocol
	}
	if out.Name == "" {
		out.Name, out.NameFR = p.Name, p.NameFR
	}
	if out.Category == "" {
		out.Category = p.Category
	}
	if out.Exposure == "" {
		out.Exposure = p.Exposure
	}
	if out.Risk == "" {
		out.Risk = p.Risk
	}
	if out.Insecure == nil {
		out.Insecure = p.Insecure
	}
	if out.HTTP == nil {
		out.HTTP = p.HTTP
	}
	if out.What.empty() {
		out.What = p.What
	}
	if out.Why.empty() {
		out.Why = p.Why
	}
	if out.Hint.empty() {
		out.Hint = p.Hint
	}
	return &out, nil
}

func validate(s *Service) error {
	switch {
	case s.Name == "":
		return fmt.Errorf("%s: no name", s.ID)
	case s.Exposure != Public && s.Exposure != Restricted && s.Exposure != Private:
		return fmt.Errorf("%s: exposure %q is not public, restricted or private", s.ID, s.Exposure)
	case SeverityRank(s.Risk) < 0:
		return fmt.Errorf("%s: risk %q is not one of %v", s.ID, s.Risk, Severities)
	case s.What.EN == "" || s.What.FR == "":
		return fmt.Errorf("%s: what must be written in English and French", s.ID)
	case s.Exposure != Public && (s.Why.EN == "" || s.Why.FR == ""):
		return fmt.Errorf("%s: a non-public service must say why, in English and French", s.ID)
	}
	for _, p := range append(append([]int{}, s.Ports...), s.UDP...) {
		if p < 1 || p > 65535 {
			return fmt.Errorf("%s: port %d out of range", s.ID, p)
		}
	}
	return nil
}

func (d *Dictionary) index(s *Service) {
	add := func(m map[string][]string, k, id string) {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			return
		}
		for _, have := range m[k] {
			if have == id {
				return
			}
		}
		m[k] = append(m[k], id)
	}
	add(d.byName, s.ID, s.ID)
	for _, a := range s.Aliases {
		add(d.byName, a, s.ID)
	}
	for _, p := range s.Products {
		add(d.byName, p, s.ID)
	}
	for _, p := range s.Ports {
		d.byPort[p] = append(d.byPort[p], s.ID)
	}
	for _, p := range s.UDP {
		d.byUDP[p] = append(d.byUDP[p], s.ID)
	}
}

// Get returns the entry with this ID, or nil.
func (d *Dictionary) Get(id string) *Service {
	s := d.services[id]
	if s == nil || s.Abstract {
		return nil
	}
	return s
}

// ByName finds the entry for a service or product name as tcpcat's
// detector or a fingerprint database writes it ("openssh", "ms-wbt-server",
// "Microsoft-IIS"). The first ID wins when several entries claim a name.
func (d *Dictionary) ByName(name string) *Service {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, k := range []string{n, strings.TrimPrefix(n, "ssl/")} {
		if ids := d.byName[k]; len(ids) > 0 {
			return d.services[ids[0]]
		}
	}
	return nil
}

// ByPort lists the entries that conventionally use a TCP port.
func (d *Dictionary) ByPort(port int) []*Service {
	return d.collect(d.byPort[port])
}

// ByUDPPort lists the entries that conventionally use a UDP port.
func (d *Dictionary) ByUDPPort(port int) []*Service {
	return d.collect(d.byUDP[port])
}

func (d *Dictionary) collect(ids []string) []*Service {
	out := make([]*Service, 0, len(ids))
	for _, id := range ids {
		out = append(out, d.services[id])
	}
	return out
}

// All returns every non-abstract entry, in file order.
func (d *Dictionary) All() []*Service {
	var out []*Service
	for _, id := range d.order {
		if s := d.services[id]; !s.Abstract {
			out = append(out, s)
		}
	}
	return out
}

// Ports returns every TCP port the dictionary knows, sorted.
func (d *Dictionary) Ports() []int {
	out := make([]int, 0, len(d.byPort))
	for p := range d.byPort {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
