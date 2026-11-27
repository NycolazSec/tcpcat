package ai

import (
	"embed"
	"io/fs"
	"path"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// tcpcat's AI speaks English and French natively. Every other language is a
// file in locales/, named after the language (es.yaml, pt-BR.yaml), that
// anyone can write without Go: see locales/README.md. A text a locale leaves
// out is written in English.

//go:embed locales/*.yaml
var localeFiles embed.FS

// Locale is one translation of tcpcat's AI.
type Locale struct {
	// Name is the language's name, written in that language.
	Name string `yaml:"name"`
	// Decimal is the decimal mark ("." when empty).
	Decimal string `yaml:"decimal"`
	// Thousands separates groups of three digits ("," when empty; "none"
	// for no separator).
	Thousands string `yaml:"thousands"`
	// Percent writes a percentage; %s is the number ("%s%%" when empty).
	Percent string `yaml:"percent"`
	// Messages translates what the AI says, by message ID.
	Messages map[string]string `yaml:"messages"`
	// Phrases translates the command line's own words, by their English text.
	Phrases map[string]string `yaml:"phrases"`
}

// TemplateFile is the file translators start from; it is not a language.
const TemplateFile = "TEMPLATE.yaml"

var locales = loadLocales(localeFiles)

func loadLocales(fsys fs.FS) map[string]*Locale {
	out := map[string]*Locale{}
	entries, err := fs.ReadDir(fsys, "locales")
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".yaml") || name == TemplateFile {
			continue
		}
		l, err := ParseLocale(fsys, path.Join("locales", name))
		if err != nil {
			continue // CI checks every locale file; a broken one is skipped, not fatal
		}
		out[strings.TrimSuffix(name, ".yaml")] = l
	}
	return out
}

// ParseLocale reads one locale file.
func ParseLocale(fsys fs.FS, name string) (*Locale, error) {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	var l Locale
	if err := yaml.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// Languages lists the languages tcpcat's AI speaks: en, fr, then the locales.
func Languages() []string {
	var more []string
	for c := range locales {
		more = append(more, c)
	}
	sort.Strings(more)
	return append([]string{"en", "fr"}, more...)
}

// Lang returns the language tcpcat's AI speaks for code, which may be a
// language tag (es, pt-BR) or a system locale (es_ES.UTF-8): the language
// itself, the same language without its region, or English.
func Lang(code string) string {
	c := strings.SplitN(strings.SplitN(code, ".", 2)[0], "@", 2)[0]
	c = strings.ToLower(strings.ReplaceAll(c, "_", "-"))
	base := strings.SplitN(c, "-", 2)[0]
	if base == "fr" {
		return "fr"
	}
	var sameBase []string
	for k := range locales {
		lk := strings.ToLower(k)
		if lk == c {
			return k
		}
		if strings.SplitN(lk, "-", 2)[0] == base {
			sameBase = append(sameBase, k)
		}
	}
	if len(sameBase) > 0 {
		sort.Strings(sameBase)
		return sameBase[0]
	}
	return "en"
}

// Phrase returns lang's translation of an English phrase of the command
// line, or "" when it has none.
func Phrase(lang, en string) string {
	if l := locales[lang]; l != nil {
		return l.Phrases[en]
	}
	return ""
}

// DecimalMark returns the decimal mark of lang.
func DecimalMark(lang string) string {
	if lang == "fr" {
		return ","
	}
	if l := locales[lang]; l != nil && l.Decimal != "" {
		return l.Decimal
	}
	return "."
}

// ThousandsSeparator returns what separates groups of three digits in lang.
func ThousandsSeparator(lang string) string {
	if lang == "fr" {
		return " "
	}
	if l := locales[lang]; l != nil && l.Thousands != "" {
		if l.Thousands == "none" {
			return ""
		}
		return l.Thousands
	}
	return ","
}

// PercentFormat returns how lang writes a percentage; %s is the number.
func PercentFormat(lang string) string {
	if lang == "fr" {
		return "%s %%"
	}
	if l := locales[lang]; l != nil && l.Percent != "" {
		return l.Percent
	}
	return "%s%%"
}

// Message is one sentence of the AI, with its English and French texts.
type Message struct {
	ID, EN, FR string
}

// Catalog lists every sentence of the AI, sorted by ID: what a locale's
// messages translate.
func Catalog() []Message {
	out := make([]Message, 0, len(messages))
	for id, m := range messages {
		out = append(out, Message{ID: id, EN: m[0], FR: m[1]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
