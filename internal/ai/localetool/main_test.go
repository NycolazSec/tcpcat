package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NycolazSec/tcpcat/internal/ai"
)

// root is the repository root, from this package's directory.
const root = "../../.."

// The template must list every text tcpcat's AI and command line can say:
// regenerate it when one changes.
func TestTemplateIsUpToDate(t *testing.T) {
	want, err := template(root, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, localesDir, ai.TemplateFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s is out of date: run go run ./internal/ai/localetool template > %s/%s from the repository root",
			ai.TemplateFile, localesDir, ai.TemplateFile)
	}
	if _, err := ai.ParseLocale(os.DirFS(filepath.Join(root, localesDir)), ai.TemplateFile); err != nil {
		t.Fatalf("the template is not valid YAML: %v", err)
	}
}

// Every translation file must be valid, name its language, translate only
// texts that exist, and keep the English placeholders.
func TestLocalesAreValid(t *testing.T) {
	problems, err := checkAll(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

func TestPhrasesAreFound(t *testing.T) {
	ps, err := phrases(root)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]string{}
	for _, p := range ps {
		have[p.EN] = p.FR
	}
	for en, fr := range map[string]string{
		"meant to be public":     "fait pour être public", // msg(lang, en, fr)
		"How the scan went":      "Comment le scan s'est déroulé",
		"Dictionary":             "Dictionnaire",       // label("...", "...")
		"seen from the internet": "vu depuis Internet", // map[string][2]string
		"Thinking":               "Réflexion",          // [][2]string (spinner)
		"product name replaced":  "",                   // model.Conditions labels
		"%d classes, %s weights, port weight %s, temperature %s": "", // a format string
	} {
		got, ok := have[en]
		if !ok {
			t.Errorf("phrase %q not found", en)
			continue
		}
		if fr != "" && got != fr {
			t.Errorf("phrase %q: French %q, want %q", en, got, fr)
		}
	}
}

func TestSameVerbs(t *testing.T) {
	for _, c := range []struct {
		en, tr string
		ok     bool
	}{
		{"%d to fix, %d to review", "%d por corregir, %d por revisar", true},
		{"port %d open (%s)", "(%[2]s) Port %[1]d offen", true},
		{"port %d open (%s)", "Port %d offen", false},
		{"port %d open (%s)", "Port %s offen (%d)", false},
		{"in %.0f ms", "en %.0f ms", true},
		{"%d%%", "%d %%", true},
		{"%d open", "100 % %d abiertos", false},
		{"Verifying", "Verificando", true},
	} {
		err := sameVerbs(c.en, c.tr)
		if (err == nil) != c.ok {
			t.Errorf("sameVerbs(%q, %q) = %v, want ok=%v", c.en, c.tr, err, c.ok)
		}
	}
}

func TestQuoteIsYAML(t *testing.T) {
	for _, s := range []string{`say "hi"`, `back\slash`, "two\nlines", "tab\there", "été %d %%"} {
		q := quote(s)
		var l ai.Locale
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "x.yaml"), []byte("name: "+q+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := ai.ParseLocale(os.DirFS(dir), "x.yaml")
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		l = *got
		if l.Name != s {
			t.Errorf("quote(%q) = %s, reads back %q", s, q, l.Name)
		}
	}
	if !strings.HasPrefix(quote("x"), `"`) {
		t.Fatal("not double-quoted")
	}
}
