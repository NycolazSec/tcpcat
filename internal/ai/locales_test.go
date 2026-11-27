package ai

import (
	"testing"
	"testing/fstest"
)

// withLocale installs a translation for the duration of a test.
func withLocale(t *testing.T, code string, l *Locale) {
	t.Helper()
	old, had := locales[code]
	locales[code] = l
	t.Cleanup(func() {
		if had {
			locales[code] = old
		} else {
			delete(locales, code)
		}
	})
}

func TestLang(t *testing.T) {
	withLocale(t, "zz", &Locale{Name: "Zed"})
	withLocale(t, "qq-BR", &Locale{Name: "Queue"})
	for in, want := range map[string]string{
		"":            "en",
		"C.UTF-8":     "en",
		"en_US.UTF-8": "en",
		"fr":          "fr",
		"fr_CA.UTF-8": "fr",
		"FR":          "fr",
		"zz":          "zz",
		"zz_ZZ.UTF-8": "zz",
		"zz-YY":       "zz",
		"qq":          "qq-BR",
		"qq_br":       "qq-BR",
		"de_DE@euro":  "en", // no German yet
	} {
		if got := Lang(in); got != want {
			t.Errorf("Lang(%q) = %q, want %q", in, got, want)
		}
	}
}

// A locale's text replaces the English one; what it leaves out stays English.
func TestLocaleFallsBackToEnglish(t *testing.T) {
	withLocale(t, "zz", &Locale{
		Name:     "Zed",
		Messages: map[string]string{"summary": "%d zfix, %d zreview, %d zok."},
		Phrases:  map[string]string{"meant to be public": "zpublic"},
	})
	if got := tr("zz", "summary", 1, 2, 3); got != "1 zfix, 2 zreview, 3 zok." {
		t.Errorf("translated message: %q", got)
	}
	if got, want := tr("zz", "title-unknown", 81), tr("en", "title-unknown", 81); got != want {
		t.Errorf("missing message: %q, want the English %q", got, want)
	}
	if got := Phrase("zz", "meant to be public"); got != "zpublic" {
		t.Errorf("phrase: %q", got)
	}
	if got := Phrase("zz", "Dictionary"); got != "" {
		t.Errorf("missing phrase: %q, want empty (English is the caller's)", got)
	}
	if got := Phrase("en", "meant to be public"); got != "" {
		t.Errorf("English has no phrases: %q", got)
	}
}

func TestNumberConventions(t *testing.T) {
	withLocale(t, "zz", &Locale{Name: "Zed", Decimal: ",", Thousands: ".", Percent: "%s %%"})
	withLocale(t, "yy", &Locale{Name: "Why", Thousands: "none"})
	for _, c := range []struct{ lang, dec, thou, pct string }{
		{"en", ".", ",", "%s%%"},
		{"fr", ",", " ", "%s %%"},
		{"zz", ",", ".", "%s %%"},
		{"yy", ".", "", "%s%%"},
	} {
		if DecimalMark(c.lang) != c.dec || ThousandsSeparator(c.lang) != c.thou || PercentFormat(c.lang) != c.pct {
			t.Errorf("%s: %q %q %q", c.lang, DecimalMark(c.lang), ThousandsSeparator(c.lang), PercentFormat(c.lang))
		}
	}
	if got := score("zz", 7.8); got != "7,8" {
		t.Errorf("score: %q", got)
	}
}

func TestLoadLocalesSkipsTemplateAndBrokenFiles(t *testing.T) {
	got := loadLocales(fstest.MapFS{
		"locales/TEMPLATE.yaml": {Data: []byte("name: \"\"\n")},
		"locales/zz.yaml":       {Data: []byte("name: Zed\nmessages:\n  summary: \"z\"\n")},
		"locales/yy.yaml":       {Data: []byte("name: [broken\n")},
	})
	if len(got) != 1 || got["zz"] == nil || got["zz"].Messages["summary"] != "z" {
		t.Fatalf("loaded %v", got)
	}
}

func TestLanguages(t *testing.T) {
	withLocale(t, "zz", &Locale{Name: "Zed"})
	l := Languages()
	if len(l) < 3 || l[0] != "en" || l[1] != "fr" {
		t.Fatalf("Languages() = %v", l)
	}
	found := false
	for _, c := range l {
		found = found || c == "zz"
	}
	if !found {
		t.Fatalf("Languages() = %v, missing zz", l)
	}
}
