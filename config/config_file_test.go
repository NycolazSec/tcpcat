package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.conf")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestParseConfigFile(t *testing.T) {
	path := writeTemp(t, `
# a comment line
sV: true
p: "22,80,443"
rate = 5000          # inline comment
--evasion: light
aws-tags: 'Key=App,Value=Web'
empty:
frag: false
`)

	got, err := parseConfigFile(path)
	if err != nil {
		t.Fatalf("parseConfigFile: %v", err)
	}
	want := []string{
		"--sV=true",
		"--p=22,80,443",
		"--rate=5000",
		"--evasion=light",
		"--aws-tags=Key=App,Value=Web",
		"--frag=false",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseConfigFile =\n  %#v\nwant\n  %#v", got, want)
	}
}

func TestParseConfigFileMissingSeparator(t *testing.T) {
	path := writeTemp(t, "this line has no separator\n")
	if _, err := parseConfigFile(path); err == nil {
		t.Errorf("expected an error for a line with no key: value separator")
	}
}

func TestParseConfigFileMissingFile(t *testing.T) {
	if _, err := parseConfigFile("/no/such/file.conf"); err == nil {
		t.Errorf("expected an error for a missing config file")
	}
}

func TestConfigArgsFromArgs(t *testing.T) {
	path := writeTemp(t, "p: 22\n")

	cases := [][]string{
		{"--config", path, "scanme.nmap.org"},
		{"--config=" + path, "scanme.nmap.org"},
		{"-config", path},
	}
	for _, args := range cases {
		got, err := configArgsFromArgs(args)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if len(got) != 1 || got[0] != "--p=22" {
			t.Errorf("%v: configArgsFromArgs = %#v, want [--p=22]", args, got)
		}
	}

	// No --config present -> no tokens, no error.
	got, err := configArgsFromArgs([]string{"-sT", "-p", "80", "host"})
	if err != nil || got != nil {
		t.Errorf("no --config should yield (nil, nil), got (%#v, %v)", got, err)
	}
}
