package main

import (
	"math/rand"
	"regexp"
	"testing"
)

func TestGeneratorWritesMatchingBanners(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for _, pattern := range []string{
		`^OpenSSH_([\d.]+)(?:p\d+)?(?: (Ubuntu|Debian)-\S+)?$`,
		`(?i)\A(?:\r|\n)*User(?:name)?\s*:\s*$`,
		`^([^ ]+) ESMTP Postfix(?: \((.+)\))?$`,
		`^Microsoft-HTTPAPI/(?:[0-9\.]*)$`,
	} {
		g := newGenerator(pattern)
		if g == nil {
			t.Fatalf("%s: no generator", pattern)
		}
		re := regexp.MustCompile(pattern)
		seen := map[string]bool{}
		for i := 0; i < 20; i++ {
			s := g.sample(r)
			if s == "" {
				continue
			}
			if !re.MatchString(s) {
				t.Errorf("%s: %q does not match", pattern, s)
			}
			seen[s] = true
		}
		if len(seen) == 0 {
			t.Errorf("%s: nothing generated", pattern)
		}
	}
}

func TestGeneratorSkipsPatternsThatFixNothing(t *testing.T) {
	for _, p := range []string{`^(.*)$`, `^(\S+) (\S+)$`, `(?<=x)y`} {
		if newGenerator(p) != nil {
			t.Errorf("%s: a generator for a pattern that says nothing (or that Go cannot parse)", p)
		}
	}
}
