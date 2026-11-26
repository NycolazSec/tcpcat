package main

import (
	"math/rand"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
)

// A generator writes banners that match one of Recog's fingerprint
// patterns: new versions, hostnames and free text around the parts the
// pattern fixes. A fingerprint usually has one or two examples; its pattern
// describes every banner of that software, so the model learns what the
// fingerprint keeps constant instead of one example's version number.
type generator struct {
	re  *syntax.Regexp
	chk *regexp.Regexp
}

// newGenerator returns nil for a pattern Go cannot parse (Ruby-only syntax)
// or one that fixes too little text to say anything (^(.*)$).
func newGenerator(pattern string) *generator {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	chk, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	if literalLen(re) < 4 {
		return nil
	}
	return &generator{re: re.Simplify(), chk: chk}
}

func literalLen(re *syntax.Regexp) int {
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune)
	case syntax.OpConcat, syntax.OpCapture:
		n := 0
		for _, s := range re.Sub {
			n += literalLen(s)
		}
		return n
	case syntax.OpAlternate:
		n := -1
		for _, s := range re.Sub {
			if l := literalLen(s); n < 0 || l < n {
				n = l
			}
		}
		return max(n, 0)
	case syntax.OpPlus, syntax.OpRepeat:
		if re.Op == syntax.OpRepeat && re.Min == 0 {
			return 0
		}
		return literalLen(re.Sub[0])
	}
	return 0
}

// sample returns a banner the pattern matches, or "" after a few failed
// tries.
func (g *generator) sample(r *rand.Rand) string {
	for try := 0; try < 8; try++ {
		var b strings.Builder
		gen(&b, g.re, r, 0)
		s := strings.TrimSpace(b.String())
		if s != "" && len(s) <= 200 && g.chk.MatchString(s) {
			return s
		}
	}
	return ""
}

var fillers = []string{
	"mail.example.com", "srv01", "host-12.example.net", "ready", "(Ubuntu)", "Debian", "x86_64",
	"build 2471", "rev 3", "Linux", "localhost", "gw", "office", "2.4.1", "1.0", "release", "lab",
}

func gen(b *strings.Builder, re *syntax.Regexp, r *rand.Rand, depth int) {
	if depth > 40 {
		return
	}
	switch re.Op {
	case syntax.OpLiteral:
		for _, c := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 && r.Intn(8) == 0 {
				c = unicode.SimpleFold(c)
			}
			b.WriteRune(c)
		}
	case syntax.OpCharClass:
		b.WriteRune(pick(re.Rune, r))
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		const pool = "abcdefghijklmnopqrstuvwxyz0123456789.-_ "
		b.WriteByte(pool[r.Intn(len(pool))])
	case syntax.OpCapture:
		gen(b, re.Sub[0], r, depth+1)
	case syntax.OpConcat:
		for _, s := range re.Sub {
			gen(b, s, r, depth+1)
		}
	case syntax.OpAlternate:
		gen(b, re.Sub[r.Intn(len(re.Sub))], r, depth+1)
	case syntax.OpQuest:
		if r.Intn(2) == 0 {
			gen(b, re.Sub[0], r, depth+1)
		}
	case syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		lo, hi := 0, 3
		switch re.Op {
		case syntax.OpPlus:
			lo = 1
		case syntax.OpRepeat:
			lo, hi = re.Min, re.Max
			if hi < 0 || hi > lo+3 {
				hi = lo + 3
			}
		}
		sub := re.Sub[0]
		if isAny(sub) && lo <= 1 {
			// ".*" and ".+" stand for free text: a word, not random letters.
			if lo == 1 || r.Intn(2) == 0 {
				b.WriteString(fillers[r.Intn(len(fillers))])
			}
			return
		}
		n := lo
		if hi > lo {
			n += r.Intn(hi - lo + 1)
		}
		if n > 12 {
			n = 12
		}
		for i := 0; i < n; i++ {
			gen(b, sub, r, depth+1)
		}
	}
	// Anchors, word boundaries and empty matches write nothing.
}

func isAny(re *syntax.Regexp) bool {
	if re.Op == syntax.OpAnyChar || re.Op == syntax.OpAnyCharNotNL {
		return true
	}
	// A broad negated class such as [^)] or \S behaves the same way.
	if re.Op == syntax.OpCharClass {
		var n int
		for i := 0; i+1 < len(re.Rune); i += 2 {
			n += int(re.Rune[i+1]-re.Rune[i]) + 1
		}
		return n > 200
	}
	return false
}

// pick returns a character from a class, preferring the readable ASCII part
// of a broad class like \S or [^)].
func pick(ranges []rune, r *rand.Rand) rune {
	var readable []rune
	for i := 0; i+1 < len(ranges); i += 2 {
		for c := max(ranges[i], 0x21); c <= ranges[i+1] && c <= 0x7e; c++ {
			readable = append(readable, c)
		}
	}
	if len(readable) == 0 && inClass(ranges, ' ') {
		return ' ' // \s
	}
	if len(readable) > 0 {
		if len(readable) > 60 {
			// \S, [^ ], .: mostly letters and digits, as in real banners.
			const common = "abcdefghijklmnopqrstuvwxyz0123456789"
			for try := 0; try < 4; try++ {
				c := rune(common[r.Intn(len(common))])
				if inClass(ranges, c) {
					return c
				}
			}
		}
		return readable[r.Intn(len(readable))]
	}
	if len(ranges) >= 2 {
		return ranges[0]
	}
	return 'x'
}

func inClass(ranges []rune, c rune) bool {
	for i := 0; i+1 < len(ranges); i += 2 {
		if c >= ranges[i] && c <= ranges[i+1] {
			return true
		}
	}
	return false
}
