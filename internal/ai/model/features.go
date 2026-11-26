// Package model is the small trained part of tcpcat's AI: a classifier that
// names the service behind a port from the banner tcpcat captured and the
// port number, and says how sure it is.
//
// It is a multinomial naive Bayes model over hashed character n-grams and
// words. That is deliberately modest: it trains in seconds, runs offline in
// microseconds, fits in the binary, and its mistakes can be understood. It
// was trained on public banners (Rapid7 Recog, BSD-2-Clause) and on the
// examples of tcpcat's dictionary, each one degraded the way real networks
// degrade a banner (see conditions.go), and it is evaluated per condition.
package model

import (
	"hash/fnv"
	"strings"
)

// Buckets is the size of the hashed feature space.
const Buckets = 1 << 18

// Normalize maps a banner to the form features are taken from: lower case,
// digit runs collapsed to "0" (versions vary, their shape does not), any
// whitespace run collapsed to one space. tcpcat's own sanitizer has already
// removed control characters from a stored banner; Normalize removes them
// too, so raw training text and stored banners look alike.
func Normalize(banner string) string {
	var b strings.Builder
	b.Grow(len(banner))
	space, digit := false, false
	for i := 0; i < len(banner); i++ {
		c := banner[i]
		switch {
		case c >= '0' && c <= '9':
			if !digit {
				b.WriteByte('0')
			}
			digit, space = true, false
			continue
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			if !space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space, digit = true, false
			continue
		case c < 0x20 || c > 0x7e:
			continue // control bytes and non-ASCII carry no signal here
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		}
		b.WriteByte(c)
		space, digit = false, false
	}
	return strings.TrimSpace(b.String())
}

// Features returns the hashed features of a banner: character 3- to 5-grams
// of the normalized banner (anchored at its start and end, so "^ssh-" and
// "^220 " stand out) and its words. The port is not a feature: the model
// weighs it separately (see Model.PortWeight), so how much a port number
// counts against the banner is learned rather than an accident of how many
// n-grams the banner happens to have.
func Features(banner string) []uint32 {
	n := Normalize(banner)
	feats := make([]uint32, 0, 3*len(n)+16)
	add := func(s string) { feats = append(feats, hash(s)) }

	if n == "" {
		add("empty")
	} else {
		t := "^" + n + "$"
		for size := 3; size <= 5; size++ {
			for i := 0; i+size <= len(t); i++ {
				add("c" + t[i:i+size])
			}
		}
		for _, w := range strings.FieldsFunc(n, func(r rune) bool {
			return (r < 'a' || r > 'z') && r != '0'
		}) {
			if len(w) >= 2 {
				add("w:" + w)
			}
		}
	}
	return feats
}

func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32() % Buckets
}
