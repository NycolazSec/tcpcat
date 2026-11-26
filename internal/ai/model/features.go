// Package model is the small trained part of tcpcat's AI: a classifier that
// names the service behind a port from the banner tcpcat captured and the
// port number, and says how sure it is.
//
// It is a multinomial logistic regression over hashed features of the
// banner (character n-grams, words, its first characters, its shape) and of
// the port. It trains in about a minute, runs offline in microseconds, fits
// in the binary, and each of its answers can be traced to the features that
// produced it. It was trained on public banners (Rapid7 Recog,
// BSD-2-Clause), on variants generated from Recog's patterns, and on the
// examples of tcpcat's dictionary, each one degraded the way real networks
// and real administrators change a banner (see conditions.go), and it is
// evaluated per condition on fingerprints it never saw.
package model

import (
	"hash/fnv"
	"sort"
	"strconv"
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

// Features returns the hashed features of a banner, each once, sorted:
//
//   - character 3- to 5-grams of the normalized banner, anchored at its start
//     and end, so "^ssh-" and "^220 " stand out;
//   - its words, and pairs of consecutive words;
//   - its first 1 to 10 characters, which carry the protocol's framing
//     ("ssh-0.0-", "+ok ", "* ok [") even when the rest was cut off;
//   - its shape, letters collapsed to "a" ("a-0.0-a_0.0a0 a"), which
//     recognizes a framing around a product the model never saw;
//   - its length, coarsely.
//
// The port is not a feature: the model weighs it separately (see
// Model.PortWeight), so how much a port number counts against the banner is
// fitted rather than an accident of how many features a banner has.
func Features(banner string) []uint32 {
	n := Normalize(banner)
	feats := make([]uint32, 0, 3*len(n)+40)
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
		words := strings.FieldsFunc(n, func(r rune) bool {
			return (r < 'a' || r > 'z') && r != '0'
		})
		prev := "^"
		for _, w := range words {
			if len(w) >= 2 {
				add("w:" + w)
			}
			add("b:" + prev + " " + w)
			prev = w
		}
		for k := 1; k <= 10 && k <= len(n); k++ {
			add("p:" + n[:k])
		}
		shape := shapeOf(n)
		add("s:" + head(shape, 8))
		add("S:" + head(shape, 16))
		add("l:" + strconv.Itoa(min(len(n)/8, 8)))
	}
	sort.Slice(feats, func(i, j int) bool { return feats[i] < feats[j] })
	out := feats[:0]
	for i, f := range feats {
		if i == 0 || f != feats[i-1] {
			out = append(out, f)
		}
	}
	return out
}

// shapeOf collapses every run of letters to "a" and keeps the rest of a
// normalized banner (digit runs are already "0").
func shapeOf(n string) string {
	var b strings.Builder
	letter := false
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c >= 'a' && c <= 'z' {
			if !letter {
				b.WriteByte('a')
			}
			letter = true
			continue
		}
		letter = false
		b.WriteByte(c)
	}
	return b.String()
}

func head(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32() % Buckets
}
