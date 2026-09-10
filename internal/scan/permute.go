package scan

import (
	"math/rand"
	"time"
)

// jobPermutation visits every integer in [0, n) exactly once, in a random
// but non-repeating order, using an O(1)-memory full-period linear
// congruential generator over the next power of two >= n (the same
// technique internal/target/generator.go's RandomCIDRGenerator uses for a
// single CIDR block, generalized to an arbitrary count) with "cycle
// walking": indices the LCG produces outside [0, n) are simply skipped
// and never emitted, rather than shrinking the modulus.
//
// This is what zmap's design is built around: dispatching (target, port)
// pairs in scan order means a probe every few milliseconds all lands on
// the same handful of hosts near the start of a big scan, and a scan
// interrupted partway through has only ever sampled that narrow slice.
// Permuting the flattened target*port space first means every point in
// time during the scan has touched a representative, unbiased sample of
// the whole target list. Final results are unaffected: engine.go sorts
// them by IP then port before returning, regardless of dispatch order.
type jobPermutation struct {
	n        uint64
	m        uint64 // next power of two >= n (1 when n == 0)
	a, c     uint64
	currentX uint64
	steps    uint64 // total LCG steps taken so far, bounded by the full cycle m
	emitted  uint64 // valid (< n) indices emitted so far, bounded by n
}

func newJobPermutation(n uint64) *jobPermutation {
	if n == 0 {
		return &jobPermutation{n: 0, m: 1}
	}

	m := uint64(1)
	for m < n {
		m <<= 1
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano())) // #nosec G404 -- scan dispatch order, not a security token
	c := uint64(r.Int63()) | 1

	var a uint64
	if m < 4 {
		a = 1
	} else {
		k := uint64(r.Int63n(int64(m / 4)))
		a = 4*k + 1
	}

	return &jobPermutation{
		n:        n,
		m:        m,
		a:        a,
		c:        c,
		currentX: uint64(r.Int63n(int64(m))),
	}
}

// next returns the next index in permuted order and true, or (0, false)
// once every index in [0, n) has been produced exactly once.
func (p *jobPermutation) next() (uint64, bool) {
	if p.emitted >= p.n {
		return 0, false
	}
	// The LCG has full period m, so at most m steps are ever needed to
	// walk the whole cycle; n of those m positions are < n and get
	// emitted, the rest are skipped. Bounding by m (not n) is what the
	// original version got wrong: it capped the number of *steps* at n,
	// but some steps land outside [0, n) and don't emit anything, so
	// stopping at n steps could miss valid indices still later in the
	// cycle.
	for p.steps < p.m {
		x := p.currentX
		p.currentX = (p.a*p.currentX + p.c) % p.m
		p.steps++
		if x < p.n {
			p.emitted++
			return x, true
		}
	}
	return 0, false
}
