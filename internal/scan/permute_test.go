package scan

import "testing"

func TestJobPermutationVisitsEveryIndexExactlyOnce(t *testing.T) {
	const n = 1000

	for trial := 0; trial < 5; trial++ {
		perm := newJobPermutation(n)
		seen := make(map[uint64]bool, n)
		count := 0
		for {
			idx, ok := perm.next()
			if !ok {
				break
			}
			if idx >= n {
				t.Fatalf("trial %d: index %d out of range [0, %d)", trial, idx, n)
			}
			if seen[idx] {
				t.Fatalf("trial %d: index %d produced twice", trial, idx)
			}
			seen[idx] = true
			count++
		}
		if count != n {
			t.Fatalf("trial %d: produced %d indices, want %d", trial, count, n)
		}
	}
}

func TestJobPermutationEmpty(t *testing.T) {
	perm := newJobPermutation(0)
	if _, ok := perm.next(); ok {
		t.Error("newJobPermutation(0).next() should immediately report done")
	}
}

func TestJobPermutationSingleton(t *testing.T) {
	perm := newJobPermutation(1)
	idx, ok := perm.next()
	if !ok || idx != 0 {
		t.Fatalf("newJobPermutation(1).next() = (%d, %v), want (0, true)", idx, ok)
	}
	if _, ok := perm.next(); ok {
		t.Error("expected exactly one index from newJobPermutation(1)")
	}
}

func TestJobPermutationNonPowerOfTwo(t *testing.T) {
	// n deliberately isn't a power of two, exercising the cycle-walking
	// skip logic (the LCG's modulus is the next power of two above n).
	const n = 777
	perm := newJobPermutation(n)
	seen := make(map[uint64]bool, n)
	for {
		idx, ok := perm.next()
		if !ok {
			break
		}
		seen[idx] = true
	}
	if len(seen) != n {
		t.Fatalf("got %d unique indices, want %d", len(seen), n)
	}
}
