package ports

import "testing"

func TestParsePortsSortsAndDeduplicates(t *testing.T) {
	got, err := ParsePorts("443,80,80,1-3", 0)
	if err != nil {
		t.Fatalf("ParsePorts returned error: %v", err)
	}

	want := []int{1, 2, 3, 80, 443}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
			break
		}
	}
}

func TestParsePortsRejectsInvalidRanges(t *testing.T) {
	for _, input := range []string{"0", "65536", "10-1", "1-65536", "80-90-100"} {
		t.Run(input, func(t *testing.T) {
			if _, err := ParsePorts(input, 0); err == nil {
				t.Fatalf("ParsePorts(%q) unexpectedly succeeded", input)
			}
		})
	}
}

func BenchmarkParsePortsLargeRange(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := ParsePorts("1-65535", 0); err != nil {
			b.Fatal(err)
		}
	}
}

func TestOpenEndedRanges(t *testing.T) {
	for spec, want := range map[string][2]int{"-": {1, 65535}, "60000-": {60000, 65535}, "-1024": {1, 1024}} {
		got, err := ParsePorts(spec, 0)
		if err != nil {
			t.Fatalf("%q: %v", spec, err)
		}
		if got[0] != want[0] || got[len(got)-1] != want[1] || len(got) != want[1]-want[0]+1 {
			t.Errorf("%q: %d..%d (%d ports)", spec, got[0], got[len(got)-1], len(got))
		}
	}
}

func TestTopPortsIsARealThousand(t *testing.T) {
	if n := len(TopPortsList); n < 1000 {
		t.Fatalf("TopPortsList has %d ports", n)
	}
	got := GetTopPorts(1000)
	seen := map[int]bool{}
	for _, p := range got {
		if seen[p] || p < 1 || p > 65535 {
			t.Fatalf("duplicate or invalid port %d", p)
		}
		seen[p] = true
	}
	if len(got) != 1000 {
		t.Fatalf("--top-ports 1000 gave %d ports", len(got))
	}
	for _, p := range []int{22, 80, 443, 3306, 6379, 6443, 10250, 25565} {
		if !seen[p] {
			t.Errorf("port %d missing from the top 1000", p)
		}
	}
}
