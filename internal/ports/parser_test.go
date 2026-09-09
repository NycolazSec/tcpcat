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
