package model

import (
	"sort"
	"strings"
	"testing"
)

func TestEmbeddedModelLoads(t *testing.T) {
	m, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if m.Size() == 0 || m.PortWeight <= 0 || m.Temperature <= 0 {
		t.Fatalf("weights %d, port weight %v, temperature %v", m.Size(), m.PortWeight, m.Temperature)
	}
	for _, want := range []string{"openssh", "postfix", "nginx", Other} {
		if !hasClass(m, want) {
			t.Errorf("class %q missing", want)
		}
	}
}

// The cases the model exists for: what the port does not say, the banner
// does, even when the product is unknown or the banner damaged.
func TestEmbeddedModelReadsBanners(t *testing.T) {
	m, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		banner  string
		port    int
		want    string // the answer, or its prefix for a family
		minimum float64
	}{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", 2222, "openssh", 0.9},
		{"SSH-2.0-dropbear_2022.83", 8022, "dropbear", 0.9},
		{"SSH-2.0-SomeCustomGateway", 2200, "ssh", 0.5},
		{"220 mail.example.org ESMTP", 2525, "smtp", 0.5},
		{"220 (vsFTPd 3.0.5)", 2121, "vsftpd", 0.9},
		{"nginx/1.24.0 (Ubuntu)", 8090, "nginx", 0.9},
		{"5.5.5-10.11.6-MariaDB-0+deb12u1", 3307, "mariadb", 0.9},
		{"+OK Dovecot (Debian) ready.", 1110, "pop3", 0.9},
		{"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", 0, "openssh", 0.9}, // no port at all
	} {
		g := m.Classify(tc.banner, tc.port)
		if g[0].ID != tc.want || g[0].P < tc.minimum {
			t.Errorf("%q on %d: got %s %.2f, want %s >= %.2f", tc.banner, tc.port, g[0].ID, g[0].P, tc.want, tc.minimum)
		}
		var sum float64
		for _, x := range g {
			sum += x.P
		}
		if sum < 0.999 || sum > 1.001 {
			t.Errorf("%q: probabilities sum to %v", tc.banner, sum)
		}
	}
}

func TestTrainEncodeDecode(t *testing.T) {
	var ex []Example
	for i := 0; i < 30; i++ {
		ex = append(ex,
			Example{Label: "ssh", Banner: "SSH-2.0-OpenSSH_9." + string(rune('0'+i%10)), Port: 22},
			Example{Label: "ftp", Banner: "220 FTP server ready " + string(rune('a'+i%26)), Port: 21},
		)
	}
	m := Train(ex, TrainOptions{Epochs: 5, Rate: 0.5, L1: 0.01, L2: 1, Dropout: 0.3, Seed: 1})
	m.Calibrate(ex)
	data, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if g := d.Classify("SSH-2.0-libssh", 2222); g[0].ID != "ssh" {
		t.Fatalf("decoded model: %+v", g)
	}
	if g := d.Classify("220 welcome", 0); g[0].ID != "ftp" {
		t.Fatalf("decoded model: %+v", g)
	}
}

func TestDecodeRejectsInconsistentWeights(t *testing.T) {
	m, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	for name, spoil := range map[string]func(*Model){
		"class out of range": func(m *Model) { m.Class[0] = 255 },
		"short start":        func(m *Model) { m.Start = m.Start[:len(m.Start)-1] },
		"unsorted features":  func(m *Model) { m.Feats[0], m.Feats[1] = m.Feats[1], m.Feats[0] },
		"missing port table": func(m *Model) { m.PortKeys = m.PortKeys[1:] },
	} {
		c := *m
		c.Class = append([]uint8(nil), m.Class...)
		c.Feats = append([]uint32(nil), m.Feats...)
		spoil(&c)
		data, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFeaturesAreSortedAndUnique(t *testing.T) {
	f := Features("220 220 220 FTP FTP ready ready")
	if !sort.SliceIsSorted(f, func(i, j int) bool { return f[i] < f[j] }) {
		t.Fatal("not sorted")
	}
	for i := 1; i < len(f); i++ {
		if f[i] == f[i-1] {
			t.Fatal("repeated feature")
		}
	}
	if shapeOf(Normalize("SSH-2.0-OpenSSH_9.6p1 Ubuntu")) != "a-0.0-a_0.0a0 a" {
		t.Fatalf("shape: %q", shapeOf(Normalize("SSH-2.0-OpenSSH_9.6p1 Ubuntu")))
	}
}

func hasClass(m *Model, id string) bool {
	for _, c := range m.Classes {
		if strings.EqualFold(c, id) {
			return true
		}
	}
	return false
}
