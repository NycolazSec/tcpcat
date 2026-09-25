package service

import "testing"

func TestFindReusedCertificatesGroupsByFingerprint(t *testing.T) {
	ResetCertRegistry()
	t.Cleanup(ResetCertRegistry)

	RecordCertObservation("fp-shared", "10.0.0.1", 443, "jarm-a")
	RecordCertObservation("fp-shared", "10.0.0.2", 443, "jarm-b")
	RecordCertObservation("fp-unique", "10.0.0.3", 443, "jarm-c")

	groups := FindReusedCertificates()
	if len(groups) != 1 {
		t.Fatalf("FindReusedCertificates() = %+v, want exactly 1 reused group", groups)
	}
	if groups[0].Fingerprint != "fp-shared" {
		t.Errorf("Fingerprint = %q, want fp-shared", groups[0].Fingerprint)
	}
	if len(groups[0].Hosts) != 2 {
		t.Errorf("Hosts = %+v, want 2 entries", groups[0].Hosts)
	}
}

func TestFindReusedCertificatesIgnoresSingleHost(t *testing.T) {
	ResetCertRegistry()
	t.Cleanup(ResetCertRegistry)

	RecordCertObservation("fp-only-one-host", "10.0.0.1", 443, "")
	RecordCertObservation("fp-only-one-host", "10.0.0.1", 8443, "")

	if groups := FindReusedCertificates(); len(groups) != 0 {
		t.Errorf("FindReusedCertificates() = %+v, want none (same host, different ports is not reuse across hosts)", groups)
	}
}

func TestRecordCertObservationIgnoresEmptyFingerprint(t *testing.T) {
	ResetCertRegistry()
	t.Cleanup(ResetCertRegistry)

	RecordCertObservation("", "10.0.0.1", 443, "")
	if groups := FindReusedCertificates(); len(groups) != 0 {
		t.Errorf("FindReusedCertificates() = %+v, want none", groups)
	}
}
