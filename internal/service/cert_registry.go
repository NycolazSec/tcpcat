package service

import "sync"

// CertObservation is one (host, JARM) pairing recorded against a
// certificate fingerprint by RecordCertObservation.
type CertObservation struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	JARM string `json:"jarm,omitempty"`
}

var (
	certRegistryMu sync.Mutex
	certRegistry   = map[string][]CertObservation{}
)

// RecordCertObservation registers that the certificate identified by
// fingerprint (TLSInfo.CertFingerprint) was served by host:port, with its
// JARM hash if one was computed, for later cross-host reuse detection
// (see FindReusedCertificates). A no-op for an empty fingerprint (TLS
// wasn't probed, or presented no certificate).
func RecordCertObservation(fingerprint, host string, port int, jarm string) {
	if fingerprint == "" {
		return
	}
	certRegistryMu.Lock()
	defer certRegistryMu.Unlock()
	certRegistry[fingerprint] = append(certRegistry[fingerprint], CertObservation{Host: host, Port: port, JARM: jarm})
}

// CertReuseGroup is one certificate fingerprint served by more than one
// distinct host -- ordinarily a shared load balancer/CDN certificate, but
// also how an unintended shared private key across otherwise-unrelated
// hosts would show up.
type CertReuseGroup struct {
	Fingerprint string            `json:"fingerprint"`
	Hosts       []CertObservation `json:"hosts"`
}

// FindReusedCertificates returns every recorded fingerprint seen on more
// than one distinct host. Meant to be called once, after a scan's service
// detection phase has recorded every TLS observation.
func FindReusedCertificates() []CertReuseGroup {
	certRegistryMu.Lock()
	defer certRegistryMu.Unlock()

	var groups []CertReuseGroup
	for fingerprint, observations := range certRegistry {
		hosts := make(map[string]bool, len(observations))
		for _, o := range observations {
			hosts[o.Host] = true
		}
		if len(hosts) > 1 {
			groups = append(groups, CertReuseGroup{Fingerprint: fingerprint, Hosts: observations})
		}
	}
	return groups
}

// ResetCertRegistry clears every recorded observation. Exported for tests;
// production code records once per process run and never needs to reset.
func ResetCertRegistry() {
	certRegistryMu.Lock()
	defer certRegistryMu.Unlock()
	certRegistry = map[string][]CertObservation{}
}
