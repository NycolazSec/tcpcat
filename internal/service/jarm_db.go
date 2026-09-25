package service

// knownJARMHashes maps a JARM fingerprint to what's known to produce it,
// letting a scan flag a match instead of leaving the operator to go look
// the hash up by hand.
//
// This is necessarily a starter list, not a maintained threat-intel feed
// (there's no free, actively-updated public JARM database this could pull
// from live, unlike the OSV-backed vulnerability lookup elsewhere in this
// package) -- entries here are cross-referenced against the reference
// JARM implementation's own published examples
// (https://github.com/salesforce/jarm, BSD-3-Clause; the "JARM Hash
// Examples" section of its README), plus one entry
// (goNetHTTPDefaultTLSServer) captured directly from this exact Go
// toolchain's own net/http default TLS server during development, since
// that's a real, common backend a scan legitimately runs into (Prometheus
// exporters, countless internal Go services) and could be verified
// first-hand rather than copied from a third party.
//
// A JARM hash is a fingerprint of the TLS *stack and its configuration*,
// not a fixed constant -- a software upgrade, a cipher-suite config
// change, or a different Go/OpenSSL version can all change it, so a miss
// here proves nothing and a hit is a strong lead, not a certainty. Extend
// this table as more verified hashes turn up; resist adding one that's
// only "probably" right, since a wrong label in a security tool is worse
// than no label.
var knownJARMHashes = map[string]string{
	"2ad2ad0002ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5": "Salesforce (salesforce.com, force.com)",
	"27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d": "Google (google.com, youtube.com, gmail.com)",
	"27d27d27d29d27d1dc41d43d00041d741011a7be03d7498e0df05581db08a9": "Meta (facebook.com, instagram.com)",
	"29d29d20d29d29d21c41d43d00041d741011a7be03d7498e0df05581db08a9": "Meta (oculus.com)",
	"22b22b09b22b22b22b22b22b22b22b352842cd5d6b0278445702035e06875c": "Trickbot malware C2",
	"1dd40d40d00040d1dc1dd40d1dd40d3df2d6a0c2caaa0dc59908f0d3602943": "AsyncRAT malware C2",
	"07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d": "Metasploit (default handler)",
	"07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": "Cobalt Strike (default profile)",
	"29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38": "Merlin C2",
	"3fd3fd0003fd3fd00043d43d00043d3bef2bf79cd6719851e8198c1e8f9a14": "Go net/http default TLS server (crypto/tls defaults, undifferentiated -- consistent with, but not proof of, a Go-based backend)",
}

// lookupJARM returns what's known about a JARM hash, or "" for no match.
func lookupJARM(hash string) string {
	return knownJARMHashes[hash]
}
