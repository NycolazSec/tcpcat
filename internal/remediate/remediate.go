// Package remediate turns an exposure that tcpcat explain classified as
// EXPOSED or FORWARDED, and that no policy authorized, into the exact
// defensive configuration that closes it: a host firewall rule (nftables),
// a systemd drop-in that confines the service to loopback, and a Kubernetes
// NetworkPolicy. It answers the "so how do I fix it?" that a finding leaves
// open.
//
// Everything produced here is inert text for an operator to read and apply.
// tcpcat does not run it, does not touch the firewall, and does not reach
// the network: this package only formats what explain already found. The
// generated allow-lists are deliberately conservative placeholders the
// operator edits, never a guess at which sources "should" have access.
package remediate

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/NycolazSec/tcpcat/internal/explain"
)

const Format = "tcpcat-remediation/v1"

// Bundle is the set of defensive configurations that close one exposure.
// A field is empty when the owner data needed to write it is absent (no
// systemd unit, no pod), so a bundle carries only what applies to the host.
type Bundle struct {
	Format      string    `json:"format"`
	Address     string    `json:"address"`
	Port        int       `json:"port"`
	Class       string    `json:"class"`
	Summary     string    `json:"summary"`
	Nftables    string    `json:"nftables,omitempty"`
	Systemd     string    `json:"systemd_drop_in,omitempty"`
	KubePolicy  string    `json:"kubernetes_network_policy,omitempty"`
	Rebind      string    `json:"rebind_hint,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
	// Attestation is the hex Ed25519 signature over this bundle's stable
	// fields, so a reviewer can tell a bundle tcpcat produced from one edited
	// by hand before it reached a change-management system.
	Attestation string `json:"attestation_ed25519,omitempty"`
}

// actionable reports whether an entry is an unauthorized exposure, i.e. one
// a remediation should be written for. An expected (policy-allowed) port, a
// loopback-only LOCAL port, a SHIELDED/REFUSED/UNTESTED one: nothing to fix.
func actionable(e explain.Entry) bool {
	return (e.Class == explain.Exposed || e.Class == explain.Forwarded) && !e.Expected
}

// FromReport returns one bundle per unauthorized exposure in the report, in
// the report's order. key may be nil to leave bundles unsigned.
func FromReport(r explain.Report, key ed25519.PrivateKey, now time.Time) []Bundle {
	var out []Bundle
	for _, e := range r.Entries {
		if b, ok := For(r.Target, e, key, now); ok {
			out = append(out, b)
		}
	}
	return out
}

// For builds the bundle that closes one exposure on address target. ok is
// false when the entry needs no remediation (see actionable).
func For(target string, e explain.Entry, key ed25519.PrivateKey, now time.Time) (Bundle, bool) {
	if !actionable(e) {
		return Bundle{}, false
	}
	b := Bundle{
		Format:      Format,
		Address:     target,
		Port:        e.Port,
		Class:       e.Class,
		Summary:     summarize(target, e),
		Nftables:    nftablesRule(target, e),
		GeneratedAt: now.UTC(),
	}
	if e.Owner != nil {
		if e.Owner.Unit != "" {
			b.Systemd = systemdDropIn(e.Owner.Unit, e.Port)
		}
		if e.Owner.Pod != "" {
			b.KubePolicy = kubeNetworkPolicy(e.Owner.Pod, e.Port)
		}
	}
	// A host-only service bound to a wildcard address is best fixed at the
	// source, not just firewalled; carry explain's own rebind advice.
	if e.Fix != "" {
		b.Rebind = e.Fix
	}
	if len(key) == ed25519.PrivateKeySize {
		b.Attestation = hex.EncodeToString(ed25519.Sign(key, b.signingPayload()))
	}
	return b, true
}

func summarize(target string, e explain.Entry) string {
	who := "a service"
	if e.Owner != nil && e.Owner.Process != "" {
		who = e.Owner.Process
		if e.Owner.PID != 0 {
			who = fmt.Sprintf("%s (pid %d)", e.Owner.Process, e.Owner.PID)
		}
	}
	svc := ""
	if e.Service != "" {
		svc = " [" + e.Service + "]"
	}
	if e.Class == explain.Forwarded {
		return fmt.Sprintf("port %d/tcp on %s is forwarded to %s%s but no policy allows it", e.Port, target, who, svc)
	}
	return fmt.Sprintf("port %d/tcp on %s is exposed by %s%s but no policy allows it", e.Port, target, who, svc)
}

// nftablesRule drops new connections to the port from everything but
// loopback, and carries a commented template the operator edits to allow the
// source networks that legitimately need it. The drop line is safe to apply
// as-is; the accept line must be reviewed first (hence it is a comment).
func nftablesRule(target string, e explain.Entry) string {
	family := "ip"
	if ip := net.ParseIP(target); ip != nil && ip.To4() == nil {
		family = "ip6"
	}
	who := "exposed service"
	if e.Owner != nil && e.Owner.Process != "" {
		who = e.Owner.Process
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Close %s on port %d. Review the allow line, then apply both in order.\n", who, e.Port)
	fmt.Fprintf(&sb, "# nft add rule inet filter input %s saddr { 10.0.0.0/8 } tcp dport %d accept comment \"tcpcat: allow %s from trusted nets\"\n", family, e.Port, who)
	fmt.Fprintf(&sb, "nft add rule inet filter input iifname != \"lo\" tcp dport %d ct state new counter drop comment \"tcpcat: close %d\"", e.Port, e.Port)
	return sb.String()
}

// systemdDropIn confines a unit's outward reachability with the kernel's own
// per-cgroup IP filter (IPAddressDeny/Allow), which needs no firewall and
// survives the service being restarted on another host.
func systemdDropIn(unit string, port int) string {
	return fmt.Sprintf(`# /etc/systemd/system/%s.d/10-tcpcat-hardening.conf
# Add the trusted source networks to IPAddressAllow, then:
#   systemctl daemon-reload && systemctl restart %s
[Service]
IPAccounting=yes
IPAddressDeny=any
IPAddressAllow=localhost
`, unit, unit)
}

// kubeNetworkPolicy scaffolds a default-deny-ingress policy for the pod's
// namespace. The podSelector is left for the operator: a NetworkPolicy
// selects by label, and an inventory holds the pod's name, not its labels,
// so guessing a selector could silently match the wrong pods.
func kubeNetworkPolicy(pod string, port int) string {
	namespace, name, ok := strings.Cut(pod, "/")
	if !ok {
		namespace, name = "default", pod
	}
	return fmt.Sprintf(`# Fill podSelector.matchLabels with the labels of %s, then kubectl apply.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tcpcat-restrict-%d
  namespace: %s
spec:
  podSelector:
    matchLabels: {} # TODO: the labels of pod %s
  policyTypes:
  - Ingress
  ingress: [] # deny all ingress until an explicit rule is added
`, name, port, namespace, name)
}

// signingPayload is the stable serialization the attestation signs: the
// fields a reviewer relies on, in a fixed order, with the timestamp to
// nanoseconds. The signature field itself is excluded.
func (b Bundle) signingPayload() []byte {
	return []byte(strings.Join([]string{
		b.Format, b.Address, fmt.Sprint(b.Port), b.Class,
		b.Summary, b.Nftables, b.Systemd, b.KubePolicy,
		b.GeneratedAt.Format(time.RFC3339Nano),
	}, "\x1f"))
}

// Verify reports whether b's attestation was produced by key's private half.
func (b Bundle) Verify(pub ed25519.PublicKey) bool {
	sig, err := hex.DecodeString(b.Attestation)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, b.signingPayload(), sig)
}
