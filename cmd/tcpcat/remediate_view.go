package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/evidence"
	"github.com/NycolazSec/tcpcat/internal/explain"
	"github.com/NycolazSec/tcpcat/internal/remediate"
)

// writeRemediation turns the explanation's unexpected exposures into the
// defensive config that closes each one and writes it to dst ("-" is
// stdout). keyPath, when set, signs each bundle with an Ed25519 key so a
// reviewer can tell tcpcat's output from a hand-edited copy.
func writeRemediation(rep explain.Report, dst, keyPath string) error {
	var key ed25519.PrivateKey
	if keyPath != "" {
		signer, err := evidence.LoadSigner(keyPath)
		if err != nil {
			return fmt.Errorf("remediation key: %w", err)
		}
		key = signer.Key()
	}

	bundles := remediate.FromReport(rep, key, time.Now())
	if len(bundles) == 0 {
		fmt.Printf("  %sNothing to remediate: no unexpected port is reachable.%s\n", config.Gray, config.Reset)
		return nil
	}

	text := renderRemediation(rep, bundles, key != nil)
	if dst == "-" {
		fmt.Print("\n" + text)
		return nil
	}
	if err := os.WriteFile(dst, []byte(text), 0600); err != nil {
		return err
	}
	fmt.Printf("  %sRemediation for %d exposure(s) written to %s%s\n", config.Gray, len(bundles), dst, config.Reset)
	return nil
}

func renderRemediation(rep explain.Report, bundles []remediate.Bundle, signed bool) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Remediation for %s (%s)\n", rep.Host, rep.Target)
	fmt.Fprintf(&sb, "# %d exposure(s) to close. Every command below is inert text: read it,\n", len(bundles))
	sb.WriteString("# adapt the allow-lists to your network, and apply it yourself. tcpcat\n")
	sb.WriteString("# runs none of it.\n")
	if signed {
		sb.WriteString("# Each bundle carries an Ed25519 attestation (attestation_ed25519).\n")
	}

	for _, b := range bundles {
		sb.WriteString("\n" + strings.Repeat("-", 72) + "\n")
		fmt.Fprintf(&sb, "## %s\n\n", b.Summary)

		fmt.Fprintf(&sb, "### Host firewall (nftables)\n%s\n", b.Nftables)
		if b.Systemd != "" {
			fmt.Fprintf(&sb, "\n### systemd service confinement\n%s", b.Systemd)
		}
		if b.KubePolicy != "" {
			fmt.Fprintf(&sb, "\n### Kubernetes NetworkPolicy\n%s", b.KubePolicy)
		}
		if b.Rebind != "" {
			fmt.Fprintf(&sb, "\n### Better: fix it at the source\n# %s\n", b.Rebind)
		}
		if b.Attestation != "" {
			fmt.Fprintf(&sb, "\n# attestation_ed25519: %s\n", b.Attestation)
		}
	}
	return sb.String()
}
