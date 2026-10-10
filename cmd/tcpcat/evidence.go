package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/NycolazSec/tcpcat/config"
	"github.com/NycolazSec/tcpcat/internal/evidence"
	"github.com/NycolazSec/tcpcat/internal/scan"
)

// writeEvidence stores the evidence bundle of a finished scan (--evidence),
// signed when --evidence-key is set. The signing key is loaded first so a
// wrong key path fails before anything is written.
func writeEvidence(opts *config.Options, results []scan.TargetResult) {
	var signer *evidence.Signer
	if opts.EvidenceKey != "" {
		s, err := evidence.LoadSigner(opts.EvidenceKey)
		if err != nil {
			fmt.Printf("%s[!] Evidence not written: %v%s\n", config.Red, err, config.Reset)
			return
		}
		signer = s
	}
	bundle := evidence.Build(results, evidence.Tool{Name: "tcpcat", Version: version, Commit: commit}, os.Args[1:], time.Now())
	if err := evidence.Write(opts.EvidenceOutput, bundle, signer); err != nil {
		fmt.Printf("%s[!] Failed to write evidence: %v%s\n", config.Red, err, config.Reset)
		return
	}
	signed := "SHA-256 digest only"
	if signer != nil {
		signed = "signed (" + opts.EvidenceOutput + ".sig)"
	}
	fmt.Printf("%s[✓] Evidence for %d open port(s) written to %s, %s. Re-check later with: tcpcat replay %s%s\n",
		config.White, len(bundle.Findings), opts.EvidenceOutput, signed, opts.EvidenceOutput, config.Reset)
}

const evidenceUsage = `Usage:
  tcpcat evidence keygen --out <prefix>          Create <prefix>.key (keep private) and <prefix>.pub
  tcpcat evidence verify <bundle.json> [--pub <key.pub>]
                                                 Check the bundle was not modified (signature, or
                                                 its .sha256 digest when no key is given)
  tcpcat replay <bundle.json> [--pub <key.pub>] [--finding <id>] [-j <report.json>] [--timeout <ms>]
                                                 Re-probe every recorded open port: exit 0 when all are
                                                 fixed, 1 when at least one still reproduces
`

func runEvidence(args []string) int {
	if len(args) == 0 {
		fmt.Print(evidenceUsage)
		return exitError
	}
	switch args[0] {
	case "keygen":
		fs := flag.NewFlagSet("evidence keygen", flag.ContinueOnError)
		out := fs.String("out", "tcpcat-evidence", "Key file prefix")
		if err := fs.Parse(args[1:]); err != nil {
			return exitError
		}
		pubPath, keyPath, err := evidence.GenerateKeyPair(*out)
		if err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
		pub, _ := evidence.LoadPublicKey(pubPath)
		fmt.Printf("%s[✓] Private key: %s (mode 0600, never share it)%s\n", config.White, keyPath, config.Reset)
		fmt.Printf("%s[✓] Public key:  %s (fingerprint %s) -- give this one to whoever verifies your evidence%s\n",
			config.White, pubPath, evidence.Fingerprint(pub), config.Reset)
		return exitOK
	case "verify":
		fs := flag.NewFlagSet("evidence verify", flag.ContinueOnError)
		pub := fs.String("pub", "", "Public key to verify the signature with")
		file, rest := splitPositional(args[1:])
		if err := fs.Parse(rest); err != nil || file == "" {
			fmt.Print(evidenceUsage)
			return exitError
		}
		bundle, err := verifyBundle(file, *pub)
		if err != nil {
			fmt.Printf("%s[✗] %v%s\n", config.Red, err, config.Reset)
			return exitViolation
		}
		fmt.Printf("%s    %d finding(s), recorded %s from %s with %s %s%s\n", config.Gray, len(bundle.Findings),
			bundle.CreatedAt.Format(time.RFC3339), bundle.Vantage.Hostname, bundle.Tool.Name, bundle.Tool.Version, config.Reset)
		return exitOK
	case "-h", "--help", "help":
		fmt.Print(evidenceUsage)
		return exitOK
	}
	fmt.Printf("%s[!] Unknown evidence command %q.%s\n\n%s", config.Red, args[0], config.Reset, evidenceUsage)
	return exitError
}

// verifyBundle checks a bundle's integrity: the Ed25519 signature when a
// public key is given (a missing .sig is then an error), otherwise the
// .sha256 digest written next to it.
func verifyBundle(path, pubPath string) (evidence.Bundle, error) {
	bundle, data, err := evidence.Load(path)
	if err != nil {
		return bundle, err
	}
	if pubPath != "" {
		pub, err := evidence.LoadPublicKey(pubPath)
		if err != nil {
			return bundle, err
		}
		sig, err := os.ReadFile(path + ".sig")
		if err != nil {
			return bundle, fmt.Errorf("no signature next to the bundle (%s.sig): %w", path, err)
		}
		if err := evidence.Verify(pub, data, string(sig)); err != nil {
			return bundle, err
		}
		fmt.Printf("%s[✓] Signature valid (key %s): the evidence is exactly as recorded.%s\n", config.White, evidence.Fingerprint(pub), config.Reset)
		return bundle, nil
	}
	digest, err := os.ReadFile(path + ".sha256")
	if err != nil {
		return bundle, fmt.Errorf("no %s.sha256 digest and no --pub key: cannot check integrity", path)
	}
	if err := evidence.VerifyDigest(data, string(digest)); err != nil {
		return bundle, err
	}
	fmt.Printf("%s[✓] SHA-256 digest matches. (A digest only detects accidental changes; use --pub with a signed bundle to rule out deliberate ones.)%s\n",
		config.White, config.Reset)
	return bundle, nil
}

func runReplay(args []string) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	pub := fs.String("pub", "", "Verify the bundle's signature with this public key before replaying")
	only := fs.String("finding", "", "Replay only the finding with this ID")
	jsonOut := fs.String("j", "", "Write the replay outcome as JSON")
	timeoutMs := fs.Int("timeout", 3000, "Per-port timeout in milliseconds")
	fs.Usage = func() { fmt.Print(evidenceUsage) }
	file, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || file == "" {
		fmt.Print(evidenceUsage)
		return exitError
	}

	bundle, err := verifyBundle(file, *pub)
	if err != nil {
		fmt.Printf("%s[✗] Refusing to replay: %v%s\n", config.Red, err, config.Reset)
		return exitError
	}
	findings := bundle.Findings
	if *only != "" {
		findings = nil
		for _, f := range bundle.Findings {
			if strings.HasPrefix(f.ID, *only) {
				findings = append(findings, f)
			}
		}
		if len(findings) == 0 {
			fmt.Printf("%s[!] No finding with ID %q in %s.%s\n", config.Red, *only, file, config.Reset)
			return exitError
		}
	}
	fmt.Printf("%s[*] Replaying %d finding(s) recorded %s from %s...%s\n", config.Bold, len(findings),
		bundle.CreatedAt.Format(time.RFC3339), bundle.Vantage.Hostname, config.Reset)

	outcomes := evidence.Replay(findings, evidence.TCPProbe(time.Duration(*timeoutMs)*time.Millisecond))
	open := 0
	for _, o := range outcomes {
		f := o.Finding
		label, color := "[✓] FIXED     ", config.White
		switch o.Result {
		case evidence.OutcomeReproduced:
			label, color = "[✗] STILL OPEN", config.Red
			open++
		case evidence.OutcomeChanged:
			label, color = "[~] CHANGED   ", config.Red
			open++
		}
		svc := strings.TrimSpace(f.Service + " " + f.Version)
		if svc != "" {
			svc = " (" + svc + ")"
		}
		fmt.Printf("%s%s %s %s%s -- %s%s\n", color, label, f.ID, hostPort(f.IP, f.Port), svc, o.Detail, config.Reset)
	}

	if *jsonOut != "" {
		data, _ := json.MarshalIndent(map[string]interface{}{
			"bundle": file, "replayed_at": time.Now().UTC(), "outcomes": outcomes,
		}, "", "  ")
		if err := os.WriteFile(*jsonOut, data, 0600); err != nil {
			fmt.Printf("%s[!] %v%s\n", config.Red, err, config.Reset)
			return exitError
		}
	}
	if open > 0 {
		fmt.Printf("%s[✗] %d of %d finding(s) still reproduce.%s\n", config.Red, open, len(outcomes), config.Reset)
		return exitViolation
	}
	fmt.Printf("%s[✓] All %d finding(s) are fixed.%s\n", config.White, len(outcomes), config.Reset)
	return exitOK
}

func hostPort(ip string, port int) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}
