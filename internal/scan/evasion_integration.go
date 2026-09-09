package scan

import (
	"net"
	"strings"

	"tcpcat/config"
	"tcpcat/internal/evasion"
)

func BuildEvasionOptions(opts *config.Options) EvasionOptions {
	evasionOpts := EvasionOptions{
		Enabled:         opts.EvasionMode != "off",
		TimingJitter:    opts.Jitter,
		FragmentPackets: opts.Fragment,
		UseAdaptiveML:   opts.EvasionMode == "aggressive" || opts.EvasionMode == "stealthy",
		Decoys:          parseDecoyIPs(opts.DecoyIPs),
	}

	switch strings.ToLower(opts.EvasionMode) {
	case "light":
		evasionOpts.Mode = evasion.EvasionModeLight
	case "moderate":
		evasionOpts.Mode = evasion.EvasionModeModerate
	case "aggressive":
		evasionOpts.Mode = evasion.EvasionModeAggressive
	case "stealthy":
		evasionOpts.Mode = evasion.EvasionModeStealthy
	default:
		evasionOpts.Mode = evasion.EvasionModeOff
	}

	return evasionOpts
}

func parseDecoyIPs(decoyStr string) []net.IP {
	if decoyStr == "" {
		return nil
	}

	parts := strings.Split(decoyStr, ",")
	var decoys []net.IP

	for _, part := range parts {
		ip := net.ParseIP(strings.TrimSpace(part))
		if ip != nil {
			decoys = append(decoys, ip)
		}
	}

	return decoys
}

func ApplyEvasionOptions(engine *Engine, opts *config.Options) {

	if opts.Jitter > 0 {

		engine.opts.Jitter = opts.Jitter
	}

	if opts.Fragment {
		engine.opts.Fragment = true
	}

	if opts.TTL > 0 {
		engine.opts.TTL = opts.TTL
	}

	if opts.SourcePort > 0 {
		engine.opts.SourcePort = opts.SourcePort
	}

	if opts.WindowSize > 0 {
		engine.opts.WindowSize = opts.WindowSize
	}

	if opts.TTLMode == "random" {
		engine.opts.TTLMode = "random"
	}

	if opts.SourcePortMode == "random" {
		engine.opts.SourcePortMode = "random"
	}
}

func ValidateEvasionCompatibility(opts *config.Options) bool {
	if opts.EvasionMode == "off" {
		return true
	}

	isSpoofable := opts.SynScan || opts.AckScan || opts.WindowScan ||
		opts.NullScan || opts.FinScan || opts.XmasScan || opts.UdpScan

	if !isSpoofable && opts.ConnectScan {

		return true
	}

	return true
}
