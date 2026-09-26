package service

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTPPostureInfo is the result of an independent, read-only HTTP security
// posture probe: which common security response headers are missing, and
// whether any of a small set of well-known sensitive paths (.git/, .env)
// are actually exposed rather than just returning a generic 200.
type HTTPPostureInfo struct {
	MissingHeaders []string `json:"missing_headers,omitempty"`
	ExposedPaths   []string `json:"exposed_paths,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	// Server/Software/Version/OS identify the HTTP server from its own
	// Server response header, read via a real net/http client -- which
	// negotiates ALPN and speaks HTTP/2 transparently when a server
	// selects it. DetectService's own hand-rolled plaintext GET (its only
	// HTTP identification attempt on a TLS port before this) can't parse
	// an HTTP/2 response at all, which is why a TLS port serving h2 used
	// to come back "unknown" despite answering every request.
	Server   string `json:"server,omitempty"`
	Software string `json:"software,omitempty"`
	Version  string `json:"version,omitempty"`
	OS       string `json:"os,omitempty"`
}

// securityHeaderChecks are checked unconditionally (independent of
// scheme). Strict-Transport-Security is meaningful only over TLS --
// browsers ignore it on plain HTTP -- so it's checked separately in
// probeHTTPPosture only when useTLS is true.
var securityHeaderChecks = []string{
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
}

// sensitivePaths are a small, well-known set -- this is meant to catch
// obvious, common exposure, not to be a path fuzzer. Each has a body
// signature, not just a status-code check: a lot of real sites (SPAs
// with a client-side router, custom error pages) return 200 for any
// path, and a bare status check would flag every one of them.
var sensitivePaths = []struct {
	path      string
	signature func(body string) bool
	label     string
}{
	{
		path:      "/.git/HEAD",
		signature: func(body string) bool { return strings.Contains(body, "ref:") },
		label:     "Git repository exposed (.git/HEAD readable)",
	},
	{
		path:      "/.git/config",
		signature: func(body string) bool { return strings.Contains(body, "[core]") },
		label:     "Git repository exposed (.git/config readable)",
	},
	{
		path: "/.env",
		signature: func(body string) bool {
			lower := strings.ToLower(body)
			return !strings.Contains(lower, "<html") && !strings.Contains(lower, "<!doctype") && strings.Contains(body, "=")
		},
		label: ".env file exposed",
	},
}

const sensitivePathBodyLimit = 4096

// probeHTTPPosture performs its own dedicated HTTP client session --
// separate from DetectService's raw-socket banner grab on the same port,
// same reasoning as probeTLS: net/http handles headers, redirects, and
// chunked responses correctly, which hand-parsing a raw response does not.
// Redirects are not followed -- a check is about *this* host's own
// response, not wherever it happens to redirect to.
//
// hostname, when the target was asked for by name, is sent as the Host
// header and as TLS SNI while still connecting to the scanned address:
// one address can serve any number of virtual hosts, and asking it by IP
// gets whichever one it falls back to -- so the headers and paths
// reported would belong to a different site than the one scanned.
func probeHTTPPosture(ip string, port int, timeout time.Duration, useTLS bool, insecureSkipVerify bool, hostname string) *HTTPPostureInfo {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(ip, strconv.Itoa(port)))

	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify, // #nosec G402 -- opt-in via caller flag, same semantics as the existing banner-grab path
		NextProtos:         []string{"h2", "http/1.1"},
	}
	if hostname != "" {
		tlsConfig.ServerName = hostname
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	// Setting TLSClientConfig ourselves opts this Transport out of Go's
	// usual *automatic* HTTP/2 wiring (net/http only self-configures h2
	// when TLSClientConfig is left nil) -- offering "h2" in NextProtos
	// above is necessary but not sufficient on its own; without enabling
	// HTTP2 here too, the client negotiates the ALPN protocol but then
	// still speaks plain HTTP/1.1 text over it, which an h2-only server
	// rejects outright as a garbled preface.
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP1(true)
	transport.Protocols.SetHTTP2(true)
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()

	get := func(path string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			return nil, err
		}
		if hostname != "" {
			req.Host = hostname
		}
		return client.Do(req)
	}

	resp, err := get("/")
	if err != nil {
		return nil
	}
	_ = resp.Body.Close()

	info := &HTTPPostureInfo{}

	if server := resp.Header.Get("Server"); server != "" {
		info.Server = server
		info.Software, info.Version, info.OS = parseServerHeaderValue(server)
	}

	if useTLS && resp.Header.Get("Strict-Transport-Security") == "" {
		info.MissingHeaders = append(info.MissingHeaders, "Strict-Transport-Security")
	}
	for _, h := range securityHeaderChecks {
		if resp.Header.Get(h) == "" {
			info.MissingHeaders = append(info.MissingHeaders, h)
		}
	}
	for _, h := range info.MissingHeaders {
		info.Warnings = append(info.Warnings, fmt.Sprintf("missing security header: %s", h))
	}

	for _, sp := range sensitivePaths {
		pResp, pErr := get(sp.path)
		if pErr != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(pResp.Body, sensitivePathBodyLimit))
		_ = pResp.Body.Close()

		if pResp.StatusCode == http.StatusOK && sp.signature(string(body)) {
			info.ExposedPaths = append(info.ExposedPaths, sp.path)
			info.Warnings = append(info.Warnings, sp.label)
		}
	}

	return info
}
