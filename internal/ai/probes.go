package ai

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Prober runs the follow-up checks of a deep analysis. Every check is
// read-only: it asks a question a normal client would ask (which login
// methods do you accept? where does this page redirect?) and never sends a
// credential. NetProber is the real one; tests use a fake.
type Prober interface {
	// SSHAuthMethods returns the login methods an SSH server offers to a
	// client that has not authenticated yet.
	SSHAuthMethods(host string, port int) ([]string, error)
	// HTTPGet fetches path and returns the status, headers and the start of
	// the body. Redirects are not followed.
	HTTPGet(host string, port int, useTLS bool, path string) (int, http.Header, string, error)
}

// NetProber talks to the real network.
type NetProber struct {
	Timeout time.Duration
}

func (p NetProber) timeout() time.Duration {
	if p.Timeout <= 0 {
		return 5 * time.Second
	}
	return p.Timeout
}

// errProbeOnly aborts an authentication method after learning the server
// offers it, before anything is sent.
var errProbeOnly = errors.New("tcpcat: login methods probe, no credential sent")

// SSHAuthMethods offers no key and answers every password or
// keyboard-interactive prompt with an error, so the client library only
// reports which methods the server allows. The server logs a failed,
// credential-less login attempt by user "tcpcat".
func (p NetProber) SSHAuthMethods(host string, port int) ([]string, error) {
	var mu sync.Mutex
	seen := map[string]bool{}
	mark := func(m string) {
		mu.Lock()
		seen[m] = true
		mu.Unlock()
	}
	cfg := &ssh.ClientConfig{
		User: "tcpcat",
		Auth: []ssh.AuthMethod{
			ssh.PasswordCallback(func() (string, error) { mark("password"); return "", errProbeOnly }),
			ssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
				mark("keyboard-interactive")
				return nil, errProbeOnly
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 -- identification probe: no session is opened and nothing is trusted
		Timeout:         p.timeout(),
	}
	// ssh.Dial's timeout only covers the TCP connection; a server that
	// accepts and then never speaks (a SYN proxy, a tarpit) would hold the
	// handshake for as long as it likes. The deadline covers it all.
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, p.timeout())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.timeout()))
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err == nil {
		// The server let an unauthenticated client in.
		_ = ssh.NewClient(sc, chans, reqs).Close()
		return []string{"none"}, nil
	}
	// Either every method we were offered failed ("unable to authenticate"),
	// or a callback above stopped the handshake once the server offered its
	// method: both mean the server answered the question.
	if !strings.Contains(err.Error(), "unable to authenticate") && !strings.Contains(err.Error(), errProbeOnly.Error()) {
		return nil, err
	}
	var methods []string
	for _, m := range []string{"password", "keyboard-interactive"} {
		if seen[m] {
			methods = append(methods, m)
		}
	}
	if len(methods) == 0 {
		methods = []string{"publickey"} // the only kind left after none, password and keyboard-interactive
	}
	return methods, nil
}

// HTTPGet sends one GET without following redirects.
func (p NetProber) HTTPGet(host string, port int, useTLS bool, path string) (int, http.Header, string, error) {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	client := &http.Client{
		Timeout: p.timeout(),
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- identification probe against the user's own hosts; nothing is sent
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	u := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + path
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("User-Agent", "tcpcat")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, resp.Header, string(body), nil
}

// Diagnoser runs the checks that explain how a scan went: is a port still
// reachable now, and how long does a service take to speak first. Both
// open a plain TCP connection and close it; nothing is sent.
type Diagnoser interface {
	// Dial says whether a port answers now: "open", "closed" (refused) or
	// "filtered" (no answer, or an ICMP error).
	Dial(host string, port int, timeout time.Duration) string
	// FirstBytes connects and waits up to wait for the service to send
	// something. connected is false when the connection itself failed;
	// otherwise delay is how long the first bytes took, and data is empty
	// when nothing came in time.
	FirstBytes(host string, port int, wait time.Duration) (connected bool, delay time.Duration, data string)
}

// Dial implements Diagnoser.
func (p NetProber) Dial(host string, port int, timeout time.Duration) string {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		if strings.Contains(err.Error(), "refused") {
			return "closed"
		}
		return "filtered"
	}
	_ = c.Close()
	return "open"
}

// FirstBytes implements Diagnoser.
func (p NetProber) FirstBytes(host string, port int, wait time.Duration) (bool, time.Duration, string) {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), p.timeout())
	if err != nil {
		return false, 0, ""
	}
	defer func() { _ = c.Close() }()
	start := time.Now()
	_ = c.SetReadDeadline(start.Add(wait))
	buf := make([]byte, 512)
	n, _ := c.Read(buf)
	return true, time.Since(start), string(buf[:n])
}
