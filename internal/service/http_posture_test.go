package service

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeHTTPPostureFlagsMissingHeadersAndExposedFiles(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ref: refs/heads/main\n"))
	})
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("DATABASE_URL=postgres://user:pass@localhost/db\nAPI_KEY=abc123\n"))
	})

	ip, port := startHTTPTestServer(t, mux)

	info := probeHTTPPosture(ip, port, 2*time.Second, false, false, "")
	if info == nil {
		t.Fatal("probeHTTPPosture() = nil, want a result")
	}

	wantMissing := []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"}
	if len(info.MissingHeaders) != len(wantMissing) {
		t.Errorf("MissingHeaders = %v, want %v", info.MissingHeaders, wantMissing)
	}

	wantExposed := []string{"/.git/HEAD", "/.git/config", "/.env"}
	if len(info.ExposedPaths) != len(wantExposed) {
		t.Fatalf("ExposedPaths = %v, want %v", info.ExposedPaths, wantExposed)
	}
	for i, p := range wantExposed {
		if info.ExposedPaths[i] != p {
			t.Errorf("ExposedPaths[%d] = %q, want %q", i, info.ExposedPaths[i], p)
		}
	}

	if len(info.Warnings) != len(wantMissing)+len(wantExposed) {
		t.Errorf("Warnings = %v, want %d entries", info.Warnings, len(wantMissing)+len(wantExposed))
	}
}

func TestProbeHTTPPostureNoFalsePositivesOnSPAFallback(t *testing.T) {
	// A single-page app whose router returns 200 + an HTML shell for any
	// unmatched path is a classic false-positive trap for a status-code-only
	// exposure check: every one of these paths "exists" (200), but none of
	// them actually is a git/env file. The body-signature check must reject
	// all of them.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		_, _ = w.Write([]byte("<html><body>app shell</body></html>"))
	})
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>Not found (SPA fallback)</body></html>"))
	})
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>Not found (SPA fallback)</body></html>"))
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>Not found (SPA fallback)</body></html>"))
	})

	ip, port := startHTTPTestServer(t, mux)

	info := probeHTTPPosture(ip, port, 2*time.Second, false, false, "")
	if info == nil {
		t.Fatal("probeHTTPPosture() = nil, want a result")
	}
	if len(info.MissingHeaders) != 0 || len(info.ExposedPaths) != 0 || len(info.Warnings) != 0 {
		t.Errorf("probeHTTPPosture() = %+v, want a clean result (all headers present, all paths correctly identified as SPA fallback)", info)
	}
}

func TestProbeHTTPPostureChecksHSTSOnlyOverTLS(t *testing.T) {
	// A plain-HTTP server missing every header except HSTS -- which
	// browsers ignore outside TLS anyway -- should not be dinged for it.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusOK)
	})

	ip, port := startHTTPTestServer(t, mux)

	info := probeHTTPPosture(ip, port, 2*time.Second, false, false, "")
	if info == nil {
		t.Fatal("probeHTTPPosture() = nil, want a result")
	}
	for _, h := range info.MissingHeaders {
		if h == "Strict-Transport-Security" {
			t.Error("HSTS should not be flagged missing over plain HTTP")
		}
	}
}

func TestProbeHTTPPostureUnreachableReturnsNil(t *testing.T) {
	if info := probeHTTPPosture("127.0.0.1", 1, 200*time.Millisecond, false, false, ""); info != nil {
		t.Errorf("probeHTTPPosture() = %+v for an unreachable port, want nil", info)
	}
}

// startHTTPTestServer starts a plain (non-TLS) HTTP server on 127.0.0.1
// and returns its host and port, so probeHTTPPosture can be exercised
// against a real listener without any external process.
func startHTTPTestServer(t *testing.T, handler http.Handler) (string, int) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	addr := server.Listener.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port
}

// TestProbeHTTPPostureReadsServerHeaderOverHTTP2 guards the ALPN gotcha
// this fixes: setting InsecureSkipVerify on tls.Config without also
// setting NextProtos silently disables Go's automatic HTTP/2 support,
// which meant this probe's own client never actually spoke HTTP/2 to a
// server that offered it (server.EnableHTTP2 forces the test server to
// require it, so a client stuck on http/1.1-only ALPN can't even connect).
func TestProbeHTTPPostureReadsServerHeaderOverHTTP2(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
	})
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)

	addr := server.Listener.Addr().(*net.TCPAddr)
	info := probeHTTPPosture("127.0.0.1", addr.Port, 2*time.Second, true, true, "")
	if info == nil {
		t.Fatal("probeHTTPPosture() = nil, want a result")
	}
	if info.Server != "nginx/1.24.0" {
		t.Errorf("Server = %q, want nginx/1.24.0", info.Server)
	}
	if info.Software != "nginx" || info.Version != "1.24.0" {
		t.Errorf("Software/Version = %q/%q, want nginx/1.24.0", info.Software, info.Version)
	}
}

func TestParseServerHeaderValue(t *testing.T) {
	software, version, os := parseServerHeaderValue("Apache/2.4.41 (Ubuntu)")
	if software != "apache" || version != "2.4.41" || os != "ubuntu" {
		t.Errorf("parseServerHeaderValue() = (%q, %q, %q), want (apache, 2.4.41, ubuntu)", software, version, os)
	}
}
