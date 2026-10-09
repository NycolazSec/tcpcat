package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func guardedHandler(t *testing.T) http.Handler {
	t.Helper()
	h, err := newHandler("127.0.0.1:8080", testToken)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	return h
}

func do(t *testing.T, h http.Handler, method, path, host string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Host = host
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGuardRequiresToken(t *testing.T) {
	h := guardedHandler(t)
	if rec := do(t, h, http.MethodGet, "/api/status", "127.0.0.1:8080", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/status", "127.0.0.1:8080", map[string]string{tokenHeader: "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: got %d, want 401", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/status", "127.0.0.1:8080", map[string]string{tokenHeader: testToken}); rec.Code != http.StatusOK {
		t.Errorf("valid token: got %d, want 200", rec.Code)
	}
}

func TestGuardRejectsDNSRebinding(t *testing.T) {
	h := guardedHandler(t)
	rec := do(t, h, http.MethodGet, "/api/status", "attacker.example:8080", map[string]string{tokenHeader: testToken})
	if rec.Code != http.StatusForbidden {
		t.Errorf("foreign Host: got %d, want 403", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/", "attacker.example:8080", nil); rec.Code != http.StatusForbidden {
		t.Errorf("foreign Host on index: got %d, want 403", rec.Code)
	}
}

func TestGuardRejectsCrossOrigin(t *testing.T) {
	h := guardedHandler(t)
	for _, origin := range []string{"http://attacker.example", "https://127.0.0.1:8080", "null"} {
		rec := do(t, h, http.MethodPost, "/api/scan", "127.0.0.1:8080", map[string]string{tokenHeader: testToken, "Origin": origin})
		if rec.Code != http.StatusForbidden {
			t.Errorf("Origin %q: got %d, want 403", origin, rec.Code)
		}
	}
	// A same-origin request passes the guard (and reaches the handler, which
	// rejects the empty body with 400 -- not a guard rejection).
	rec := do(t, h, http.MethodPost, "/api/scan", "127.0.0.1:8080", map[string]string{tokenHeader: testToken, "Origin": "http://127.0.0.1:8080"})
	if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Errorf("same-origin request was blocked by the guard: %d", rec.Code)
	}
}

func TestGuardServesIndexWithoutTokenAndSetsHeaders(t *testing.T) {
	h := guardedHandler(t)
	for _, host := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		rec := do(t, h, http.MethodGet, "/", host, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("index via %s: got %d, want 200", host, rec.Code)
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("index via %s: missing security headers", host)
		}
	}
}

func TestAllowedHostsPort80AcceptsBareHost(t *testing.T) {
	hosts, err := allowedHosts("127.0.0.1:80")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"localhost", "127.0.0.1", "[::1]", "localhost:80"} {
		if !hosts[h] {
			t.Errorf("port 80 should accept Host %q", h)
		}
	}
}

func TestNewTokenIsRandom(t *testing.T) {
	a, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newToken()
	if len(a) != 64 || a == b {
		t.Errorf("tokens should be 64 hex chars and unique: %q %q", a, b)
	}
}
