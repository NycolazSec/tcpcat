package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleScanRejectsUnreadableScopeBeforeScan(t *testing.T) {
	server := &server{}
	request := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewBufferString(`{"target":"127.0.0.1","ports":"80","profile":"safe-production","scope_file":"/does/not/exist"}`))
	recorder := httptest.NewRecorder()

	server.handleScan(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

func TestHandleScanRejectsUnsupportedProfile(t *testing.T) {
	server := &server{}
	request := httptest.NewRequest(http.MethodPost, "/api/scan", bytes.NewBufferString(`{"target":"127.0.0.1","ports":"80","profile":"unsafe"}`))
	recorder := httptest.NewRecorder()

	server.handleScan(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}
