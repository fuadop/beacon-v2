package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithCORSHandlesPreflight(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	req := httptest.NewRequest(http.MethodOptions, "/devices", nil)
	rec := httptest.NewRecorder()
	withCORS(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for OPTIONS preflight, got %d", rec.Code)
	}
	if called {
		t.Fatal("preflight OPTIONS request must not reach the wrapped handler")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("expected Access-Control-Allow-Origin: *, got %q", got)
	}
}

// Business Forms panels issue their initial/update requests as plain fetch()
// calls from the user's own browser rather than through Grafana's backend proxy,
// so every real response (not just preflight) needs the CORS header too.
func TestWithCORSSetsHeaderOnRealRequests(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	rec := httptest.NewRecorder()
	withCORS(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected request to reach wrapped handler, got status %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("expected Access-Control-Allow-Origin: *, got %q", got)
	}
}
