package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCollectorGetReturnsConfiguredIP(t *testing.T) {
	h := &CollectorHandler{IP: "172.16.254.27"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /collector-ip", h.Get)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/collector-ip")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["ip"] != "172.16.254.27" {
		t.Errorf("ip = %q, want 172.16.254.27", got["ip"])
	}
}

func TestCollectorGetUnconfiguredReturns500(t *testing.T) {
	h := &CollectorHandler{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /collector-ip", h.Get)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/collector-ip")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}
