package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fuad/network-monitor/internal/store"
)

func newTestSettingsServer(t *testing.T) *httptest.Server {
	t.Helper()
	db, err := store.OpenConfigDB(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	h := &SettingsHandler{Store: store.NewSettingsStore(db)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /settings/polling-interval", h.GetPollingInterval)
	mux.HandleFunc("POST /settings/polling-interval", h.SetPollingInterval)
	return httptest.NewServer(mux)
}

func TestGetPollingIntervalDefault(t *testing.T) {
	srv := newTestSettingsServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/settings/polling-interval")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got map[string]int
	json.NewDecoder(resp.Body).Decode(&got)
	if got["polling_interval_seconds"] != 60 {
		t.Fatalf("expected default 60, got %v", got)
	}
}

func TestSetPollingIntervalValidValue(t *testing.T) {
	srv := newTestSettingsServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/settings/polling-interval", "application/json",
		strings.NewReader(`{"polling_interval_seconds":300}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	getResp, err := http.Get(srv.URL + "/settings/polling-interval")
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()
	var got map[string]int
	json.NewDecoder(getResp.Body).Decode(&got)
	if got["polling_interval_seconds"] != 300 {
		t.Fatalf("expected 300 after update, got %v", got)
	}
}

func TestSetPollingIntervalRejectsInvalidValue(t *testing.T) {
	srv := newTestSettingsServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/settings/polling-interval", "application/json",
		strings.NewReader(`{"polling_interval_seconds":7}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for disallowed interval, got %d", resp.StatusCode)
	}
}
