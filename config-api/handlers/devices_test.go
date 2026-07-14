package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fuad/network-monitor/internal/crypto"
	"github.com/fuad/network-monitor/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, *DeviceHandler) {
	t.Helper()
	db, err := store.OpenConfigDB(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	rawKey := make([]byte, 32)
	rand.Read(rawKey)
	key, err := crypto.NewKey(hex.EncodeToString(rawKey))
	if err != nil {
		t.Fatal(err)
	}

	h := &DeviceHandler{Store: store.NewDeviceStore(db), Key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /devices", h.List)
	mux.HandleFunc("POST /devices", h.Create)
	mux.HandleFunc("GET /devices/{id}", h.Get)
	mux.HandleFunc("PATCH /devices/{id}", h.Update)

	return httptest.NewServer(mux), h
}

func TestCreateDeviceMasksCredentials(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	body := `{"ip_address":"192.168.1.10","snmp_version":"v2c","community":"super-secret-community"}`
	resp, err := http.Post(srv.URL+"/devices", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	rawBody := new(bytes.Buffer)
	rawBody.ReadFrom(resp.Body)
	if strings.Contains(rawBody.String(), "super-secret-community") {
		t.Fatalf("response leaked plaintext credential: %s", rawBody.String())
	}

	var got deviceResponse
	if err := json.Unmarshal(rawBody.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.HasCommunity {
		t.Fatal("expected has_community=true")
	}
	if got.IsPublicIP {
		t.Fatal("192.168.1.10 should be classified private")
	}
	if got.Status != "pending" {
		t.Fatalf("expected status pending, got %q", got.Status)
	}
}

func TestCreateDeviceClassifiesPublicIP(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	body := `{"ip_address":"8.8.8.8","snmp_version":"v2c","community":"x"}`
	resp, err := http.Post(srv.URL+"/devices", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got deviceResponse
	json.NewDecoder(resp.Body).Decode(&got)
	if !got.IsPublicIP {
		t.Fatal("8.8.8.8 should be classified public")
	}
}

func TestCreateDeviceIgnoresClientSuppliedIsPublicIP(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	// A malicious/buggy client claiming a private IP is public (or vice versa)
	// must not override the server-side RFC1918 classification.
	body := `{"ip_address":"192.168.1.20","is_public_ip":true}`
	resp, err := http.Post(srv.URL+"/devices", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got deviceResponse
	json.NewDecoder(resp.Body).Decode(&got)
	if got.IsPublicIP {
		t.Fatal("server must derive is_public_ip from ip_address, not trust client input")
	}
}

func TestUpdateDeviceCredentialRoundTripsThroughEncryption(t *testing.T) {
	srv, h := newTestServer(t)
	defer srv.Close()

	createResp, err := http.Post(srv.URL+"/devices", "application/json",
		strings.NewReader(`{"ip_address":"10.1.1.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	var created deviceResponse
	json.NewDecoder(createResp.Body).Decode(&created)
	createResp.Body.Close()

	req, err := http.NewRequest(http.MethodPatch, srv.URL+"/devices/1",
		strings.NewReader(`{"community":"new-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	patchResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer patchResp.Body.Close()
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", patchResp.StatusCode)
	}

	d, err := h.Store.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Community == "new-secret" {
		t.Fatal("community must be stored encrypted, not plaintext")
	}
	decrypted, err := h.Key.Decrypt(d.Community)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != "new-secret" {
		t.Fatalf("expected decrypted community 'new-secret', got %q", decrypted)
	}
}

func TestListDevices(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	http.Post(srv.URL+"/devices", "application/json", strings.NewReader(`{"ip_address":"10.2.2.2"}`))
	http.Post(srv.URL+"/devices", "application/json", strings.NewReader(`{"ip_address":"10.2.2.3"}`))

	resp, err := http.Get(srv.URL + "/devices")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var list []deviceResponse
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(list))
	}
}
