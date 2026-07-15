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
	"time"

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

	// Short timeout: tests probe unreachable/fake IPs and should fail fast
	// rather than eating the 3s production default on every device creation.
	h := &DeviceHandler{Store: store.NewDeviceStore(db), Key: key, ProbeTimeout: 100 * time.Millisecond}

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
	// 192.168.1.10 isn't a real reachable device in this test, so the
	// synchronous create-time probe (see TestCreateDeviceProbesAndSetsStatus)
	// is expected to fail — that's the point: it proves credentials were
	// actually tried rather than the device silently defaulting to "pending".
	if got.Status != "failed" {
		t.Fatalf("expected status failed (unreachable probe target), got %q", got.Status)
	}
}

func TestCreateDeviceWithoutSNMPVersionStaysPending(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/devices", "application/json", strings.NewReader(`{"ip_address":"10.9.9.9"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got deviceResponse
	json.NewDecoder(resp.Body).Decode(&got)
	if got.Status != "pending" {
		t.Fatalf("expected status pending when no snmp_version is given (nothing to probe), got %q", got.Status)
	}
}

func TestCreateDeviceProbesAndSetsStatus(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	// Same reasoning as TestCreateDeviceMasksCredentials: no real agent is
	// listening, so a version being set means the probe runs and fails.
	body := `{"ip_address":"10.9.9.10","snmp_version":"v2c","community":"public"}`
	resp, err := http.Post(srv.URL+"/devices", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got deviceResponse
	json.NewDecoder(resp.Body).Decode(&got)
	if got.Status != "failed" {
		t.Fatalf("expected status failed, got %q", got.Status)
	}
}

func TestCreateDeviceReturnsPopulatedTimestamps(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/devices", "application/json", strings.NewReader(`{"ip_address":"10.5.5.5"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got deviceResponse
	json.NewDecoder(resp.Body).Decode(&got)
	if got.CreatedAt == "" || got.UpdatedAt == "" {
		t.Fatalf("expected created_at/updated_at to be populated in the create response, got %+v", got)
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

func TestUpdateDeviceReprobesWhenSNMPFieldsChange(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	createResp, err := http.Post(srv.URL+"/devices", "application/json", strings.NewReader(`{"ip_address":"10.9.9.11"}`))
	if err != nil {
		t.Fatal(err)
	}
	var created deviceResponse
	json.NewDecoder(createResp.Body).Decode(&created)
	createResp.Body.Close()
	if created.Status != "pending" {
		t.Fatalf("expected freshly-created device with no version to be pending, got %q", created.Status)
	}

	req, err := http.NewRequest(http.MethodPatch, srv.URL+"/devices/1",
		strings.NewReader(`{"snmp_version":"v2c","community":"public"}`))
	if err != nil {
		t.Fatal(err)
	}
	patchResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer patchResp.Body.Close()

	var got deviceResponse
	json.NewDecoder(patchResp.Body).Decode(&got)
	// Unreachable target -> probe runs and fails, proving the update path
	// re-probes rather than leaving status wherever it was before the edit.
	if got.Status != "failed" {
		t.Fatalf("expected status failed after adding snmp credentials to an unreachable IP, got %q", got.Status)
	}
}

func TestUpdateDeviceRespectsExplicitStatus(t *testing.T) {
	srv, _ := newTestServer(t)
	defer srv.Close()

	createResp, err := http.Post(srv.URL+"/devices", "application/json", strings.NewReader(`{"ip_address":"10.9.9.12"}`))
	if err != nil {
		t.Fatal(err)
	}
	createResp.Body.Close()

	// Caller explicitly sets status alongside credentials — e.g. an operator
	// who knows the device is fine and wants to force it active without
	// waiting on a probe. That explicit choice must not be overridden.
	req, err := http.NewRequest(http.MethodPatch, srv.URL+"/devices/1",
		strings.NewReader(`{"snmp_version":"v2c","community":"public","status":"active"}`))
	if err != nil {
		t.Fatal(err)
	}
	patchResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer patchResp.Body.Close()

	var got deviceResponse
	json.NewDecoder(patchResp.Body).Decode(&got)
	if got.Status != "active" {
		t.Fatalf("expected explicit status to be respected, got %q", got.Status)
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
