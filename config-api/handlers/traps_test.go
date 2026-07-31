package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/fuad/network-monitor/internal/crypto"
	"github.com/fuad/network-monitor/internal/store"
)

func TestTrapsListReturnsRecentFirst(t *testing.T) {
	db, err := store.OpenTrapsDB(filepath.Join(t.TempDir(), "traps.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	trapStore := store.NewTrapStore(db)

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if _, err := trapStore.Insert(&store.Trap{SourceIP: ip, OID: ".1.3.6.1.6.3.1.1.5.3", Payload: "[]"}); err != nil {
			t.Fatal(err)
		}
	}

	h := &TrapsHandler{Store: trapStore}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /traps", h.List)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/traps")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got []store.Trap
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 traps, got %d", len(got))
	}
	if got[0].SourceIP != "10.0.0.3" {
		t.Errorf("expected newest trap (10.0.0.3) first, got %q", got[0].SourceIP)
	}
}

func TestTrapsListRespectsLimit(t *testing.T) {
	db, err := store.OpenTrapsDB(filepath.Join(t.TempDir(), "traps.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	trapStore := store.NewTrapStore(db)

	for i := 0; i < 5; i++ {
		if _, err := trapStore.Insert(&store.Trap{SourceIP: "10.0.0.1", OID: "x", Payload: "[]"}); err != nil {
			t.Fatal(err)
		}
	}

	h := &TrapsHandler{Store: trapStore}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /traps", h.List)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/traps?limit=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got []store.Trap
	json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 2 {
		t.Fatalf("expected 2 traps with limit=2, got %d", len(got))
	}
}

func newTestKey(t *testing.T) *crypto.Key {
	t.Helper()
	raw := make([]byte, 32)
	rand.Read(raw)
	key, err := crypto.NewKey(hex.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// TestListReadableResolvesDeviceByAgentAddress covers the primary attribution
// path: a v1 trap's agent_address matching a device's registered IP directly.
func TestListReadableResolvesDeviceByAgentAddress(t *testing.T) {
	configDB, err := store.OpenConfigDB(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer configDB.Close()
	key := newTestKey(t)
	devices := store.NewDeviceStore(configDB)
	encCommunity, _ := key.Encrypt("R2_Library_NETTMU")
	if _, err := devices.Create(&store.Device{
		IPAddress: "172.16.154.78", Hostname: "R2", SNMPVersion: "v2c", Community: encCommunity, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}

	trapsDB, err := store.OpenTrapsDB(filepath.Join(t.TempDir(), "traps.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer trapsDB.Close()
	trapStore := store.NewTrapStore(trapsDB)
	if _, err := trapStore.Insert(&store.Trap{
		SourceIP:     "172.16.154.69", // masked at the IP layer -- attribution must come from AgentAddress
		OID:          ".1.3.6.1.6.3.1.1.5.3",
		Payload:      `[{"oid":".1.3.6.1.2.1.2.2.1.1.1","type":"Integer","value":1},{"oid":".1.3.6.1.2.1.2.2.1.2.1","type":"OctetString","value":"GigabitEthernet0/1"}]`,
		Community:    "R2_Library_NETTMU",
		AgentAddress: "172.16.154.78",
	}); err != nil {
		t.Fatal(err)
	}

	h := &TrapsHandler{Store: trapStore, Devices: devices, Key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /traps/readable", h.ListReadable)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/traps/readable")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got []ReadableTrap
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 trap, got %d", len(got))
	}
	if got[0].Device != "R2" {
		t.Errorf("expected device R2, got %q", got[0].Device)
	}
	if got[0].Interface != "GigabitEthernet0/1" {
		t.Errorf("expected interface GigabitEthernet0/1, got %q", got[0].Interface)
	}
	if got[0].Name != "LinkDown" {
		t.Errorf("expected name LinkDown, got %q", got[0].Name)
	}
}

// TestListReadableFallsBackToCommunityMatch covers the ASA case: agent_address
// is a real value but doesn't match any registered device's IP (its internal
// failover-link address, not a routable one), so resolution must fall back to
// the community string, which is unique per device.
func TestListReadableFallsBackToCommunityMatch(t *testing.T) {
	configDB, err := store.OpenConfigDB(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer configDB.Close()
	key := newTestKey(t)
	devices := store.NewDeviceStore(configDB)
	encCommunity, _ := key.Encrypt("FW_LIBRARY_NetTMU")
	if _, err := devices.Create(&store.Device{
		IPAddress: "172.16.154.74", Hostname: "Firewall", SNMPVersion: "v2c", Community: encCommunity, Status: "active",
	}); err != nil {
		t.Fatal(err)
	}

	trapsDB, err := store.OpenTrapsDB(filepath.Join(t.TempDir(), "traps.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer trapsDB.Close()
	trapStore := store.NewTrapStore(trapsDB)
	if _, err := trapStore.Insert(&store.Trap{
		SourceIP:     "172.16.154.69",
		OID:          ".1.3.6.1.4.1.9.1.1902.0",
		Payload:      `[]`,
		Community:    "FW_LIBRARY_NetTMU",
		AgentAddress: "169.254.1.2", // ASA's internal failover-link address, not a registered device IP
	}); err != nil {
		t.Fatal(err)
	}

	h := &TrapsHandler{Store: trapStore, Devices: devices, Key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /traps/readable", h.ListReadable)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/traps/readable")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got []ReadableTrap
	json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 1 {
		t.Fatalf("expected 1 trap, got %d", len(got))
	}
	if got[0].Device != "Firewall" {
		t.Errorf("expected device Firewall (via community fallback), got %q", got[0].Device)
	}
}

func TestExtractInterfacePrefersIfDescr(t *testing.T) {
	payload := `[{"oid":".1.3.6.1.2.1.2.2.1.1.2","type":"Integer","value":2},{"oid":".1.3.6.1.2.1.2.2.1.2.2","type":"OctetString","value":"GigabitEthernet0/2"}]`
	if got := extractInterface(payload); got != "GigabitEthernet0/2" {
		t.Errorf("expected GigabitEthernet0/2, got %q", got)
	}
}

func TestExtractInterfaceFallsBackToIfIndex(t *testing.T) {
	// The ASA sends ifIndex but no ifDescr, confirmed live.
	payload := `[{"oid":".1.3.6.1.2.1.2.2.1.1.3","type":"Integer","value":3}]`
	if got := extractInterface(payload); got != "ifIndex 3" {
		t.Errorf("expected 'ifIndex 3', got %q", got)
	}
}

func TestExtractInterfaceEmptyPayload(t *testing.T) {
	if got := extractInterface(`[]`); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}
