package main

import (
	"path/filepath"
	"testing"

	"github.com/fuad/network-monitor/internal/snmp"
	"github.com/fuad/network-monitor/internal/store"
)

func newTestDeviceStore(t *testing.T) *store.DeviceStore {
	t.Helper()
	db, err := store.OpenConfigDB(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return store.NewDeviceStore(db)
}

func TestShouldConsiderDiscoveredIPRejectsPublicIP(t *testing.T) {
	devices := newTestDeviceStore(t)
	if shouldConsiderDiscoveredIP(devices, testLogger(), "8.8.8.8", "192.168.1.1") {
		t.Fatal("expected public IP to be rejected")
	}
}

func TestShouldConsiderDiscoveredIPRejectsParentIP(t *testing.T) {
	devices := newTestDeviceStore(t)
	if shouldConsiderDiscoveredIP(devices, testLogger(), "192.168.1.1", "192.168.1.1") {
		t.Fatal("expected parent's own IP to be rejected")
	}
}

func TestShouldConsiderDiscoveredIPRejectsAlreadyTracked(t *testing.T) {
	devices := newTestDeviceStore(t)
	if _, err := devices.Create(&store.Device{IPAddress: "192.168.1.5"}); err != nil {
		t.Fatal(err)
	}
	if shouldConsiderDiscoveredIP(devices, testLogger(), "192.168.1.5", "192.168.1.1") {
		t.Fatal("expected already-tracked IP to be rejected")
	}
}

func TestShouldConsiderDiscoveredIPAcceptsNewPrivateIP(t *testing.T) {
	devices := newTestDeviceStore(t)
	if !shouldConsiderDiscoveredIP(devices, testLogger(), "192.168.1.5", "192.168.1.1") {
		t.Fatal("expected new private IP to be accepted")
	}
}

func TestInsertDiscoveredDeviceWithoutDuplicationStaysPending(t *testing.T) {
	devices := newTestDeviceStore(t)
	key := testKey(t)

	ok := insertDiscoveredDevice(testLogger(), devices, key, "192.168.1.5", snmp.Credentials{}, false)
	if !ok {
		t.Fatal("expected insert to succeed")
	}

	d, err := devices.GetByIP("192.168.1.5")
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "pending" {
		t.Fatalf("expected status pending when duplication disabled, got %q", d.Status)
	}
	if d.DiscoveredVia != "routing_table_sweep" {
		t.Fatalf("expected discovered_via routing_table_sweep, got %q", d.DiscoveredVia)
	}
	if d.Community != "" {
		t.Fatal("expected no credentials attached when duplication is disabled")
	}
}

func TestInsertDiscoveredDeviceWithDuplicationFailsForUnreachableIP(t *testing.T) {
	devices := newTestDeviceStore(t)
	key := testKey(t)

	parentCreds := snmp.Credentials{Version: "v2c", Community: "public"}
	ok := insertDiscoveredDevice(testLogger(), devices, key, unreachableIP, parentCreds, true)
	if !ok {
		t.Fatal("expected insert to succeed even when the credential-reuse probe fails")
	}

	d, err := devices.GetByIP(unreachableIP)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "failed" {
		t.Fatalf("expected status failed when reuse probe can't reach the device, got %q", d.Status)
	}
	if d.Community == "" {
		t.Fatal("expected the attempted (encrypted) credential to still be recorded for UI display context")
	}
	decrypted, err := key.Decrypt(d.Community)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != "public" {
		t.Fatalf("expected attempted community 'public', got %q", decrypted)
	}
}

func TestDecryptCredentialsRoundTrip(t *testing.T) {
	key := testKey(t)
	encCommunity, _ := key.Encrypt("public")
	encAuth, _ := key.Encrypt("authpass")
	encPriv, _ := key.Encrypt("privpass")

	d := &store.Device{
		SNMPVersion: "v3", Community: encCommunity, V3User: "monitor",
		V3AuthKey: encAuth, V3PrivKey: encPriv, V3AuthProtocol: "SHA", V3PrivProtocol: "AES",
	}

	creds, err := decryptCredentials(d, key)
	if err != nil {
		t.Fatal(err)
	}
	if creds.Community != "public" || creds.V3AuthKey != "authpass" || creds.V3PrivKey != "privpass" {
		t.Fatalf("unexpected decrypted credentials: %+v", creds)
	}
}
