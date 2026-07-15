package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"github.com/gosnmp/gosnmp"

	"github.com/fuad/network-monitor/internal/store"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestTrapStore(t *testing.T) *store.TrapStore {
	t.Helper()
	db, err := store.OpenTrapsDB(filepath.Join(t.TempDir(), "traps.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return store.NewTrapStore(db)
}

func TestTrapHandlerStoresV2cTrap(t *testing.T) {
	traps := newTestTrapStore(t)
	handler := newTrapHandler(testLogger(), traps)

	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		Variables: []gosnmp.SnmpPDU{
			{Name: snmpTrapOID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"}, // linkDown
			{Name: ".1.3.6.1.2.1.2.2.1.1", Type: gosnmp.Integer, Value: 2},
			{Name: ".1.3.6.1.2.1.1.5.0", Type: gosnmp.OctetString, Value: []byte("router1")},
		},
	}
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1")}

	handler(packet, addr)

	stored, err := traps.List(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored trap, got %d", len(stored))
	}
	got := stored[0]
	if got.SourceIP != "192.168.1.1" {
		t.Errorf("expected source_ip 192.168.1.1, got %q", got.SourceIP)
	}
	if got.OID != ".1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("expected oid linkDown, got %q", got.OID)
	}

	var payload []varbind
	if err := json.Unmarshal([]byte(got.Payload), &payload); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if len(payload) != 3 {
		t.Fatalf("expected 3 varbinds in payload, got %d", len(payload))
	}
	// The OctetString varbind should decode as a readable string, not base64 bytes.
	if payload[2].Value != "router1" {
		t.Errorf("expected decoded OctetString value 'router1', got %v", payload[2].Value)
	}
}

func TestTrapHandlerStoresV1Trap(t *testing.T) {
	traps := newTestTrapStore(t)
	handler := newTrapHandler(testLogger(), traps)

	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version1,
		SnmpTrap: gosnmp.SnmpTrap{
			Enterprise:   ".1.3.6.1.4.1.9",
			GenericTrap:  3,
			SpecificTrap: 0,
		},
	}
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1")}

	handler(packet, addr)

	stored, err := traps.List(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored trap, got %d", len(stored))
	}
	if stored[0].OID != ".1.3.6.1.4.1.9" {
		t.Errorf("expected enterprise OID as trap oid, got %q", stored[0].OID)
	}
}

func TestExtractTrapOIDMissingVarbindReturnsEmpty(t *testing.T) {
	packet := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Variables: nil}
	if got := extractTrapOID(packet); got != "" {
		t.Errorf("expected empty oid, got %q", got)
	}
}

func TestNormalizeValuePrintableBytes(t *testing.T) {
	got := normalizeValue([]byte("hello"))
	if got != "hello" {
		t.Errorf("expected 'hello', got %v", got)
	}
}

func TestNormalizeValueNonPrintableBytesBecomeHex(t *testing.T) {
	got := normalizeValue([]byte{0xff, 0xfe, 0x00, 0x01})
	if got != "fffe0001" {
		t.Errorf("expected hex-encoded string, got %v", got)
	}
}

func TestNormalizeValuePassesThroughOtherTypes(t *testing.T) {
	if got := normalizeValue(42); got != 42 {
		t.Errorf("expected 42, got %v", got)
	}
}
