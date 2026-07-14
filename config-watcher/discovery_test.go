package main

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/fuad/network-monitor/internal/crypto"
	"github.com/fuad/network-monitor/internal/store"
)

// 192.0.2.0/24 is TEST-NET-1 (RFC 5737), reserved for documentation — guaranteed
// to never have a live SNMP agent, so probes against it fail deterministically
// and quickly without needing real network access.
const unreachableIP = "192.0.2.1"

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testKey(t *testing.T) *crypto.Key {
	t.Helper()
	raw := make([]byte, 32)
	rand.Read(raw)
	k, err := crypto.NewKey(hex.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestProbeAndUpdateMarksFailedWhenUnreachable(t *testing.T) {
	db, err := store.OpenConfigDB(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	devices := store.NewDeviceStore(db)

	id, err := devices.Create(&store.Device{IPAddress: unreachableIP, DiscoveredVia: "gateway"})
	if err != nil {
		t.Fatal(err)
	}

	probeAndUpdate(testLogger(), devices, testKey(t), id, unreachableIP)

	got, err := devices.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "failed" {
		t.Fatalf("expected status 'failed', got %q", got.Status)
	}
}
