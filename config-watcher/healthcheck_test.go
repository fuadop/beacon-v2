package main

import (
	"testing"
	"time"

	"github.com/fuad/network-monitor/internal/store"
)

func TestCheckDeviceHealthSkipsDeviceWithNoCredentials(t *testing.T) {
	devices := newTestDeviceStore(t)
	id, err := devices.Create(&store.Device{IPAddress: unreachableIP, Status: "pending"})
	if err != nil {
		t.Fatal(err)
	}

	checkDeviceHealth(testLogger(), devices, testKey(t))

	got, err := devices.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "pending" {
		t.Fatalf("expected status untouched ('pending'), got %q", got.Status)
	}
}

func TestCheckDeviceHealthMarksUnreachableDeviceFailed(t *testing.T) {
	devices := newTestDeviceStore(t)
	key := testKey(t)
	encCommunity, err := key.Encrypt("public")
	if err != nil {
		t.Fatal(err)
	}
	id, err := devices.Create(&store.Device{
		IPAddress: unreachableIP, SNMPVersion: "v2c", Community: encCommunity, Status: "active",
	})
	if err != nil {
		t.Fatal(err)
	}

	checkDeviceHealth(testLogger(), devices, key)

	got, err := devices.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "failed" {
		t.Fatalf("expected status 'failed' for an unreachable device, got %q", got.Status)
	}
}

func TestCheckDeviceHealthLeavesAlreadyFailedDeviceAlone(t *testing.T) {
	devices := newTestDeviceStore(t)
	key := testKey(t)
	encCommunity, _ := key.Encrypt("public")
	id, err := devices.Create(&store.Device{
		IPAddress: unreachableIP, SNMPVersion: "v2c", Community: encCommunity, Status: "failed",
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := devices.Get(id)
	if err != nil {
		t.Fatal(err)
	}

	checkDeviceHealth(testLogger(), devices, key)

	after, err := devices.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != "failed" {
		t.Fatalf("expected status to remain 'failed', got %q", after.Status)
	}
	if after.UpdatedAt != before.UpdatedAt {
		t.Error("expected no write (and so no updated_at bump) when status doesn't actually change")
	}
}

func TestPingHostUnreachableReturnsFalseWithinTimeout(t *testing.T) {
	start := time.Now()
	ok := pingHost(unreachableIP, 200*time.Millisecond)
	elapsed := time.Since(start)

	if ok {
		t.Error("expected ping to a TEST-NET-1 address to fail")
	}
	if elapsed > time.Second {
		t.Errorf("pingHost took %s, expected it to respect the timeout", elapsed)
	}
}
