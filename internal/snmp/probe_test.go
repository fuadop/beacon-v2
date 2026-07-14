package snmp

import (
	"testing"
	"time"
)

// 192.0.2.0/24 is TEST-NET-1 (RFC 5737), reserved for documentation and
// guaranteed to never have a live SNMP agent — used here to exercise the
// no-response path quickly and deterministically without a real network.
const unreachableIP = "192.0.2.1"

func TestVerifyUnsupportedVersionFailsFast(t *testing.T) {
	err := Verify("127.0.0.1", Credentials{Version: "v4"}, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestVerifyUnreachableHostTimesOut(t *testing.T) {
	err := Verify(unreachableIP, Credentials{Version: "v2c", Community: "public"}, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected error against an unreachable host")
	}
}

func TestProbeDefaultsReturnsErrProbeFailedWhenUnreachable(t *testing.T) {
	_, err := ProbeDefaults(unreachableIP, 100*time.Millisecond)
	if err != ErrProbeFailed {
		t.Fatalf("expected ErrProbeFailed, got %v", err)
	}
}

func TestBuildClientRejectsUnknownV3AuthProtocol(t *testing.T) {
	_, err := buildClient(unreachableIP, Credentials{
		Version:        "v3",
		V3User:         "user",
		V3AuthKey:      "authpass",
		V3AuthProtocol: "NOT-A-PROTOCOL",
	}, time.Second)
	if err == nil {
		t.Fatal("expected error for unknown auth protocol")
	}
}

func TestBuildClientRejectsUnknownV3PrivProtocol(t *testing.T) {
	_, err := buildClient(unreachableIP, Credentials{
		Version:        "v3",
		V3User:         "user",
		V3PrivKey:      "privpass",
		V3PrivProtocol: "NOT-A-PROTOCOL",
	}, time.Second)
	if err == nil {
		t.Fatal("expected error for unknown privacy protocol")
	}
}

func TestBuildClientAcceptsValidV1V2c(t *testing.T) {
	for _, v := range []string{"v1", "v2c"} {
		if _, err := buildClient(unreachableIP, Credentials{Version: v, Community: "public"}, time.Second); err != nil {
			t.Errorf("buildClient(%q) unexpected error: %v", v, err)
		}
	}
}
