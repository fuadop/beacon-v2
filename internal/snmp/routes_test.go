package snmp

import (
	"testing"
	"time"
)

func TestWalkRouteNextHopsUnreachableHostFails(t *testing.T) {
	_, err := WalkRouteNextHops(unreachableIP, Credentials{Version: "v2c", Community: "public"}, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected error walking route table of an unreachable host")
	}
}
