package snmp

import (
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
)

// ipRouteNextHop (RFC1213-MIB ipRouteTable) is deprecated in favor of
// inetCidrRouteTable, but remains the most broadly supported column across
// routers/switches of varying age — exactly the devices this sweep targets.
const ipRouteNextHopOID = ".1.3.6.1.2.1.4.21.1.7"

// WalkRouteNextHops walks a device's IP routing table and returns the distinct,
// non-zero next-hop IPs referenced in it — i.e. neighboring routers this device
// knows about, which are the candidates for the routing-table discovery sweep
// (plan §6 Phase 4).
func WalkRouteNextHops(ip string, creds Credentials, timeout time.Duration) ([]string, error) {
	client, err := buildClient(ip, creds, timeout)
	if err != nil {
		return nil, err
	}
	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("snmp: connecting to %s: %w", ip, err)
	}
	defer client.Close()

	seen := make(map[string]bool)
	var hops []string
	walkErr := client.Walk(ipRouteNextHopOID, func(pdu gosnmp.SnmpPDU) error {
		hop, ok := pdu.Value.(string)
		if !ok || hop == "" || hop == "0.0.0.0" {
			return nil
		}
		if !seen[hop] {
			seen[hop] = true
			hops = append(hops, hop)
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("snmp: walking route table on %s: %w", ip, walkErr)
	}
	return hops, nil
}
