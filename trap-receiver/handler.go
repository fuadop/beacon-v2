package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/fuad/network-monitor/internal/store"
)

// snmpTrapOID is snmpTrapOID.0 (SNMPv2-MIB): for v2c/v3 traps, the varbind at
// this OID carries the actual trap-type OID, which is what we record as the
// trap's identity.
const snmpTrapOID = ".1.3.6.1.6.3.1.1.4.1.0"

type varbind struct {
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}

// newTrapHandler builds a gosnmp.TrapHandlerFunc that stores every received
// trap/inform as a row in the traps table (plan §6 Phase 5). SNMP v1/v2c traps
// have no meaningful authentication, so this accepts and records traps from any
// source without validating the community string — see the threat-model notes
// added in Phase 7.
func newTrapHandler(logger *slog.Logger, traps *store.TrapStore) gosnmp.TrapHandlerFunc {
	return func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		oid := extractTrapOID(packet)
		payload, err := encodeVarbinds(packet.Variables)
		if err != nil {
			logger.Error("encoding trap varbinds", "error", err, "source", addr.IP.String())
			return
		}

		t := &store.Trap{
			SourceIP: addr.IP.String(),
			OID:      oid,
			Payload:  payload,
			// Community is on every v1/v2c packet, but only v1 also carries
			// AgentAddress -- the sending device's own real IP, embedded in the
			// PDU itself rather than the UDP header, which is what lets
			// config-api attribute a trap correctly even when something between
			// the device and here (Docker's own port-publishing, in this
			// deployment's case) rewrites the packet's actual source IP.
			Community: packet.Community,
		}
		if packet.Version == gosnmp.Version1 {
			t.AgentAddress = packet.AgentAddress
		}
		if _, err := traps.Insert(t); err != nil {
			logger.Error("storing trap", "error", err, "source", addr.IP.String())
			return
		}
		logger.Info("received trap", "source", addr.IP.String(), "oid", oid, "agent_address", t.AgentAddress)
	}
}

// genericTrapOID maps SNMPv1's generic-trap integer (0-5; RFC 1157) to the same
// specific SNMPv2-MIB OID a v2c/v3 device would send for the same event --
// keeping v1 traps identifiable by internal/snmp.TrapName the same way v2c/v3
// ones are, rather than collapsing every v1 trap to the bare enterprise OID.
var genericTrapOID = map[int]string{
	0: ".1.3.6.1.6.3.1.1.5.1", // coldStart
	1: ".1.3.6.1.6.3.1.1.5.2", // warmStart
	2: ".1.3.6.1.6.3.1.1.5.3", // linkDown
	3: ".1.3.6.1.6.3.1.1.5.4", // linkUp
	4: ".1.3.6.1.6.3.1.1.5.5", // authenticationFailure
	5: ".1.3.6.1.6.3.1.1.5.6", // egpNeighborLoss
}

// extractTrapOID finds the trap's identifying OID. For v2c/v3 that's the value
// of the snmpTrapOID.0 varbind. v1 has no such varbind -- the generic-trap
// integer identifies one of the six standard types above, or 6
// ("enterpriseSpecific") meaning the real identity is the vendor's own
// enterprise OID plus its specific-trap number (e.g. a Cisco ASA's traps).
func extractTrapOID(packet *gosnmp.SnmpPacket) string {
	if packet.Version == gosnmp.Version1 {
		if oid, ok := genericTrapOID[packet.GenericTrap]; ok {
			return oid
		}
		enterprise := strings.TrimSuffix(packet.Enterprise, ".")
		return fmt.Sprintf("%s.%d", enterprise, packet.SpecificTrap)
	}
	for _, v := range packet.Variables {
		if v.Name == snmpTrapOID {
			if s, ok := v.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

func encodeVarbinds(vars []gosnmp.SnmpPDU) (string, error) {
	out := make([]varbind, 0, len(vars))
	for _, v := range vars {
		out = append(out, varbind{
			OID:   v.Name,
			Type:  v.Type.String(),
			Value: normalizeValue(v.Value),
		})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// normalizeValue makes SNMP PDU values JSON-friendly. encoding/json base64-encodes
// []byte by default, which is unreadable for OctetString varbinds — prefer the
// UTF-8 string when the bytes are valid text, falling back to hex otherwise.
func normalizeValue(v any) any {
	if b, ok := v.([]byte); ok {
		if utf8.Valid(b) {
			return string(b)
		}
		return hex.EncodeToString(b)
	}
	return v
}
