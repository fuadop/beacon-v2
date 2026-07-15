package main

import (
	"encoding/hex"
	"encoding/json"
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
		}
		if _, err := traps.Insert(t); err != nil {
			logger.Error("storing trap", "error", err, "source", addr.IP.String())
			return
		}
		logger.Info("received trap", "source", addr.IP.String(), "oid", oid)
	}
}

// extractTrapOID finds the trap's identifying OID: for v1 traps that's the
// enterprise OID carried in the packet header, for v2c/v3 it's the value of the
// snmpTrapOID.0 varbind.
func extractTrapOID(packet *gosnmp.SnmpPacket) string {
	if packet.Version == gosnmp.Version1 {
		return strings.TrimSuffix(packet.Enterprise, ".")
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
