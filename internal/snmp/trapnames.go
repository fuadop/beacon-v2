package snmp

import "strings"

// trapNames maps well-known trap/notification OIDs to human-readable names.
// Standard entries are RFC 3418 (SNMPv2-MIB) traps, universally supported.
// Cisco entries are sourced from CISCO-CONFIG-MAN-MIB (github.com/cisco/cisco-mibs,
// v2/CISCO-CONFIG-MAN-MIB.my): ciscoConfigManMIB = ciscoMgmt.43, notifications
// live under ciscoConfigManMIBNotificationPrefix (ciscoConfigManMIB.2.0).
var trapNames = map[string]string{
	".1.3.6.1.6.3.1.1.5.1": "ColdStart",
	".1.3.6.1.6.3.1.1.5.2": "WarmStart",
	".1.3.6.1.6.3.1.1.5.3": "LinkDown",
	".1.3.6.1.6.3.1.1.5.4": "LinkUp",
	".1.3.6.1.6.3.1.1.5.5": "AuthenticationFailure",
	".1.3.6.1.6.3.1.1.5.6": "EgpNeighborLoss",

	".1.3.6.1.4.1.9.9.43.2.0.1": "ConfigManEvent",
	".1.3.6.1.4.1.9.9.43.2.0.2": "ConfigChanged",
	".1.3.6.1.4.1.9.9.43.2.0.3": "ConfigCTIDRolledOver",
}

// TrapName returns the human-readable name for a trap OID, e.g. "LinkDown"
// for ".1.3.6.1.6.3.1.1.5.3". Falls back to the OID itself (unchanged) when
// unrecognized, rather than hiding or guessing at unknown traps.
func TrapName(oid string) string {
	normalized := oid
	if !strings.HasPrefix(normalized, ".") {
		normalized = "." + normalized
	}
	normalized = strings.TrimSuffix(normalized, ".")

	if name, ok := trapNames[normalized]; ok {
		return name
	}
	return oid
}
