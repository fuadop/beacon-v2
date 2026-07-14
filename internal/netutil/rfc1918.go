// Package netutil provides the shared public/private IP classification used to
// gate credential auto-duplication and unsolicited discovery (see plan §4.5, §9.3).
package netutil

import "net"

var privateBlocks = mustParseCIDRs(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8", // loopback, never a real discovery target but never "public" either
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		nets = append(nets, n)
	}
	return nets
}

// IsPrivate reports whether ip falls in an RFC1918 private range. Unparseable
// input is treated as not-private (i.e. safest to classify as public).
func IsPrivate(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range privateBlocks {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// IsPublic is the negation of IsPrivate, kept as a named helper for readability
// at call sites that gate on "is this a public IP" (credential duplication, discovery).
func IsPublic(ip string) bool {
	return !IsPrivate(ip)
}
