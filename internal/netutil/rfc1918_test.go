package netutil

import "testing"

func TestIsPrivate(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.1":       true,
		"10.255.255.255": true,
		"172.16.0.1":     true,
		"172.31.255.255": true,
		"192.168.1.1":    true,
		"127.0.0.1":      true,
		"8.8.8.8":        false,
		"1.1.1.1":        false,
		"172.32.0.1":     false, // just outside 172.16.0.0/12
		"not-an-ip":      false,
	}
	for ip, want := range cases {
		if got := IsPrivate(ip); got != want {
			t.Errorf("IsPrivate(%q) = %v, want %v", ip, got, want)
		}
		if got := IsPublic(ip); got != !want {
			t.Errorf("IsPublic(%q) = %v, want %v", ip, got, !want)
		}
	}
}
