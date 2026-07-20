package snmp

import "testing"

func TestTrapName(t *testing.T) {
	cases := []struct {
		oid  string
		want string
	}{
		{".1.3.6.1.6.3.1.1.5.3", "LinkDown"},
		{"1.3.6.1.6.3.1.1.5.4", "LinkUp"},      // no leading dot
		{".1.3.6.1.6.3.1.1.5.1.", "ColdStart"}, // trailing dot
		{".1.3.6.1.4.1.9.9.43.2.0.2", "ConfigChanged"},
		{".1.2.3.4.5.6", ".1.2.3.4.5.6"}, // unknown: falls back to raw OID
	}
	for _, c := range cases {
		if got := TrapName(c.oid); got != c.want {
			t.Errorf("TrapName(%q) = %q, want %q", c.oid, got, c.want)
		}
	}
}
