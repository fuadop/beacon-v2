// Package snmp wraps gosnmp for the credential "probing" this project does:
// trying default v1/v2c communities and verifying explicitly-supplied v3
// credentials. This is not true SNMP version detection — see plan §4.6.
package snmp

import (
	"errors"
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
)

// sysDescr0 is used as the cheapest possible read to confirm a credential set
// actually works against a device.
const sysDescr0 = "1.3.6.1.2.1.1.1.0"

var ErrProbeFailed = errors.New("snmp: no working credentials found")

// defaultCommunities are tried in order for devices with no credentials on file
// yet (e.g. a freshly discovered gateway). These are the well-known SNMP
// factory defaults, not a security control.
var defaultCommunities = []struct {
	version   gosnmp.SnmpVersion
	community string
}{
	{gosnmp.Version2c, "public"},
	{gosnmp.Version2c, "private"},
	{gosnmp.Version1, "public"},
}

// Credentials describes what's needed to attempt an SNMP read, mirroring the
// relevant subset of store.Device fields in plaintext (already decrypted by the caller).
type Credentials struct {
	Version        string // "v1", "v2c", "v3"
	Community      string
	V3User         string
	V3AuthKey      string
	V3PrivKey      string
	V3AuthProtocol string // MD5, SHA
	V3PrivProtocol string // DES, AES
}

// Verify attempts a single SNMP GET of sysDescr.0 against ip using creds,
// returning nil if the device responds, or an error describing why it didn't.
func Verify(ip string, creds Credentials, timeout time.Duration) error {
	client, err := buildClient(ip, creds, timeout)
	if err != nil {
		return err
	}
	if err := client.Connect(); err != nil {
		return fmt.Errorf("snmp: connecting to %s: %w", ip, err)
	}
	defer client.Close()

	if _, err := client.Get([]string{sysDescr0}); err != nil {
		return fmt.Errorf("snmp: get sysDescr from %s: %w", ip, err)
	}
	return nil
}

// ProbeDefaults tries the well-known v1/v2c default communities against ip and
// returns the first working set of Credentials. It never attempts v3 — there is
// no meaningful "default" v3 user/auth/priv combination, so v3 devices must have
// credentials supplied by the user (plan §4.6).
func ProbeDefaults(ip string, timeout time.Duration) (*Credentials, error) {
	for _, d := range defaultCommunities {
		versionStr := "v2c"
		if d.version == gosnmp.Version1 {
			versionStr = "v1"
		}
		creds := Credentials{Version: versionStr, Community: d.community}
		if err := Verify(ip, creds, timeout); err == nil {
			return &creds, nil
		}
	}
	return nil, ErrProbeFailed
}

func buildClient(ip string, creds Credentials, timeout time.Duration) (*gosnmp.GoSNMP, error) {
	client := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Timeout:   timeout,
		Retries:   1,
		Transport: "udp",
	}

	switch creds.Version {
	case "v1":
		client.Version = gosnmp.Version1
		client.Community = creds.Community
	case "v2c":
		client.Version = gosnmp.Version2c
		client.Community = creds.Community
	case "v3":
		authProto, err := parseAuthProtocol(creds.V3AuthProtocol)
		if err != nil {
			return nil, err
		}
		privProto, err := parsePrivProtocol(creds.V3PrivProtocol)
		if err != nil {
			return nil, err
		}
		client.Version = gosnmp.Version3
		client.SecurityModel = gosnmp.UserSecurityModel
		msgFlags := gosnmp.NoAuthNoPriv
		if creds.V3AuthKey != "" {
			msgFlags = gosnmp.AuthNoPriv
		}
		if creds.V3PrivKey != "" {
			msgFlags = gosnmp.AuthPriv
		}
		client.MsgFlags = msgFlags
		client.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 creds.V3User,
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: creds.V3AuthKey,
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        creds.V3PrivKey,
			// AuthoritativeEngineID left empty: gosnmp performs USM engine-ID
			// discovery automatically on Connect() when it's unset.
		}
	default:
		return nil, fmt.Errorf("snmp: unsupported version %q", creds.Version)
	}

	return client, nil
}

func parseAuthProtocol(s string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch s {
	case "", "NoAuth":
		return gosnmp.NoAuth, nil
	case "MD5":
		return gosnmp.MD5, nil
	case "SHA":
		return gosnmp.SHA, nil
	default:
		return 0, fmt.Errorf("snmp: unsupported auth protocol %q", s)
	}
}

func parsePrivProtocol(s string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch s {
	case "", "NoPriv":
		return gosnmp.NoPriv, nil
	case "DES":
		return gosnmp.DES, nil
	case "AES":
		return gosnmp.AES, nil
	default:
		return 0, fmt.Errorf("snmp: unsupported privacy protocol %q", s)
	}
}
