package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fuad/network-monitor/internal/store"
)

func repoTemplatePath(t *testing.T) string {
	t.Helper()
	// telegraf.conf.tmpl lives at the repo root's telegraf/ dir; tests run with
	// cwd set to this package's directory.
	path := filepath.Join("..", "telegraf", "telegraf.conf.tmpl")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("template not found at %s: %v", path, err)
	}
	return path
}

func TestRenderTelegrafConfigV2c(t *testing.T) {
	key := testKey(t)
	encCommunity, err := key.Encrypt("public")
	if err != nil {
		t.Fatal(err)
	}

	devices := []*store.Device{
		{ID: 1, IPAddress: "192.168.1.1", SNMPVersion: "v2c", Community: encCommunity},
	}

	rendered, err := renderTelegrafConfig(repoTemplatePath(t), 60, "http://influxdb:8181", "tok", "network_monitor", devices, key)
	if err != nil {
		t.Fatalf("renderTelegrafConfig: %v", err)
	}

	for _, want := range []string{
		`interval = "60s"`,
		`urls = ["http://influxdb:8181"]`,
		`token = "tok"`,
		`bucket = "network_monitor"`,
		`agents = ["udp://192.168.1.1:161"]`,
		"version = 2",
		`community = "public"`,
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered config missing %q\n---\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, encCommunity) {
		t.Fatal("rendered config must contain the decrypted community, not ciphertext")
	}
}

func TestRenderTelegrafConfigV3(t *testing.T) {
	key := testKey(t)
	encAuth, _ := key.Encrypt("authpass123")
	encPriv, _ := key.Encrypt("privpass123")

	devices := []*store.Device{
		{
			ID: 2, IPAddress: "192.168.1.2", SNMPVersion: "v3",
			V3User: "monitor", V3AuthKey: encAuth, V3PrivKey: encPriv,
			V3AuthProtocol: "SHA", V3PrivProtocol: "AES",
		},
	}

	rendered, err := renderTelegrafConfig(repoTemplatePath(t), 30, "http://influxdb:8181", "tok", "network_monitor", devices, key)
	if err != nil {
		t.Fatalf("renderTelegrafConfig: %v", err)
	}

	for _, want := range []string{
		"version = 3",
		`sec_name = "monitor"`,
		`sec_level = "authPriv"`,
		`auth_protocol = "SHA"`,
		`auth_password = "authpass123"`,
		`priv_protocol = "AES"`,
		`priv_password = "privpass123"`,
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered config missing %q\n---\n%s", want, rendered)
		}
	}
}

func TestRenderTelegrafConfigNoDevices(t *testing.T) {
	key := testKey(t)
	rendered, err := renderTelegrafConfig(repoTemplatePath(t), 60, "http://influxdb:8181", "tok", "network_monitor", nil, key)
	if err != nil {
		t.Fatalf("renderTelegrafConfig: %v", err)
	}
	if strings.Contains(rendered, "[[inputs.snmp]]") {
		t.Fatal("expected no inputs.snmp blocks with zero devices")
	}
	if !strings.Contains(rendered, "[[outputs.influxdb_v2]]") {
		t.Fatal("expected outputs block even with zero devices")
	}
}

func TestVersionNumber(t *testing.T) {
	cases := map[string]int{"v1": 1, "v2c": 2, "v3": 3, "": 2, "garbage": 2}
	for in, want := range cases {
		if got := versionNumber(in); got != want {
			t.Errorf("versionNumber(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestV3SecLevel(t *testing.T) {
	cases := []struct {
		authKey, privKey, want string
	}{
		{"", "", "noAuthNoPriv"},
		{"auth", "", "authNoPriv"},
		{"auth", "priv", "authPriv"},
		{"", "priv", "authPriv"}, // priv implies auth in practice; we don't second-guess the caller
	}
	for _, c := range cases {
		if got := v3SecLevel(c.authKey, c.privKey); got != c.want {
			t.Errorf("v3SecLevel(%q, %q) = %q, want %q", c.authKey, c.privKey, got, c.want)
		}
	}
}

func TestWriteIfChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telegraf.conf")

	changed, err := writeIfChanged(path, "content-v1")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected change writing to a non-existent file")
	}

	changed, err = writeIfChanged(path, "content-v1")
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("expected no change writing identical content")
	}

	changed, err = writeIfChanged(path, "content-v2")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected change writing different content")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "content-v2" {
		t.Fatalf("expected file to contain latest content, got %q", got)
	}
}
