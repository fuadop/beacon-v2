package main

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/fuad/network-monitor/internal/crypto"
	"github.com/fuad/network-monitor/internal/store"
)

type deviceTemplateData struct {
	IPAddress      string
	VersionNumber  int
	Community      string
	V3User         string
	V3SecLevel     string
	V3AuthProtocol string
	V3AuthPassword string
	V3PrivProtocol string
	V3PrivPassword string
}

type telegrafTemplateData struct {
	PollingIntervalSeconds int
	InfluxURL              string
	InfluxToken            string
	InfluxDatabase         string
	Devices                []deviceTemplateData
}

// buildDeviceConfigs decrypts each active device's credentials (already-decrypted
// values never touch disk — they exist only in the rendered telegraf.conf, which
// lives on a Docker volume Telegraf and config-watcher share) and shapes them for
// the telegraf.conf.tmpl template.
func buildDeviceConfigs(devices []*store.Device, key *crypto.Key) ([]deviceTemplateData, error) {
	out := make([]deviceTemplateData, 0, len(devices))
	for _, d := range devices {
		community, err := key.Decrypt(d.Community)
		if err != nil {
			return nil, fmt.Errorf("telegraf_gen: decrypting community for device %d: %w", d.ID, err)
		}
		authKey, err := key.Decrypt(d.V3AuthKey)
		if err != nil {
			return nil, fmt.Errorf("telegraf_gen: decrypting v3 auth key for device %d: %w", d.ID, err)
		}
		privKey, err := key.Decrypt(d.V3PrivKey)
		if err != nil {
			return nil, fmt.Errorf("telegraf_gen: decrypting v3 priv key for device %d: %w", d.ID, err)
		}

		out = append(out, deviceTemplateData{
			IPAddress:      d.IPAddress,
			VersionNumber:  versionNumber(d.SNMPVersion),
			Community:      community,
			V3User:         d.V3User,
			V3SecLevel:     v3SecLevel(authKey, privKey),
			V3AuthProtocol: d.V3AuthProtocol,
			V3AuthPassword: authKey,
			V3PrivProtocol: d.V3PrivProtocol,
			V3PrivPassword: privKey,
		})
	}
	return out, nil
}

func versionNumber(snmpVersion string) int {
	switch snmpVersion {
	case "v1":
		return 1
	case "v3":
		return 3
	default: // "v2c" and unset both default to v2c
		return 2
	}
}

func v3SecLevel(authKey, privKey string) string {
	switch {
	case privKey != "":
		return "authPriv"
	case authKey != "":
		return "authNoPriv"
	default:
		return "noAuthNoPriv"
	}
}

// renderTelegrafConfig executes the telegraf.conf.tmpl template at tmplPath against
// the currently-active devices and settings, returning the rendered TOML.
func renderTelegrafConfig(tmplPath string, pollingIntervalSeconds int, influxURL, influxToken, influxDatabase string, devices []*store.Device, key *crypto.Key) (string, error) {
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		return "", fmt.Errorf("telegraf_gen: parsing template %s: %w", tmplPath, err)
	}

	deviceConfigs, err := buildDeviceConfigs(devices, key)
	if err != nil {
		return "", err
	}

	data := telegrafTemplateData{
		PollingIntervalSeconds: pollingIntervalSeconds,
		InfluxURL:              influxURL,
		InfluxToken:            influxToken,
		InfluxDatabase:         influxDatabase,
		Devices:                deviceConfigs,
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("telegraf_gen: executing template: %w", err)
	}
	return buf.String(), nil
}

// writeIfChanged writes content to path only if it differs from the file's
// current contents, returning whether a write happened. Avoiding unnecessary
// writes means we only reload Telegraf when something actually changed.
func writeIfChanged(path, content string) (bool, error) {
	existing, err := os.ReadFile(path)
	if err == nil && string(existing) == content {
		return false, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("telegraf_gen: reading existing config %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return false, fmt.Errorf("telegraf_gen: writing config %s: %w", path, err)
	}
	return true, nil
}
