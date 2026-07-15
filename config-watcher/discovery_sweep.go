package main

import (
	"log/slog"
	"time"

	"github.com/fuad/network-monitor/internal/crypto"
	"github.com/fuad/network-monitor/internal/netutil"
	"github.com/fuad/network-monitor/internal/snmp"
	"github.com/fuad/network-monitor/internal/store"
)

const routeSweepTimeout = 3 * time.Second

// maxNewDevicesPerSweep rate-limits how many new devices a single sweep run can
// insert, so a misbehaving or very large routing table can't flood the devices
// table in one pass (plan §7 rate-limiting requirement).
const maxNewDevicesPerSweep = 10

// runDiscoverySweep walks the routing table of every active device looking for
// private-IP neighbors not already tracked. Credential reuse against newly found
// IPs only happens if credential_duplication_enabled is set (plan §4.5: opt-in,
// never default, never for public IPs).
func runDiscoverySweep(logger *slog.Logger, devices *store.DeviceStore, settings *store.SettingsStore, key *crypto.Key) {
	dupEnabled, err := settings.Get("credential_duplication_enabled")
	if err != nil {
		logger.Error("reading credential_duplication_enabled setting", "error", err)
		return
	}

	activeDevices, err := devices.ListByStatus("active")
	if err != nil {
		logger.Error("listing active devices for discovery sweep", "error", err)
		return
	}

	newCount := 0
	for _, parent := range activeDevices {
		if newCount >= maxNewDevicesPerSweep {
			logger.Info("discovery sweep hit per-run device cap, stopping early", "cap", maxNewDevicesPerSweep)
			return
		}

		parentCreds, err := decryptCredentials(parent, key)
		if err != nil {
			logger.Error("decrypting parent credentials", "error", err, "device_id", parent.ID)
			continue
		}

		hops, err := snmp.WalkRouteNextHops(parent.IPAddress, parentCreds, routeSweepTimeout)
		if err != nil {
			logger.Warn("routing table walk failed", "error", err, "device_id", parent.ID, "ip", parent.IPAddress)
			continue
		}

		for _, hopIP := range hops {
			if newCount >= maxNewDevicesPerSweep {
				break
			}
			if !shouldConsiderDiscoveredIP(devices, logger, hopIP, parent.IPAddress) {
				continue
			}
			if insertDiscoveredDevice(logger, devices, key, hopIP, parentCreds, dupEnabled == "1") {
				newCount++
			}
		}
	}
}

func shouldConsiderDiscoveredIP(devices *store.DeviceStore, logger *slog.Logger, ip, parentIP string) bool {
	if ip == parentIP {
		return false
	}
	if netutil.IsPublic(ip) {
		return false // never auto-discover public IPs (plan §4.5)
	}
	if _, err := devices.GetByIP(ip); err == nil {
		return false // already tracked
	} else if err != store.ErrNotFound {
		logger.Error("looking up discovered device", "error", err, "ip", ip)
		return false
	}
	return true
}

func decryptCredentials(d *store.Device, key *crypto.Key) (snmp.Credentials, error) {
	community, err := key.Decrypt(d.Community)
	if err != nil {
		return snmp.Credentials{}, err
	}
	authKey, err := key.Decrypt(d.V3AuthKey)
	if err != nil {
		return snmp.Credentials{}, err
	}
	privKey, err := key.Decrypt(d.V3PrivKey)
	if err != nil {
		return snmp.Credentials{}, err
	}
	return snmp.Credentials{
		Version:        d.SNMPVersion,
		Community:      community,
		V3User:         d.V3User,
		V3AuthKey:      authKey,
		V3PrivKey:      privKey,
		V3AuthProtocol: d.V3AuthProtocol,
		V3PrivProtocol: d.V3PrivProtocol,
	}, nil
}

// insertDiscoveredDevice creates a row for a newly-seen, private-IP device. When
// credential duplication is enabled it tries the parent's credentials first: success
// moves the device straight to active, failure records it as failed with the
// attempted (not necessarily working, for this device) credentials attached so the
// dashboard can show "this is what we tried" — the API never returns them in
// plaintext regardless (config-api/handlers/devices.go masks all credential fields).
func insertDiscoveredDevice(logger *slog.Logger, devices *store.DeviceStore, key *crypto.Key, ip string, parentCreds snmp.Credentials, dupEnabled bool) bool {
	d := &store.Device{
		IPAddress:     ip,
		IsPublicIP:    false, // caller already filtered to private IPs
		DiscoveredVia: "routing_table_sweep",
		Status:        "pending",
	}

	if dupEnabled {
		encCommunity, err := key.Encrypt(parentCreds.Community)
		if err != nil {
			logger.Error("encrypting attempted community", "error", err, "ip", ip)
		} else {
			d.SNMPVersion = parentCreds.Version
			d.Community = encCommunity
		}
		if err := snmp.Verify(ip, parentCreds, routeSweepTimeout); err == nil {
			d.Status = "active"
		} else {
			d.Status = "failed"
		}
	}

	id, err := devices.Create(d)
	if err != nil {
		logger.Error("creating discovered device", "error", err, "ip", ip)
		return false
	}
	logger.Info("discovered new device via routing table sweep", "ip", ip, "id", id, "status", d.Status)
	return true
}
