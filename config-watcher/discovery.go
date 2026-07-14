package main

import (
	"log/slog"
	"time"

	"github.com/jackpal/gateway"

	"github.com/fuad/network-monitor/internal/crypto"
	"github.com/fuad/network-monitor/internal/netutil"
	"github.com/fuad/network-monitor/internal/snmp"
	"github.com/fuad/network-monitor/internal/store"
)

const probeTimeout = 2 * time.Second

// discoverGatewayDevice finds the host's default gateway and ensures a devices
// row exists for it, probing default SNMP credentials the first time the row is
// created. Idempotent: safe to call on every startup (plan §6 Phase 2).
func discoverGatewayDevice(logger *slog.Logger, devices *store.DeviceStore, key *crypto.Key) {
	gw, err := gateway.DiscoverGateway()
	if err != nil {
		logger.Warn("gateway detection failed", "error", err)
		return
	}
	ip := gw.String()

	if _, err := devices.GetByIP(ip); err == nil {
		logger.Info("gateway device already tracked", "ip", ip)
		return
	} else if err != store.ErrNotFound {
		logger.Error("looking up gateway device", "error", err)
		return
	}

	d := &store.Device{
		IPAddress:     ip,
		Status:        "pending",
		IsPublicIP:    netutil.IsPublic(ip),
		DiscoveredVia: "gateway",
	}
	id, err := devices.Create(d)
	if err != nil {
		logger.Error("creating gateway device row", "error", err, "ip", ip)
		return
	}
	logger.Info("discovered default gateway", "ip", ip, "id", id)

	probeAndUpdate(logger, devices, key, id, ip)
}

// probeAndUpdate tries default v1/v2c communities against ip and moves the device
// to "active" (with the working credential recorded, encrypted) or "failed" so the
// user can supply credentials manually via the dashboard.
func probeAndUpdate(logger *slog.Logger, devices *store.DeviceStore, key *crypto.Key, id int64, ip string) {
	creds, err := snmp.ProbeDefaults(ip, probeTimeout)
	if err != nil {
		logger.Info("snmp probe failed, leaving device for user-supplied credentials", "ip", ip)
		if uerr := devices.Update(id, map[string]any{"status": "failed"}); uerr != nil {
			logger.Error("updating device status", "error", uerr, "id", id)
		}
		return
	}

	encryptedCommunity, err := key.Encrypt(creds.Community)
	if err != nil {
		logger.Error("encrypting probed community", "error", err, "id", id)
		return
	}

	if err := devices.Update(id, map[string]any{
		"snmp_version": creds.Version,
		"community":    encryptedCommunity,
		"status":       "active",
	}); err != nil {
		logger.Error("updating device after successful probe", "error", err, "id", id)
		return
	}
	logger.Info("snmp probe succeeded", "ip", ip, "version", creds.Version)
}
