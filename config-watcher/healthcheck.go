package main

import (
	"log/slog"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/fuad/network-monitor/internal/crypto"
	"github.com/fuad/network-monitor/internal/snmp"
	"github.com/fuad/network-monitor/internal/store"
)

const healthCheckTimeout = 3 * time.Second

// checkDeviceHealth pings and SNMP-probes every device with credentials on
// file -- not just the ones currently "active" -- so a device that recovers
// (e.g. a router reboots, or someone fixes its SNMP config) gets picked back
// up automatically rather than staying stuck "failed" until someone manually
// edits it.
//
// SNMP is authoritative for the stored status: it's the thing that actually
// determines whether Telegraf can collect from this device, which is what
// the status is for (reconcileTelegrafConfig only includes "active" devices
// in telegraf.conf -- this loop and that one are the two halves of the same
// feedback loop). Ping runs too and is logged, but never overrides the SNMP
// result: ICMP is commonly blocked by firewalls even when SNMP works fine,
// and treating a blocked ping as "device down" would produce false failures
// on a device that's actually being monitored correctly.
func checkDeviceHealth(logger *slog.Logger, devices *store.DeviceStore, key *crypto.Key) {
	all, err := devices.List()
	if err != nil {
		logger.Error("listing devices for health check", "error", err)
		return
	}

	for _, d := range all {
		if d.SNMPVersion == "" {
			// No credentials configured yet (e.g. a routing-table-sweep
			// discovery that skipped credential duplication) -- nothing to
			// check yet.
			continue
		}

		pingOK := pingHost(d.IPAddress, healthCheckTimeout)

		creds, err := decryptCredentials(d, key)
		if err != nil {
			logger.Error("decrypting credentials for health check", "error", err, "device_id", d.ID)
			continue
		}
		snmpOK := snmp.Verify(d.IPAddress, creds, healthCheckTimeout) == nil

		newStatus := "failed"
		if snmpOK {
			newStatus = "active"
		}
		if newStatus == d.Status {
			continue
		}

		if err := devices.Update(d.ID, map[string]any{"status": newStatus}); err != nil {
			logger.Error("updating device status", "error", err, "device_id", d.ID)
			continue
		}
		logger.Info("device health check changed status", "device_id", d.ID, "ip", d.IPAddress,
			"old_status", d.Status, "new_status", newStatus, "ping_ok", pingOK, "snmp_ok", snmpOK)
	}
}

// pingHost sends a single ICMP echo request and reports whether a reply came
// back in time. Best-effort/diagnostic only (see checkDeviceHealth) -- never
// the sole basis for a status change, so failures here are logged at debug
// level rather than treated as an error.
func pingHost(ip string, timeout time.Duration) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		// Typically means the container lost CAP_NET_RAW -- not fatal, SNMP
		// alone still drives status.
		return false
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("beacon-v2-healthcheck"),
		},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	if _, err := conn.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(ip)}); err != nil {
		return false
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}
	rb := make([]byte, 512)
	n, _, err := conn.ReadFrom(rb)
	if err != nil {
		return false
	}

	reply, err := icmp.ParseMessage(1, rb[:n]) // protocol 1 = ICMP
	if err != nil {
		return false
	}
	return reply.Type == ipv4.ICMPTypeEchoReply
}
