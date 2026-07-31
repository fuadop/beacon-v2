package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/fuad/network-monitor/internal/crypto"
	"github.com/fuad/network-monitor/internal/snmp"
	"github.com/fuad/network-monitor/internal/store"
)

type TrapsHandler struct {
	Store   *store.TrapStore
	Devices *store.DeviceStore
	Key     *crypto.Key
}

// ReadableTrap mirrors store.Trap with Name/Device/Interface added: Name is
// "LinkDown" etc. (translated from OID), Device is the resolved hostname
// ("R2") when identifiable, and Interface is pulled out of the trap's own
// payload. Device/Interface are best-effort and left empty rather than guessed
// when there isn't enough information to resolve them confidently.
type ReadableTrap struct {
	ID         int64
	SourceIP   string
	OID        string
	Name       string
	Device     string
	Interface  string
	Payload    string
	ReceivedAt string
}

func limitFromQuery(r *http.Request) int {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	return limit
}

// List returns the most recent traps, newest first. Accepts an optional
// ?limit= query param (default 100) for the Grafana Infinity datasource panel.
func (h *TrapsHandler) List(w http.ResponseWriter, r *http.Request) {
	traps, err := h.Store.List(limitFromQuery(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, traps)
}

// ListReadable is List with Name/Device/Interface added -- see ReadableTrap.
// Unrecognized OIDs fall back to the raw OID as their Name rather than being
// hidden or mislabeled.
func (h *TrapsHandler) ListReadable(w http.ResponseWriter, r *http.Request) {
	traps, err := h.Store.List(limitFromQuery(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	readable := make([]ReadableTrap, len(traps))
	for i, t := range traps {
		readable[i] = ReadableTrap{
			ID:         t.ID,
			SourceIP:   t.SourceIP,
			OID:        t.OID,
			Name:       snmp.TrapName(t.OID),
			Device:     h.resolveDevice(t.AgentAddress, t.Community),
			Interface:  extractInterface(t.Payload),
			Payload:    t.Payload,
			ReceivedAt: t.ReceivedAt,
		}
	}
	writeJSON(w, http.StatusOK, readable)
}

// resolveDevice identifies which registered device sent a trap. AgentAddress
// (SNMPv1 only) is tried first, matched against devices.ip_address -- this is
// a real per-device IP for most of the fleet, immune to whatever rewrites the
// UDP packet's own source IP in transit. When that doesn't match any known
// device -- e.g. a Cisco ASA stamping its internal failover-link address
// rather than a real routable IP, confirmed live in this deployment -- fall
// back to comparing the trap's community string against each device's own
// decrypted community, since every device here has been given its own unique
// one specifically for trap forwarding. Returns "" rather than guessing when
// neither matches.
func (h *TrapsHandler) resolveDevice(agentAddress, community string) string {
	if h.Devices == nil {
		return ""
	}
	if agentAddress != "" {
		if d, err := h.Devices.GetByIP(agentAddress); err == nil {
			return d.Hostname
		}
	}
	if community == "" || h.Key == nil {
		return ""
	}
	devices, err := h.Devices.List()
	if err != nil {
		return ""
	}
	for _, d := range devices {
		if d.Community == "" {
			continue
		}
		plain, err := h.Key.Decrypt(d.Community)
		if err != nil || plain == "" {
			continue
		}
		if plain == community {
			return d.Hostname
		}
	}
	return ""
}

// trapVarbind is the shape trap-receiver encodes each payload varbind as
// (see trap-receiver/handler.go's varbind type).
type trapVarbind struct {
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}

// ifDescrPrefix and ifIndexPrefix are IF-MIB ifTable column OIDs (RFC 2863):
// ifIndex.<n> and ifDescr.<n>, indexed by interface. Every LinkDown/LinkUp
// trap in this project's telegraf.conf.tmpl-configured devices carries both.
const (
	ifDescrPrefix = ".1.3.6.1.2.1.2.2.1.2."
	ifIndexPrefix = ".1.3.6.1.2.1.2.2.1.1."
)

// extractInterface pulls the interface name (ifDescr, e.g. "GigabitEthernet0/1")
// out of a trap's already-stored payload -- this data has been captured since
// trap-receiver started, just never surfaced before. Falls back to "ifIndex N"
// for devices that don't send ifDescr in their traps (the Cisco ASA sends only
// a numeric ifIndex, confirmed live), and "" when neither is present.
func extractInterface(payload string) string {
	var vars []trapVarbind
	if err := json.Unmarshal([]byte(payload), &vars); err != nil {
		return ""
	}
	var ifIndex string
	for _, v := range vars {
		switch {
		case strings.HasPrefix(v.OID, ifDescrPrefix):
			if s, ok := v.Value.(string); ok && s != "" {
				return s
			}
		case strings.HasPrefix(v.OID, ifIndexPrefix):
			ifIndex = fmt.Sprint(v.Value)
		}
	}
	if ifIndex != "" {
		return "ifIndex " + ifIndex
	}
	return ""
}
