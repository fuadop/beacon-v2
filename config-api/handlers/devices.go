package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/fuad/network-monitor/internal/crypto"
	"github.com/fuad/network-monitor/internal/netutil"
	"github.com/fuad/network-monitor/internal/snmp"
	"github.com/fuad/network-monitor/internal/store"
)

// defaultProbeTimeout bounds how long Create/Update block waiting on an SNMP
// probe. Only the gateway-discovery flow (config-watcher) sets device status
// in the background; devices added or edited through this API get probed
// synchronously with the credentials actually supplied so the dashboard shows
// active/failed immediately instead of leaving devices stuck at "pending"
// forever with no way to reach "active" from the UI.
const defaultProbeTimeout = 3 * time.Second

type DeviceHandler struct {
	Store        *store.DeviceStore
	Key          *crypto.Key
	ProbeTimeout time.Duration
}

func (h *DeviceHandler) probeTimeout() time.Duration {
	if h.ProbeTimeout > 0 {
		return h.ProbeTimeout
	}
	return defaultProbeTimeout
}

// probeStatus attempts an SNMP read using creds and returns "active" or
// "failed". If creds has no SNMP version set, there's nothing to probe yet and
// the device stays "pending".
func (h *DeviceHandler) probeStatus(ip string, creds snmp.Credentials) string {
	if creds.Version == "" {
		return "pending"
	}
	if err := snmp.Verify(ip, creds, h.probeTimeout()); err != nil {
		return "failed"
	}
	return "active"
}

// deviceResponse is the wire representation returned to the browser. Credential
// fields are never included in plaintext or ciphertext — only whether they're set —
// per plan §4.4/§7.1 (never render credentials back to the browser).
type deviceResponse struct {
	ID             int64  `json:"id"`
	IPAddress      string `json:"ip_address"`
	Hostname       string `json:"hostname"`
	SNMPVersion    string `json:"snmp_version"`
	HasCommunity   bool   `json:"has_community"`
	V3User         string `json:"v3_user,omitempty"`
	HasV3AuthKey   bool   `json:"has_v3_auth_key"`
	HasV3PrivKey   bool   `json:"has_v3_priv_key"`
	V3AuthProtocol string `json:"v3_auth_protocol,omitempty"`
	V3PrivProtocol string `json:"v3_priv_protocol,omitempty"`
	GroupName      string `json:"group_name,omitempty"`
	Status         string `json:"status"`
	IsPublicIP     bool   `json:"is_public_ip"`
	DiscoveredVia  string `json:"discovered_via,omitempty"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

func toDeviceResponse(d *store.Device) deviceResponse {
	return deviceResponse{
		ID:             d.ID,
		IPAddress:      d.IPAddress,
		Hostname:       d.Hostname,
		SNMPVersion:    d.SNMPVersion,
		HasCommunity:   d.Community != "",
		V3User:         d.V3User,
		HasV3AuthKey:   d.V3AuthKey != "",
		HasV3PrivKey:   d.V3PrivKey != "",
		V3AuthProtocol: d.V3AuthProtocol,
		V3PrivProtocol: d.V3PrivProtocol,
		GroupName:      d.GroupName,
		Status:         d.Status,
		IsPublicIP:     d.IsPublicIP,
		DiscoveredVia:  d.DiscoveredVia,
		CreatedAt:      d.CreatedAt,
		UpdatedAt:      d.UpdatedAt,
	}
}

// deviceRequest is the shape accepted from the Business Forms panel for both
// create and update. Credential fields are plaintext on the wire (over the
// operator's own LAN, from the dashboard to the config API) and encrypted
// immediately before touching storage.
type deviceRequest struct {
	IPAddress      string `json:"ip_address"`
	Hostname       string `json:"hostname"`
	SNMPVersion    string `json:"snmp_version"`
	Community      string `json:"community"`
	V3User         string `json:"v3_user"`
	V3AuthKey      string `json:"v3_auth_key"`
	V3PrivKey      string `json:"v3_priv_key"`
	V3AuthProtocol string `json:"v3_auth_protocol"`
	V3PrivProtocol string `json:"v3_priv_protocol"`
	GroupName      string `json:"group_name"`
	Status         string `json:"status"`
}

func (h *DeviceHandler) List(w http.ResponseWriter, r *http.Request) {
	devices, err := h.Store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	resp := make([]deviceResponse, 0, len(devices))
	for _, d := range devices {
		resp = append(resp, toDeviceResponse(d))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *DeviceHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid device id"))
		return
	}
	d, err := h.Store.Get(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, toDeviceResponse(d))
}

func (h *DeviceHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req deviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.IPAddress == "" {
		writeError(w, http.StatusBadRequest, errors.New("ip_address is required"))
		return
	}

	community, err := h.Key.Encrypt(req.Community)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	authKey, err := h.Key.Encrypt(req.V3AuthKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	privKey, err := h.Key.Encrypt(req.V3PrivKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	status := h.probeStatus(req.IPAddress, snmp.Credentials{
		Version:        req.SNMPVersion,
		Community:      req.Community,
		V3User:         req.V3User,
		V3AuthKey:      req.V3AuthKey,
		V3PrivKey:      req.V3PrivKey,
		V3AuthProtocol: req.V3AuthProtocol,
		V3PrivProtocol: req.V3PrivProtocol,
	})

	d := &store.Device{
		IPAddress:      req.IPAddress,
		Hostname:       req.Hostname,
		SNMPVersion:    req.SNMPVersion,
		Community:      community,
		V3User:         req.V3User,
		V3AuthKey:      authKey,
		V3PrivKey:      privKey,
		V3AuthProtocol: req.V3AuthProtocol,
		V3PrivProtocol: req.V3PrivProtocol,
		GroupName:      req.GroupName,
		Status:         status,
		// is_public_ip is derived server-side, never trusted from the client.
		IsPublicIP:    netutil.IsPublic(req.IPAddress),
		DiscoveredVia: "manual",
	}

	id, err := h.Store.Create(d)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Re-fetch rather than trust the in-memory d: created_at/updated_at are set by
	// SQLite's DEFAULT CURRENT_TIMESTAMP, not by this process.
	created, err := h.Store.Get(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, toDeviceResponse(created))
}

func (h *DeviceHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid device id"))
		return
	}

	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	updates := map[string]any{}
	for jsonKey, column := range map[string]string{
		"hostname":         "hostname",
		"snmp_version":     "snmp_version",
		"v3_user":          "v3_user",
		"v3_auth_protocol": "v3_auth_protocol",
		"v3_priv_protocol": "v3_priv_protocol",
		"group_name":       "group_name",
		"status":           "status",
	} {
		if v, ok := req[jsonKey]; ok {
			updates[column] = v
		}
	}
	for jsonKey, column := range map[string]string{
		"community":   "community",
		"v3_auth_key": "v3_auth_key",
		"v3_priv_key": "v3_priv_key",
	} {
		if v, ok := req[jsonKey]; ok {
			plaintext, _ := v.(string)
			encrypted, err := h.Key.Encrypt(plaintext)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			updates[column] = encrypted
		}
	}

	if err := h.Store.Update(id, updates); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	d, err := h.Store.Get(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Re-probe with the resulting credentials whenever the caller touched
	// SNMP-relevant fields and didn't explicitly set status themselves — same
	// reasoning as Create: this is the only path by which a device edited
	// through the dashboard can move to "active" or "failed".
	if snmpFieldsChanged(req) {
		if _, explicitStatus := req["status"]; !explicitStatus {
			community, err := h.Key.Decrypt(d.Community)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			authKey, err := h.Key.Decrypt(d.V3AuthKey)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			privKey, err := h.Key.Decrypt(d.V3PrivKey)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			status := h.probeStatus(d.IPAddress, snmp.Credentials{
				Version:        d.SNMPVersion,
				Community:      community,
				V3User:         d.V3User,
				V3AuthKey:      authKey,
				V3PrivKey:      privKey,
				V3AuthProtocol: d.V3AuthProtocol,
				V3PrivProtocol: d.V3PrivProtocol,
			})
			if err := h.Store.Update(id, map[string]any{"status": status}); err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			d.Status = status
		}
	}

	writeJSON(w, http.StatusOK, toDeviceResponse(d))
}

func (h *DeviceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid device id"))
		return
	}

	if err := h.Store.Delete(id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func snmpFieldsChanged(req map[string]any) bool {
	for _, key := range []string{"snmp_version", "community", "v3_user", "v3_auth_key", "v3_priv_key", "v3_auth_protocol", "v3_priv_protocol"} {
		if _, ok := req[key]; ok {
			return true
		}
	}
	return false
}
