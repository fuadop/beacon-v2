package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// readableTrap mirrors config-api's handlers.ReadableTrap JSON shape
// (config-api/handlers/traps.go), returned by GET /traps/readable.
type readableTrap struct {
	ID         int64  `json:"ID"`
	SourceIP   string `json:"SourceIP"`
	OID        string `json:"OID"`
	Name       string `json:"Name"`
	ReceivedAt string `json:"ReceivedAt"`
}

// device mirrors config-api's deviceResponse JSON shape (config-api/handlers/devices.go).
// Only the fields useful for device identification/description are kept --
// chat-api never touches credential fields, which config-api never returns
// in the first place.
//
// Note: sysLocation/sysContact (e.g. "Toronto Data Center, Rack 1Ab") are
// NOT included here -- that data isn't currently stored anywhere (not in
// the devices table, not in InfluxDB). Fetching it would mean either giving
// chat-api SNMP-credential-decrypt access (which would widen this service's
// trust boundary the same way the earlier trap-receiver/community-string
// discussion in this project deliberately avoided), or adding it to
// config-api's probe path and devices table. Left as a follow-up rather
// than silently implemented against either of those options.
type device struct {
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
	Status    string `json:"status"`
	GroupName string `json:"group_name"`
}

type configAPIClient struct {
	baseURL string
	http    *http.Client
}

func newConfigAPIClient(baseURL string) *configAPIClient {
	return &configAPIClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		http:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *configAPIClient) listDevices() ([]device, error) {
	resp, err := c.http.Get(c.baseURL + "/devices")
	if err != nil {
		return nil, fmt.Errorf("calling config-api: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config-api returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var devices []device
	if err := json.Unmarshal(body, &devices); err != nil {
		return nil, fmt.Errorf("decoding config-api response: %w", err)
	}
	return devices, nil
}

// getRecentTraps fetches recent traps from config-api and filters to the
// last `hours`. Filtering happens here rather than via a query param because
// GET /traps/readable only supports ?limit=, not a time range -- trap
// volume in this project is low enough that fetching a generous limit and
// filtering client-side is simpler than adding a new config-api parameter
// for this alone.
func (c *configAPIClient) getRecentTraps(hours float64) ([]readableTrap, error) {
	resp, err := c.http.Get(c.baseURL + "/traps/readable?limit=500")
	if err != nil {
		return nil, fmt.Errorf("calling config-api: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config-api returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var traps []readableTrap
	if err := json.Unmarshal(body, &traps); err != nil {
		return nil, fmt.Errorf("decoding config-api response: %w", err)
	}

	cutoff := time.Now().Add(-time.Duration(hours * float64(time.Hour)))
	var recent []readableTrap
	for _, t := range traps {
		receivedAt, err := time.Parse(time.RFC3339, t.ReceivedAt)
		if err != nil || receivedAt.After(cutoff) {
			recent = append(recent, t)
		}
	}
	return recent, nil
}

// resolveDevice matches a user-supplied device reference (a hostname, a
// hostname prefix like "R1", or a raw IP) against the known device list,
// returning the device's real IP (agent_host in InfluxDB) -- which is what
// query_metric/rank_devices actually filter on, never the caller's string
// directly. This is the injection defense for the "device" tool parameter:
// whatever the model passes, the only thing that reaches SQL is an IP that
// was already in config-api's device list.
func resolveDevice(devices []device, ref string) (device, error) {
	ref = strings.TrimSpace(ref)
	lower := strings.ToLower(ref)

	for _, d := range devices {
		if d.IPAddress == ref {
			return d, nil
		}
	}
	for _, d := range devices {
		if strings.EqualFold(d.Hostname, ref) {
			return d, nil
		}
	}
	// Prefix match, e.g. "R1" against "R1.compnet.torontomu.ca".
	var matches []device
	for _, d := range devices {
		if strings.HasPrefix(strings.ToLower(d.Hostname), lower) {
			matches = append(matches, d)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return device{}, fmt.Errorf("%q matches more than one device, be more specific", ref)
	}
	return device{}, fmt.Errorf("no known device matches %q -- call list_devices to see what's monitored", ref)
}
