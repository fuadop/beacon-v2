package handlers

import (
	"errors"
	"net/http"
)

// CollectorHandler serves the collector's own address as reachable by
// monitored devices (e.g. for configuring SNMP trap destinations). This
// can't be auto-detected from inside a container, so it's just config
// (COLLECTOR_IP) passed through.
type CollectorHandler struct {
	IP string
}

func (h *CollectorHandler) Get(w http.ResponseWriter, r *http.Request) {
	if h.IP == "" {
		writeError(w, http.StatusInternalServerError, errors.New("COLLECTOR_IP is not configured"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ip": h.IP})
}
