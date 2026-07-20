package handlers

import (
	"net/http"
	"strconv"

	"github.com/fuad/network-monitor/internal/snmp"
	"github.com/fuad/network-monitor/internal/store"
)

type TrapsHandler struct {
	Store *store.TrapStore
}

// ReadableTrap mirrors store.Trap with an added Name field, e.g. "LinkDown"
// instead of just ".1.3.6.1.6.3.1.1.5.3".
type ReadableTrap struct {
	ID         int64
	SourceIP   string
	OID        string
	Name       string
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

// ListReadable is List with a Name field added ("LinkDown", "ConfigChanged",
// etc.), translated from OID via snmp.TrapName. Unrecognized OIDs fall back
// to the raw OID as their Name rather than being hidden or mislabeled.
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
			Payload:    t.Payload,
			ReceivedAt: t.ReceivedAt,
		}
	}
	writeJSON(w, http.StatusOK, readable)
}
