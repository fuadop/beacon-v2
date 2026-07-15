package handlers

import (
	"net/http"
	"strconv"

	"github.com/fuad/network-monitor/internal/store"
)

type TrapsHandler struct {
	Store *store.TrapStore
}

// List returns the most recent traps, newest first. Accepts an optional
// ?limit= query param (default 100) for the Grafana Infinity datasource panel.
func (h *TrapsHandler) List(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	traps, err := h.Store.List(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, traps)
}
