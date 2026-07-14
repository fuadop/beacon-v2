package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/fuad/network-monitor/internal/store"
)

const pollingIntervalKey = "polling_interval_seconds"

// allowedPollingIntervals matches the dropdown options specified in plan §6 Phase 6
// (30s, 1min, 2min, 5min, 10min) — rejecting anything else keeps a typo in the form
// from generating a Telegraf config that hammers devices every second.
var allowedPollingIntervals = map[int]bool{
	30: true, 60: true, 120: true, 300: true, 600: true,
}

type SettingsHandler struct {
	Store *store.SettingsStore
}

func (h *SettingsHandler) GetPollingInterval(w http.ResponseWriter, r *http.Request) {
	value, err := h.Store.Get(pollingIntervalKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	seconds, err := strconv.Atoi(value)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"polling_interval_seconds": seconds})
}

func (h *SettingsHandler) SetPollingInterval(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PollingIntervalSeconds int `json:"polling_interval_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !allowedPollingIntervals[req.PollingIntervalSeconds] {
		writeError(w, http.StatusBadRequest, errors.New("polling_interval_seconds must be one of 30, 60, 120, 300, 600"))
		return
	}
	if err := h.Store.Set(pollingIntervalKey, strconv.Itoa(req.PollingIntervalSeconds)); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"polling_interval_seconds": req.PollingIntervalSeconds})
}
