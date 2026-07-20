package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/fuad/network-monitor/config-api/handlers"
	"github.com/fuad/network-monitor/internal/crypto"
	"github.com/fuad/network-monitor/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	dbPath := envOrDefault("CONFIG_DB_PATH", "/data/config.db")
	db, err := store.OpenConfigDB(dbPath)
	if err != nil {
		logger.Error("opening config db", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	trapsDBPath := envOrDefault("TRAPS_DB_PATH", "/data/traps.db")
	trapsDB, err := store.OpenTrapsDB(trapsDBPath)
	if err != nil {
		logger.Error("opening traps db", "error", err)
		os.Exit(1)
	}
	defer trapsDB.Close()

	key, err := crypto.NewKey(os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		logger.Error("loading encryption key", "error", err)
		os.Exit(1)
	}

	collectorIP := os.Getenv("COLLECTOR_IP")

	deviceHandler := &handlers.DeviceHandler{Store: store.NewDeviceStore(db), Key: key}
	settingsHandler := &handlers.SettingsHandler{Store: store.NewSettingsStore(db)}
	trapsHandler := &handlers.TrapsHandler{Store: store.NewTrapStore(trapsDB)}
	collectorHandler := &handlers.CollectorHandler{IP: collectorIP}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /devices", deviceHandler.List)
	mux.HandleFunc("POST /devices", deviceHandler.Create)
	mux.HandleFunc("GET /devices/{id}", deviceHandler.Get)
	mux.HandleFunc("PATCH /devices/{id}", deviceHandler.Update)
	mux.HandleFunc("DELETE /devices/{id}", deviceHandler.Delete)
	mux.HandleFunc("GET /settings/polling-interval", settingsHandler.GetPollingInterval)
	mux.HandleFunc("POST /settings/polling-interval", settingsHandler.SetPollingInterval)
	mux.HandleFunc("GET /settings/credential-duplication", settingsHandler.GetCredentialDuplication)
	mux.HandleFunc("POST /settings/credential-duplication", settingsHandler.SetCredentialDuplication)
	mux.HandleFunc("GET /traps", trapsHandler.List)
	mux.HandleFunc("GET /traps/readable", trapsHandler.ListReadable)
	mux.HandleFunc("GET /collector-ip", collectorHandler.Get)

	addr := ":8080"
	logger.Info("config-api listening", "addr", addr, "db", dbPath)
	if err := http.ListenAndServe(addr, requestLogger(logger, withCORS(mux))); err != nil {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// withCORS lets the Grafana Business Forms panels call this API directly from
// the browser. Those panels issue plain fetch() calls from the user's browser
// rather than going through Grafana's backend proxy (unlike the Infinity/InfluxDB
// datasource queries), so without CORS headers here the browser blocks every
// response — this isn't optional plumbing, the dashboard doesn't work without it.
// Wide open by design: this API has no auth of its own and is meant to sit
// behind the operator's own network boundary, same as Grafana itself.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
