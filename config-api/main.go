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

	deviceHandler := &handlers.DeviceHandler{Store: store.NewDeviceStore(db), Key: key}
	settingsHandler := &handlers.SettingsHandler{Store: store.NewSettingsStore(db)}
	trapsHandler := &handlers.TrapsHandler{Store: store.NewTrapStore(trapsDB)}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /devices", deviceHandler.List)
	mux.HandleFunc("POST /devices", deviceHandler.Create)
	mux.HandleFunc("GET /devices/{id}", deviceHandler.Get)
	mux.HandleFunc("PATCH /devices/{id}", deviceHandler.Update)
	mux.HandleFunc("GET /settings/polling-interval", settingsHandler.GetPollingInterval)
	mux.HandleFunc("POST /settings/polling-interval", settingsHandler.SetPollingInterval)
	mux.HandleFunc("GET /settings/credential-duplication", settingsHandler.GetCredentialDuplication)
	mux.HandleFunc("POST /settings/credential-duplication", settingsHandler.SetCredentialDuplication)
	mux.HandleFunc("GET /traps", trapsHandler.List)

	addr := ":8080"
	logger.Info("config-api listening", "addr", addr, "db", dbPath)
	if err := http.ListenAndServe(addr, requestLogger(logger, mux)); err != nil {
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
