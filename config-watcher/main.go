package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/fuad/network-monitor/internal/crypto"
	"github.com/fuad/network-monitor/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info("config-watcher starting")

	dbPath := envOrDefault("CONFIG_DB_PATH", "/data/config.db")
	db, err := store.OpenConfigDB(dbPath)
	if err != nil {
		logger.Error("opening config db", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	key, err := crypto.NewKey(os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		logger.Error("loading encryption key", "error", err)
		os.Exit(1)
	}

	devices := store.NewDeviceStore(db)

	discoverGatewayDevice(logger, devices, key)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	logger.Info("config-watcher shutting down")
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
