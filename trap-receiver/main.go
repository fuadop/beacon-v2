package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/gosnmp/gosnmp"

	"github.com/fuad/network-monitor/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info("trap-receiver starting")

	dbPath := envOrDefault("TRAPS_DB_PATH", "/data/traps.db")
	db, err := store.OpenTrapsDB(dbPath)
	if err != nil {
		logger.Error("opening traps db", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	traps := store.NewTrapStore(db)

	listener := gosnmp.NewTrapListener()
	listener.OnNewTrap = newTrapHandler(logger, traps)
	listener.Params = gosnmp.Default

	listenAddr := envOrDefault("TRAP_LISTEN_ADDR", "0.0.0.0:162")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		logger.Info("trap-receiver shutting down")
		listener.Close()
	}()

	logger.Info("trap-receiver listening", "addr", listenAddr, "db", dbPath)
	if err := listener.Listen(listenAddr); err != nil {
		logger.Error("trap listener exited", "error", err)
		os.Exit(1)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
