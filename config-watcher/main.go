package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

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
	settings := store.NewSettingsStore(db)

	cfg := watcherConfig{
		templatePath:   envOrDefault("TELEGRAF_TEMPLATE_PATH", "/telegraf.conf.tmpl"),
		configPath:     envOrDefault("TELEGRAF_CONF_PATH", "/etc/telegraf/telegraf.conf"),
		containerName:  envOrDefault("TELEGRAF_CONTAINER_NAME", "telegraf"),
		influxURL:      envOrDefault("INFLUXDB_URL", "http://influxdb:8181"),
		influxToken:    os.Getenv("INFLUXDB_TOKEN"),
		influxDatabase: envOrDefault("INFLUXDB_DATABASE", "network_monitor"),
	}

	pollSeconds, err := strconv.Atoi(envOrDefault("CONFIG_WATCHER_POLL_SECONDS", "10"))
	if err != nil || pollSeconds <= 0 {
		logger.Warn("invalid CONFIG_WATCHER_POLL_SECONDS, defaulting to 10", "error", err)
		pollSeconds = 10
	}

	sweepSeconds, err := strconv.Atoi(envOrDefault("DISCOVERY_SWEEP_INTERVAL_SECONDS", "300"))
	if err != nil || sweepSeconds <= 0 {
		logger.Warn("invalid DISCOVERY_SWEEP_INTERVAL_SECONDS, defaulting to 300", "error", err)
		sweepSeconds = 300
	}

	discoverGatewayDevice(logger, devices, key)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Reconcile once immediately on startup, then on every tick.
	reconcileTelegrafConfig(logger, devices, settings, key, cfg)

	reconcileTicker := time.NewTicker(time.Duration(pollSeconds) * time.Second)
	defer reconcileTicker.Stop()

	// The routing-table sweep runs on its own, much slower cadence: it makes
	// live SNMP walks against every active device, so ticking it as fast as the
	// config reconcile loop would hammer devices for no benefit.
	sweepTicker := time.NewTicker(time.Duration(sweepSeconds) * time.Second)
	defer sweepTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("config-watcher shutting down")
			return
		case <-reconcileTicker.C:
			reconcileTelegrafConfig(logger, devices, settings, key, cfg)
		case <-sweepTicker.C:
			runDiscoverySweep(logger, devices, settings, key)
		}
	}
}

type watcherConfig struct {
	templatePath   string
	configPath     string
	containerName  string
	influxURL      string
	influxToken    string
	influxDatabase string
}

// reconcileTelegrafConfig regenerates telegraf.conf from the current set of
// active devices and the polling-interval setting, reloading Telegraf only if
// the rendered config actually changed (plan §6 Phase 3).
func reconcileTelegrafConfig(logger *slog.Logger, devices *store.DeviceStore, settings *store.SettingsStore, key *crypto.Key, cfg watcherConfig) {
	pollingIntervalStr, err := settings.Get("polling_interval_seconds")
	if err != nil {
		logger.Error("reading polling interval setting", "error", err)
		return
	}
	pollingInterval, err := strconv.Atoi(pollingIntervalStr)
	if err != nil {
		logger.Error("parsing polling interval setting", "error", err, "value", pollingIntervalStr)
		return
	}

	activeDevices, err := devices.ListByStatus("active")
	if err != nil {
		logger.Error("listing active devices", "error", err)
		return
	}

	rendered, err := renderTelegrafConfig(cfg.templatePath, pollingInterval, cfg.influxURL, cfg.influxToken, cfg.influxDatabase, activeDevices, key)
	if err != nil {
		logger.Error("rendering telegraf config", "error", err)
		return
	}

	changed, err := writeIfChanged(cfg.configPath, rendered)
	if err != nil {
		logger.Error("writing telegraf config", "error", err)
		return
	}
	if !changed {
		return
	}

	logger.Info("telegraf config changed, reloading", "active_devices", len(activeDevices), "polling_interval_seconds", pollingInterval)
	if err := reloadTelegraf(cfg.containerName); err != nil {
		logger.Error("reloading telegraf", "error", err)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
