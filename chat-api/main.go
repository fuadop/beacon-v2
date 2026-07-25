package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info("chat-api starting")

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		logger.Error("ANTHROPIC_API_KEY is not set")
		os.Exit(1)
	}

	influxURL := envOrDefault("INFLUXDB_URL", "http://influxdb:8181")
	influxToken := os.Getenv("INFLUXDB_TOKEN")
	influxDatabase := envOrDefault("INFLUXDB_DATABASE", "network_monitor")
	configAPIURL := envOrDefault("CONFIG_API_URL", "http://config-api:8080")

	tc := toolContext{
		influx:    newInfluxClient(influxURL, influxToken, influxDatabase),
		configAPI: newConfigAPIClient(configAPIURL),
	}

	handler := &chatHandler{
		anthropic:   newAnthropicClient(apiKey),
		tools:       tc,
		rateLimiter: newRateLimiter(10, time.Minute),
		logger:      logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /chat", handler.handle)

	addr := ":8082"
	logger.Info("chat-api listening", "addr", addr)
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

// withCORS lets the Grafana chat panel call this API directly from the
// browser, same reasoning as config-api's identical middleware: the panel
// issues a plain fetch() rather than going through Grafana's backend proxy.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
