package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type influxClient struct {
	url      string
	token    string
	database string
	http     *http.Client
}

func newInfluxClient(url, token, database string) *influxClient {
	return &influxClient{
		url:      strings.TrimSuffix(url, "/"),
		token:    token,
		database: database,
		http:     &http.Client{Timeout: 15 * time.Second},
	}
}

// query runs a SQL query against InfluxDB 3's query_sql API and returns one
// map per row. Callers (tools.go) are responsible for only ever building sql
// from whitelisted table/column names plus quoted/validated literal values --
// this client has no injection defenses of its own, it just executes SQL.
func (c *influxClient) query(sql string) ([]map[string]any, error) {
	body, err := json.Marshal(map[string]string{
		"db":     c.database,
		"q":      sql,
		"format": "json",
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.url+"/api/v3/query_sql", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying influxdb: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading influxdb response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// InfluxDB's error bodies are plain, readable text (e.g. the
		// Parquet-file-scan-limit message) -- surface them as-is so the
		// tool_result the model sees is actually informative.
		return nil, fmt.Errorf("influxdb query failed: %s", strings.TrimSpace(string(respBody)))
	}

	var rows []map[string]any
	if err := json.Unmarshal(respBody, &rows); err != nil {
		return nil, fmt.Errorf("decoding influxdb response: %w", err)
	}
	return rows, nil
}

// sqlQuote escapes a string for safe interpolation as a SQL string literal.
// Used as defense-in-depth for values that are validated against known-good
// sets before reaching here (device IPs resolved via config-api, interface/
// pool names checked against what a device actually reports) -- never used
// as the only line of defense.
func sqlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
