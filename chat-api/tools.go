package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// toolContext bundles the dependencies every tool needs.
type toolContext struct {
	influx    *influxClient
	configAPI *configAPIClient
}

// maxQueryHours bounds every time_range parameter. InfluxDB 3 Core caps how
// many Parquet files a single query can scan (discovered empirically against
// this deployment's live data: an unbounded query started failing outright
// once the file count crossed a few hundred), so every query here must stay
// bounded -- this is the ceiling under which that limit isn't hit.
const maxQueryHours = 72

// anthropicTool is the JSON shape Anthropic's Messages API expects for each
// tool definition (name/description/input_schema).
type anthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

func toolDefinitions() []anthropicTool {
	return []anthropicTool{
		{
			Name: "list_devices",
			Description: "List every monitored device with its hostname, IP, status, and group. " +
				"Call this first to resolve a name like \"R1\" to a real device, or to answer " +
				"\"what devices are being monitored\".",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name: "query_metric",
			Description: "Query a single metric for one device. Covers current value, historical " +
				"series, average/max/min over a time window, counting how many times a value crossed " +
				"a threshold (\"spiked\"), and throughput rate for byte counters. Available tables and " +
				"columns:\n" + describeWhitelist() +
				"\nFor the interface table, sub_filter is REQUIRED and must be an interface name (e.g. " +
				"\"GigabitEthernet0/0\") -- call this tool once with aggregation=current on any interface " +
				"column first if you don't already know the device's interface names, or use rank_devices " +
				"style history to discover them. For the memory table, sub_filter is optional and defaults " +
				"to the \"Processor\" pool, which is the one that reflects actual device load.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"device":      map[string]any{"type": "string", "description": "Device hostname, hostname prefix (e.g. \"R1\"), or IP."},
					"table":       map[string]any{"type": "string", "enum": []string{"cpu", "memory", "interface"}},
					"column":      map[string]any{"type": "string", "description": "Column name, must be one of the columns listed for the chosen table."},
					"aggregation": map[string]any{"type": "string", "enum": []string{"current", "history", "avg", "max", "min", "count_above_threshold", "rate"}},
					"hours":       map[string]any{"type": "number", "description": fmt.Sprintf("How many hours back to look. Max %d.", maxQueryHours)},
					"threshold":   map[string]any{"type": "number", "description": "Required only for aggregation=count_above_threshold."},
					"sub_filter":  map[string]any{"type": "string", "description": "Interface name (interface table) or pool name (memory table). Not used for cpu."},
				},
				"required": []string{"device", "table", "column", "aggregation", "hours"},
			},
		},
		{
			Name: "rank_devices",
			Description: "Rank all devices by a metric over a time window, highest first -- answers " +
				"questions like \"what router has the highest CPU load\". Same table/column whitelist as " +
				"query_metric. Uses the average value over the window for gauge metrics (e.g. cpu1min), or " +
				"average throughput for counter metrics like ifInOctets/ifOutOctets (device-wide, summed " +
				"across interfaces).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"table":  map[string]any{"type": "string", "enum": []string{"cpu", "memory", "interface"}},
					"column": map[string]any{"type": "string"},
					"hours":  map[string]any{"type": "number", "description": fmt.Sprintf("How many hours back to look. Max %d.", maxQueryHours)},
				},
				"required": []string{"table", "column", "hours"},
			},
		},
		{
			Name: "get_recent_traps",
			Description: "List recent SNMP traps (LinkDown, ConfigChanged, etc.) across all devices in " +
				"the last N hours. IMPORTANT LIMITATION: traps currently cannot be reliably attributed to " +
				"a specific device -- their recorded source IP is masked by the network's port-forwarding " +
				"setup, not the real originating router. Always tell the user this when reporting trap " +
				"counts/history: you can say how many of a given trap type happened, but not confidently " +
				"say which router caused which one.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"hours": map[string]any{"type": "number", "description": fmt.Sprintf("How many hours back to look. Max %d.", maxQueryHours)},
				},
				"required": []string{"hours"},
			},
		},
	}
}

func describeWhitelist() string {
	var b strings.Builder
	for _, table := range []string{"cpu", "memory", "interface"} {
		fmt.Fprintf(&b, "- %s: ", table)
		first := true
		for col, mc := range metricWhitelist[table] {
			if !first {
				b.WriteString(", ")
			}
			first = false
			fmt.Fprintf(&b, "%s (%s)", col, mc.Description)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func clampHours(h float64) (float64, error) {
	if h <= 0 {
		return 0, fmt.Errorf("hours must be positive")
	}
	if h > maxQueryHours {
		return 0, fmt.Errorf("hours capped at %d to stay within InfluxDB's query limits -- ask a narrower question or make multiple calls", maxQueryHours)
	}
	return h, nil
}

// executeTool dispatches a tool call by name and returns the JSON string to
// send back as the tool_result content.
func executeTool(tc toolContext, name string, input map[string]any) (string, error) {
	switch name {
	case "list_devices":
		return toolListDevices(tc)
	case "query_metric":
		return toolQueryMetric(tc, input)
	case "rank_devices":
		return toolRankDevices(tc, input)
	case "get_recent_traps":
		return toolGetRecentTraps(tc, input)
	default:
		return "", fmt.Errorf("unknown tool %q", name)
	}
}

func toolListDevices(tc toolContext) (string, error) {
	devices, err := tc.configAPI.listDevices()
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(devices)
	return string(b), err
}

func inputString(input map[string]any, key string) string {
	if v, ok := input[key].(string); ok {
		return v
	}
	return ""
}

func inputFloat(input map[string]any, key string) (float64, bool) {
	v, ok := input[key].(float64)
	return v, ok
}

func toolQueryMetric(tc toolContext, input map[string]any) (string, error) {
	table := inputString(input, "table")
	column := inputString(input, "column")
	aggregation := inputString(input, "aggregation")
	deviceRef := inputString(input, "device")
	subFilter := inputString(input, "sub_filter")

	hoursRaw, ok := inputFloat(input, "hours")
	if !ok {
		return "", fmt.Errorf("hours is required")
	}
	hours, err := clampHours(hoursRaw)
	if err != nil {
		return "", err
	}

	mc, err := lookupColumn(table, column)
	if err != nil {
		return "", err
	}

	devices, err := tc.configAPI.listDevices()
	if err != nil {
		return "", err
	}
	dev, err := resolveDevice(devices, deviceRef)
	if err != nil {
		return "", err
	}

	subFilter, err = resolveSubFilter(tc, table, mc, dev.IPAddress, subFilter)
	if err != nil {
		return "", err
	}

	sql, err := buildMetricQuery(table, column, mc, dev.IPAddress, subFilter, aggregation, hours, input)
	if err != nil {
		return "", err
	}

	rows, err := tc.influx.query(sql)
	if err != nil {
		return "", err
	}

	result := map[string]any{
		"device": dev.Hostname,
		"table":  table,
		"column": column,
		"rows":   rows,
	}
	b, err := json.Marshal(result)
	return string(b), err
}

// resolveSubFilter validates/defaults sub_filter against what a device
// actually reports, rather than interpolating model-supplied text directly.
func resolveSubFilter(tc toolContext, table string, mc metricColumn, agentHost, requested string) (string, error) {
	if mc.SubDimension == "" {
		return "", nil
	}
	if requested == "" {
		if mc.SubDimensionDefault != "" {
			return mc.SubDimensionDefault, nil
		}
		return "", fmt.Errorf("sub_filter is required for table %q (%s)", table, mc.SubDimension)
	}

	sql := fmt.Sprintf(
		`SELECT DISTINCT "%s" AS v FROM %s WHERE agent_host = %s AND time >= now() - INTERVAL '%d hours'`,
		mc.SubDimension, table, sqlQuote(agentHost), maxQueryHours,
	)
	rows, err := tc.influx.query(sql)
	if err != nil {
		return "", fmt.Errorf("looking up valid %s values: %w", mc.SubDimension, err)
	}

	var known []string
	for _, r := range rows {
		if v, ok := r["v"].(string); ok && v != "" {
			known = append(known, v)
		}
	}

	lower := strings.ToLower(requested)
	for _, v := range known {
		if strings.EqualFold(v, requested) {
			return v, nil
		}
	}
	var matches []string
	for _, v := range known {
		if strings.Contains(strings.ToLower(v), lower) {
			matches = append(matches, v)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	return "", fmt.Errorf("%q does not match a known %s (%s) for this device; known values: %s",
		requested, mc.SubDimension, table, strings.Join(known, ", "))
}

func buildMetricQuery(table, column string, mc metricColumn, agentHost, subFilter, aggregation string, hours float64, input map[string]any) (string, error) {
	where := fmt.Sprintf(`agent_host = %s AND time >= now() - INTERVAL '%g hours'`, sqlQuote(agentHost), hours)
	if subFilter != "" {
		where += fmt.Sprintf(` AND "%s" = %s`, mc.SubDimension, sqlQuote(subFilter))
	}

	switch aggregation {
	case "current":
		return fmt.Sprintf(`SELECT time, "%s" FROM %s WHERE %s ORDER BY time DESC LIMIT 1`, column, table, where), nil

	case "history":
		return fmt.Sprintf(`SELECT time, "%s" FROM %s WHERE %s ORDER BY time ASC LIMIT 500`, column, table, where), nil

	case "avg", "max", "min":
		if mc.Kind == kindCounter {
			return "", fmt.Errorf("%s is a cumulative counter, %s doesn't apply -- use aggregation=rate for a throughput figure, or aggregation=history to see raw values", column, aggregation)
		}
		fn := map[string]string{"avg": "AVG", "max": "MAX", "min": "MIN"}[aggregation]
		return fmt.Sprintf(`SELECT %s("%s") AS result FROM %s WHERE %s`, fn, column, table, where), nil

	case "count_above_threshold":
		if mc.Kind == kindCounter {
			return "", fmt.Errorf("%s is a cumulative counter, count_above_threshold doesn't apply to it directly -- use aggregation=rate to check throughput instead", column)
		}
		threshold, ok := inputFloat(input, "threshold")
		if !ok {
			return "", fmt.Errorf("threshold is required for aggregation=count_above_threshold")
		}
		return fmt.Sprintf(`SELECT COUNT(*) AS result FROM %s WHERE %s AND "%s" > %g`, table, where, column, threshold), nil

	case "rate":
		if mc.Kind != kindCounter {
			return "", fmt.Errorf("%s is not a counter -- aggregation=rate only applies to cumulative byte/error counters like ifInOctets/ifOutOctets", column)
		}
		return rateQuery(table, column, where), nil

	default:
		return "", fmt.Errorf("unknown aggregation %q", aggregation)
	}
}

// rateQuery computes average throughput in Mbps over the window, using the
// same wraparound-safe LAG/delta pattern validated against live data
// earlier in this project (32-bit counters wrap at ~4.29GB and need the
// +4294967296 clamp when a delta comes back negative).
func rateQuery(table, column, where string) string {
	return fmt.Sprintf(`
WITH deltas AS (
  SELECT time, "%s" - LAG("%s") OVER (ORDER BY time) AS delta
  FROM %s WHERE %s
)
SELECT
  SUM(CASE WHEN delta < 0 THEN delta + 4294967296 ELSE delta END) AS total_bytes,
  EXTRACT(EPOCH FROM (MAX(time) - MIN(time))) AS span_seconds
FROM deltas WHERE delta IS NOT NULL`, column, column, table, where)
}

func toolRankDevices(tc toolContext, input map[string]any) (string, error) {
	table := inputString(input, "table")
	column := inputString(input, "column")

	hoursRaw, ok := inputFloat(input, "hours")
	if !ok {
		return "", fmt.Errorf("hours is required")
	}
	hours, err := clampHours(hoursRaw)
	if err != nil {
		return "", err
	}

	mc, err := lookupColumn(table, column)
	if err != nil {
		return "", err
	}

	devices, err := tc.configAPI.listDevices()
	if err != nil {
		return "", err
	}

	type ranked struct {
		Device string  `json:"device"`
		Value  float64 `json:"value"`
	}
	var results []ranked

	for _, d := range devices {
		subFilter := ""
		if mc.SubDimension != "" {
			subFilter, err = resolveSubFilter(tc, table, mc, d.IPAddress, "")
			if err != nil {
				// No data / no matching sub-dimension for this device -- skip it
				// rather than failing the whole ranking.
				continue
			}
		}
		where := fmt.Sprintf(`agent_host = %s AND time >= now() - INTERVAL '%g hours'`, sqlQuote(d.IPAddress), hours)
		if subFilter != "" {
			where += fmt.Sprintf(` AND "%s" = %s`, mc.SubDimension, sqlQuote(subFilter))
		}

		var sql string
		if mc.Kind == kindCounter {
			sql = rateQuery(table, column, where)
		} else {
			sql = fmt.Sprintf(`SELECT AVG("%s") AS result FROM %s WHERE %s`, column, table, where)
		}

		rows, err := tc.influx.query(sql)
		if err != nil || len(rows) == 0 {
			continue
		}

		var value float64
		if mc.Kind == kindCounter {
			totalBytes, _ := rows[0]["total_bytes"].(float64)
			spanSeconds, _ := rows[0]["span_seconds"].(float64)
			if spanSeconds > 0 {
				value = totalBytes * 8.0 / 1e6 / spanSeconds
			}
		} else {
			value, _ = rows[0]["result"].(float64)
		}
		results = append(results, ranked{Device: d.Hostname, Value: value})
	}

	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if results[j].Value > results[i].Value {
				results[i], results[j] = results[j], results[i]
			}
		}
	}

	unit := "avg value"
	if mc.Kind == kindCounter {
		unit = "avg Mbps"
	}
	b, err := json.Marshal(map[string]any{"table": table, "column": column, "unit": unit, "ranking": results})
	return string(b), err
}

func toolGetRecentTraps(tc toolContext, input map[string]any) (string, error) {
	hoursRaw, ok := inputFloat(input, "hours")
	if !ok {
		return "", fmt.Errorf("hours is required")
	}
	hours, err := clampHours(hoursRaw)
	if err != nil {
		return "", err
	}

	traps, err := tc.configAPI.getRecentTraps(hours)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(map[string]any{
		"note":  "source device attribution is not reliable for these traps, see tool description",
		"traps": traps,
	})
	return string(b), err
}
