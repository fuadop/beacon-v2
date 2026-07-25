package main

import "fmt"

// columnKind determines how a metric column can be aggregated. Gauge columns
// (percentages, status codes, byte counts of "current" free/used memory) can
// be read directly. Counter columns (SNMP Counter32, monotonically
// increasing since boot) need a rate/delta calculation to mean anything --
// same reasoning as the throughput queries built earlier in this project.
type columnKind int

const (
	kindGauge columnKind = iota
	kindCounter
)

type metricColumn struct {
	Kind        columnKind
	Description string
	// SubDimension names the tag/field a table needs an extra filter on
	// because it has multiple rows per device per poll (e.g. one row per
	// interface, or one row per memory pool). Empty if the table has a
	// single row per device per poll (e.g. cpu).
	SubDimension string
	// SubDimensionDefault is used when the caller doesn't specify a
	// sub-filter and a reasonable default exists (memory defaults to the
	// "Processor" pool, per the earlier throughput/memory discussion in
	// this project -- it's the pool that reflects actual device load).
	SubDimensionDefault string
}

// metricWhitelist is the only source of truth for what query_metric/
// rank_devices can query. Table and column names here are the only ones
// ever interpolated into SQL -- never anything from tool-call input --
// so this whitelist is what makes those tools safe against injection
// regardless of what the model asks for.
var metricWhitelist = map[string]map[string]metricColumn{
	"cpu": {
		"cpu5sec": {Kind: kindGauge, Description: "CPU utilization over the last 5 seconds (%). Spiky/noisy -- use cpu1min for a stable reading."},
		"cpu1min": {Kind: kindGauge, Description: "CPU utilization over the last 1 minute (%). The standard \"current load\" metric."},
		"cpu5min": {Kind: kindGauge, Description: "CPU utilization over the last 5 minutes (%). Use for trend/sustained-load questions."},
	},
	"memory": {
		"ciscoMemoryPoolUsed":        {Kind: kindGauge, Description: "Bytes used in this memory pool.", SubDimension: "ciscoMemoryPoolName", SubDimensionDefault: "Processor"},
		"ciscoMemoryPoolFree":        {Kind: kindGauge, Description: "Bytes free in this memory pool.", SubDimension: "ciscoMemoryPoolName", SubDimensionDefault: "Processor"},
		"ciscoMemoryPoolLargestFree": {Kind: kindGauge, Description: "Largest contiguous free block in this memory pool (bytes) -- a fragmentation signal.", SubDimension: "ciscoMemoryPoolName", SubDimensionDefault: "Processor"},
	},
	"interface": {
		"ifOperStatus":  {Kind: kindGauge, Description: "Interface operational status: 1=up, 2=down, others rarer.", SubDimension: "ifDescr"},
		"ifAdminStatus": {Kind: kindGauge, Description: "Interface administrative status: 1=up, 2=down.", SubDimension: "ifDescr"},
		"ifSpeed":       {Kind: kindGauge, Description: "Interface negotiated speed in bits/sec.", SubDimension: "ifDescr"},
		"ifInOctets":    {Kind: kindCounter, Description: "Cumulative inbound bytes since boot (32-bit counter). Use aggregation=rate for a Mbps throughput figure, not current/avg/max/min.", SubDimension: "ifDescr"},
		"ifOutOctets":   {Kind: kindCounter, Description: "Cumulative outbound bytes since boot (32-bit counter). Use aggregation=rate for a Mbps throughput figure, not current/avg/max/min.", SubDimension: "ifDescr"},
		"ifInErrors":    {Kind: kindCounter, Description: "Cumulative inbound error count since boot.", SubDimension: "ifDescr"},
		"ifOutErrors":   {Kind: kindCounter, Description: "Cumulative outbound error count since boot.", SubDimension: "ifDescr"},
	},
}

// poolMemoryTables/interfaceTables note: memory has exactly two pools in
// practice ("Processor", "I/O") -- see docs/chatbot-plan.md's earlier
// discussion on why Processor is the meaningful one for load questions.

func lookupColumn(table, column string) (metricColumn, error) {
	cols, ok := metricWhitelist[table]
	if !ok {
		return metricColumn{}, fmt.Errorf("unknown table %q: known tables are cpu, memory, interface", table)
	}
	mc, ok := cols[column]
	if !ok {
		return metricColumn{}, fmt.Errorf("unknown column %q on table %q", column, table)
	}
	return mc, nil
}
