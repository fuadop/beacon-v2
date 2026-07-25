package main

import (
	"strings"
	"testing"
)

func TestClampHours(t *testing.T) {
	if _, err := clampHours(0); err == nil {
		t.Error("expected error for hours=0")
	}
	if _, err := clampHours(-1); err == nil {
		t.Error("expected error for negative hours")
	}
	if _, err := clampHours(maxQueryHours + 1); err == nil {
		t.Error("expected error for hours over the cap")
	}
	got, err := clampHours(6)
	if err != nil || got != 6 {
		t.Errorf("clampHours(6) = %v, %v", got, err)
	}
}

func TestBuildMetricQueryCurrentGauge(t *testing.T) {
	mc, _ := lookupColumn("cpu", "cpu1min")
	sql, err := buildMetricQuery("cpu", "cpu1min", mc, "172.16.154.63", "", "current", 6, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, `agent_host = '172.16.154.63'`) {
		t.Errorf("missing agent_host filter: %s", sql)
	}
	if !strings.Contains(sql, "ORDER BY time DESC LIMIT 1") {
		t.Errorf("current aggregation should be latest-first, limit 1: %s", sql)
	}
}

func TestBuildMetricQueryRejectsAvgOnCounter(t *testing.T) {
	mc, _ := lookupColumn("interface", "ifInOctets")
	_, err := buildMetricQuery("interface", "ifInOctets", mc, "172.16.154.63", "GigabitEthernet0/0", "avg", 6, nil)
	if err == nil {
		t.Fatal("expected error using avg on a counter column")
	}
}

func TestBuildMetricQueryRateOnGaugeRejected(t *testing.T) {
	mc, _ := lookupColumn("cpu", "cpu1min")
	_, err := buildMetricQuery("cpu", "cpu1min", mc, "172.16.154.63", "", "rate", 6, nil)
	if err == nil {
		t.Fatal("expected error using rate on a gauge column")
	}
}

func TestBuildMetricQueryCountAboveThresholdRequiresThreshold(t *testing.T) {
	mc, _ := lookupColumn("cpu", "cpu1min")
	_, err := buildMetricQuery("cpu", "cpu1min", mc, "172.16.154.63", "", "count_above_threshold", 6, map[string]any{})
	if err == nil {
		t.Fatal("expected error when threshold is missing")
	}

	sql, err := buildMetricQuery("cpu", "cpu1min", mc, "172.16.154.63", "", "count_above_threshold", 6, map[string]any{"threshold": 80.0})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, `"cpu1min" > 80`) {
		t.Errorf("missing threshold comparison: %s", sql)
	}
}

func TestBuildMetricQuerySubFilterIncluded(t *testing.T) {
	mc, _ := lookupColumn("interface", "ifOperStatus")
	sql, err := buildMetricQuery("interface", "ifOperStatus", mc, "172.16.154.63", "GigabitEthernet0/0", "current", 6, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, `"ifDescr" = 'GigabitEthernet0/0'`) {
		t.Errorf("missing sub-dimension filter: %s", sql)
	}
}

func TestRateQueryClampsWraparound(t *testing.T) {
	sql := rateQuery("interface", "ifInOctets", "agent_host = '172.16.154.63'")
	if !strings.Contains(sql, "4294967296") {
		t.Errorf("rate query should include the 32-bit wraparound clamp: %s", sql)
	}
}
