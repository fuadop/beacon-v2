package main

import "testing"

func TestLookupColumn(t *testing.T) {
	mc, err := lookupColumn("cpu", "cpu1min")
	if err != nil {
		t.Fatal(err)
	}
	if mc.Kind != kindGauge {
		t.Errorf("cpu1min kind = %v, want kindGauge", mc.Kind)
	}

	mc, err = lookupColumn("interface", "ifInOctets")
	if err != nil {
		t.Fatal(err)
	}
	if mc.Kind != kindCounter {
		t.Errorf("ifInOctets kind = %v, want kindCounter", mc.Kind)
	}
	if mc.SubDimension != "ifDescr" {
		t.Errorf("ifInOctets SubDimension = %q, want ifDescr", mc.SubDimension)
	}
}

func TestLookupColumnUnknownTable(t *testing.T) {
	if _, err := lookupColumn("bogus", "x"); err == nil {
		t.Fatal("expected error for unknown table")
	}
}

func TestLookupColumnUnknownColumn(t *testing.T) {
	if _, err := lookupColumn("cpu", "bogus"); err == nil {
		t.Fatal("expected error for unknown column")
	}
}
