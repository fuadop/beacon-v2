package main

import "testing"

func testDevices() []device {
	return []device{
		{Hostname: "R1.compnet.torontomu.ca", IPAddress: "172.16.154.63"},
		{Hostname: "R2.compnet.torontomu.ca", IPAddress: "172.16.154.65"},
	}
}

func TestResolveDeviceByExactIP(t *testing.T) {
	d, err := resolveDevice(testDevices(), "172.16.154.63")
	if err != nil {
		t.Fatal(err)
	}
	if d.Hostname != "R1.compnet.torontomu.ca" {
		t.Errorf("got %q", d.Hostname)
	}
}

func TestResolveDeviceByExactHostname(t *testing.T) {
	d, err := resolveDevice(testDevices(), "R2.compnet.torontomu.ca")
	if err != nil {
		t.Fatal(err)
	}
	if d.IPAddress != "172.16.154.65" {
		t.Errorf("got %q", d.IPAddress)
	}
}

func TestResolveDeviceByPrefix(t *testing.T) {
	d, err := resolveDevice(testDevices(), "R1")
	if err != nil {
		t.Fatal(err)
	}
	if d.IPAddress != "172.16.154.63" {
		t.Errorf("got %q", d.IPAddress)
	}
}

func TestResolveDeviceByPrefixCaseInsensitive(t *testing.T) {
	d, err := resolveDevice(testDevices(), "r2")
	if err != nil {
		t.Fatal(err)
	}
	if d.IPAddress != "172.16.154.65" {
		t.Errorf("got %q", d.IPAddress)
	}
}

func TestResolveDeviceNoMatch(t *testing.T) {
	if _, err := resolveDevice(testDevices(), "R99"); err == nil {
		t.Fatal("expected error for unknown device")
	}
}

func TestResolveDeviceAmbiguousPrefix(t *testing.T) {
	devices := []device{
		{Hostname: "R1.compnet.torontomu.ca", IPAddress: "172.16.154.63"},
		{Hostname: "R1-backup.compnet.torontomu.ca", IPAddress: "172.16.154.64"},
	}
	if _, err := resolveDevice(devices, "R1"); err == nil {
		t.Fatal("expected error for ambiguous prefix match")
	}
}
