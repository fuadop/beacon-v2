package store

import (
	"path/filepath"
	"testing"
)

func newTestConfigDB(t *testing.T) *DeviceStore {
	t.Helper()
	db, err := OpenConfigDB(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewDeviceStore(db)
}

func TestDeviceCreateGetList(t *testing.T) {
	s := newTestConfigDB(t)

	id, err := s.Create(&Device{
		IPAddress:   "192.168.1.1",
		SNMPVersion: "v2c",
		Community:   "encrypted-blob",
		Status:      "pending",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.IPAddress != "192.168.1.1" || got.SNMPVersion != "v2c" {
		t.Fatalf("unexpected device: %+v", got)
	}

	list, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 device, got %d", len(list))
	}
}

func TestDeviceCreateDuplicateIPFails(t *testing.T) {
	s := newTestConfigDB(t)
	if _, err := s.Create(&Device{IPAddress: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(&Device{IPAddress: "10.0.0.1"}); err == nil {
		t.Fatal("expected unique constraint violation on duplicate ip_address")
	}
}

func TestDeviceUpdate(t *testing.T) {
	s := newTestConfigDB(t)
	id, err := s.Create(&Device{IPAddress: "10.0.0.2", Status: "pending"})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Update(id, map[string]any{"status": "active", "hostname": "router1"}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "active" || got.Hostname != "router1" {
		t.Fatalf("unexpected device after update: %+v", got)
	}
}

func TestDeviceUpdateUnknownIDReturnsNotFound(t *testing.T) {
	s := newTestConfigDB(t)
	err := s.Update(999, map[string]any{"status": "active"})
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDeviceUpdateRejectsUnknownColumn(t *testing.T) {
	s := newTestConfigDB(t)
	id, err := s.Create(&Device{IPAddress: "10.0.0.3"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(id, map[string]any{"id": 5}); err == nil {
		t.Fatal("expected error updating disallowed column")
	}
}

func TestDeviceListByStatus(t *testing.T) {
	s := newTestConfigDB(t)
	id1, _ := s.Create(&Device{IPAddress: "10.0.0.4", Status: "pending"})
	id2, _ := s.Create(&Device{IPAddress: "10.0.0.5", Status: "active"})

	active, err := s.ListByStatus("active")
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].ID != id2 {
		t.Fatalf("expected only id2 active, got %+v (id1=%d)", active, id1)
	}
}

func TestGetByIPNotFound(t *testing.T) {
	s := newTestConfigDB(t)
	if _, err := s.GetByIP("10.0.0.99"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDeviceDelete(t *testing.T) {
	s := newTestConfigDB(t)
	id, err := s.Create(&Device{IPAddress: "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(id); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := s.Get(id); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestDeviceDeleteUnknownIDReturnsNotFound(t *testing.T) {
	s := newTestConfigDB(t)
	if err := s.Delete(999); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
