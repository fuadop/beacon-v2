package store

import (
	"path/filepath"
	"testing"
)

func newTestSettingsStore(t *testing.T) *SettingsStore {
	t.Helper()
	db, err := OpenConfigDB(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewSettingsStore(db)
}

func TestSettingsSeededDefault(t *testing.T) {
	s := newTestSettingsStore(t)
	v, err := s.Get("polling_interval_seconds")
	if err != nil {
		t.Fatal(err)
	}
	if v != "60" {
		t.Fatalf("expected seeded default 60, got %q", v)
	}
}

func TestSettingsSetOverwrites(t *testing.T) {
	s := newTestSettingsStore(t)
	if err := s.Set("polling_interval_seconds", "300"); err != nil {
		t.Fatal(err)
	}
	v, err := s.Get("polling_interval_seconds")
	if err != nil {
		t.Fatal(err)
	}
	if v != "300" {
		t.Fatalf("expected 300, got %q", v)
	}
}

func TestSettingsGetUnknownKey(t *testing.T) {
	s := newTestSettingsStore(t)
	if _, err := s.Get("does_not_exist"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
