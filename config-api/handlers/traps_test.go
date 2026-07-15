package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/fuad/network-monitor/internal/store"
)

func TestTrapsListReturnsRecentFirst(t *testing.T) {
	db, err := store.OpenTrapsDB(filepath.Join(t.TempDir(), "traps.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	trapStore := store.NewTrapStore(db)

	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if _, err := trapStore.Insert(&store.Trap{SourceIP: ip, OID: ".1.3.6.1.6.3.1.1.5.3", Payload: "[]"}); err != nil {
			t.Fatal(err)
		}
	}

	h := &TrapsHandler{Store: trapStore}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /traps", h.List)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/traps")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got []store.Trap
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 traps, got %d", len(got))
	}
	if got[0].SourceIP != "10.0.0.3" {
		t.Errorf("expected newest trap (10.0.0.3) first, got %q", got[0].SourceIP)
	}
}

func TestTrapsListRespectsLimit(t *testing.T) {
	db, err := store.OpenTrapsDB(filepath.Join(t.TempDir(), "traps.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	trapStore := store.NewTrapStore(db)

	for i := 0; i < 5; i++ {
		if _, err := trapStore.Insert(&store.Trap{SourceIP: "10.0.0.1", OID: "x", Payload: "[]"}); err != nil {
			t.Fatal(err)
		}
	}

	h := &TrapsHandler{Store: trapStore}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /traps", h.List)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/traps?limit=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got []store.Trap
	json.NewDecoder(resp.Body).Decode(&got)
	if len(got) != 2 {
		t.Fatalf("expected 2 traps with limit=2, got %d", len(got))
	}
}
