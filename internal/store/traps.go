package store

import (
	"database/sql"
	"fmt"
)

type Trap struct {
	ID       int64
	SourceIP string
	OID      string
	Payload  string // JSON blob of varbinds
	// Community and AgentAddress are only populated for SNMPv1 traps -- v1's
	// wire format carries both in the message itself, immune to whatever a
	// NAT/proxy layer between the device and trap-receiver does to the UDP
	// packet's own source IP (see config-api's device-resolution logic, which
	// uses these to attribute a trap when SourceIP can't be trusted).
	Community    string
	AgentAddress string
	ReceivedAt   string
}

type TrapStore struct {
	db *sql.DB
}

func NewTrapStore(db *sql.DB) *TrapStore {
	return &TrapStore{db: db}
}

func (s *TrapStore) Insert(t *Trap) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO traps (source_ip, oid, payload, community, agent_address) VALUES (?, ?, ?, ?, ?)`,
		t.SourceIP, t.OID, t.Payload, t.Community, t.AgentAddress)
	if err != nil {
		return 0, fmt.Errorf("store: inserting trap: %w", err)
	}
	return res.LastInsertId()
}

// List returns the most recent traps, newest first, capped at limit. community/
// agent_address are COALESCEd to '' since rows written before those columns
// existed (added via migration, see OpenTrapsDB) have them as NULL.
func (s *TrapStore) List(limit int) ([]*Trap, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, source_ip, oid, payload, COALESCE(community, ''),
		COALESCE(agent_address, ''), received_at FROM traps ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: listing traps: %w", err)
	}
	defer rows.Close()

	var traps []*Trap
	for rows.Next() {
		var t Trap
		if err := rows.Scan(&t.ID, &t.SourceIP, &t.OID, &t.Payload, &t.Community, &t.AgentAddress, &t.ReceivedAt); err != nil {
			return nil, fmt.Errorf("store: scanning trap: %w", err)
		}
		traps = append(traps, &t)
	}
	return traps, rows.Err()
}
