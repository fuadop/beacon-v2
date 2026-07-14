package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

const configSchema = `
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT NOT NULL UNIQUE,
  hostname TEXT,
  snmp_version TEXT CHECK(snmp_version IN ('v1','v2c','v3','')),
  community TEXT,
  v3_user TEXT,
  v3_auth_key TEXT,
  v3_priv_key TEXT,
  v3_auth_protocol TEXT,
  v3_priv_protocol TEXT,
  group_name TEXT,
  status TEXT CHECK(status IN ('pending','active','failed')) DEFAULT 'pending',
  is_public_ip BOOLEAN DEFAULT 0,
  discovered_via TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('polling_interval_seconds', '60');
`

const trapsSchema = `
CREATE TABLE IF NOT EXISTS traps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_ip TEXT NOT NULL,
  oid TEXT,
  payload TEXT,
  received_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`

// OpenConfigDB opens (creating if necessary) the SQLite database used for device
// and settings configuration, and applies the schema.
func OpenConfigDB(path string) (*sql.DB, error) {
	db, err := open(path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(configSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: applying config schema: %w", err)
	}
	return db, nil
}

// OpenTrapsDB opens (creating if necessary) the SQLite database used to store
// received SNMP traps, and applies the schema.
func OpenTrapsDB(path string) (*sql.DB, error) {
	db, err := open(path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(trapsSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: applying traps schema: %w", err)
	}
	return db, nil
}

func open(path string) (*sql.DB, error) {
	// _pragma busy_timeout avoids "database is locked" errors when the API and
	// watcher processes touch the same SQLite file concurrently.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
}
