package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// Device mirrors the devices table. Credential fields (Community, V3AuthKey, V3PrivKey)
// are stored and returned as ciphertext — callers are responsible for encrypting
// before writing and decrypting after reading, via internal/crypto.
type Device struct {
	ID              int64
	IPAddress       string
	Hostname        string
	SNMPVersion     string
	Community       string
	V3User          string
	V3AuthKey       string
	V3PrivKey       string
	V3AuthProtocol  string
	V3PrivProtocol  string
	GroupName       string
	Status          string
	IsPublicIP      bool
	DiscoveredVia   string
	CreatedAt       string
	UpdatedAt       string
}

var ErrNotFound = errors.New("store: not found")

type DeviceStore struct {
	db *sql.DB
}

func NewDeviceStore(db *sql.DB) *DeviceStore {
	return &DeviceStore{db: db}
}

const deviceColumns = `id, ip_address, hostname, snmp_version, community, v3_user, v3_auth_key,
	v3_priv_key, v3_auth_protocol, v3_priv_protocol, group_name, status, is_public_ip,
	discovered_via, created_at, updated_at`

func scanDevice(row interface{ Scan(...any) error }) (*Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.IPAddress, &d.Hostname, &d.SNMPVersion, &d.Community, &d.V3User,
		&d.V3AuthKey, &d.V3PrivKey, &d.V3AuthProtocol, &d.V3PrivProtocol, &d.GroupName, &d.Status,
		&d.IsPublicIP, &d.DiscoveredVia, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *DeviceStore) List() ([]*Device, error) {
	rows, err := s.db.Query(`SELECT ` + deviceColumns + ` FROM devices ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: listing devices: %w", err)
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning device: %w", err)
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// ListByStatus returns devices matching the given status, e.g. "active" for the
// Telegraf config generator.
func (s *DeviceStore) ListByStatus(status string) ([]*Device, error) {
	rows, err := s.db.Query(`SELECT `+deviceColumns+` FROM devices WHERE status = ? ORDER BY id`, status)
	if err != nil {
		return nil, fmt.Errorf("store: listing devices by status: %w", err)
	}
	defer rows.Close()

	var devices []*Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scanning device: %w", err)
		}
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

func (s *DeviceStore) Get(id int64) (*Device, error) {
	row := s.db.QueryRow(`SELECT `+deviceColumns+` FROM devices WHERE id = ?`, id)
	d, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: getting device %d: %w", id, err)
	}
	return d, nil
}

func (s *DeviceStore) GetByIP(ip string) (*Device, error) {
	row := s.db.QueryRow(`SELECT `+deviceColumns+` FROM devices WHERE ip_address = ?`, ip)
	d, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: getting device by ip %s: %w", ip, err)
	}
	return d, nil
}

// Create inserts a device. Credential fields on d must already be encrypted.
func (s *DeviceStore) Create(d *Device) (int64, error) {
	if d.Status == "" {
		d.Status = "pending"
	}
	res, err := s.db.Exec(`
		INSERT INTO devices (ip_address, hostname, snmp_version, community, v3_user, v3_auth_key,
			v3_priv_key, v3_auth_protocol, v3_priv_protocol, group_name, status, is_public_ip, discovered_via)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.IPAddress, d.Hostname, d.SNMPVersion, d.Community, d.V3User, d.V3AuthKey, d.V3PrivKey,
		d.V3AuthProtocol, d.V3PrivProtocol, d.GroupName, d.Status, d.IsPublicIP, d.DiscoveredVia)
	if err != nil {
		return 0, fmt.Errorf("store: creating device: %w", err)
	}
	return res.LastInsertId()
}

// Update applies a partial set of column updates to a device, identified by id.
// Only non-nil fields in updates are written. Credential values must already be encrypted.
func (s *DeviceStore) Update(id int64, updates map[string]any) error {
	if len(updates) == 0 {
		return nil
	}
	setClause := ""
	args := make([]any, 0, len(updates)+1)
	for col, val := range updates {
		if !allowedDeviceColumn(col) {
			return fmt.Errorf("store: invalid column %q", col)
		}
		if setClause != "" {
			setClause += ", "
		}
		setClause += col + " = ?"
		args = append(args, val)
	}
	setClause += ", updated_at = CURRENT_TIMESTAMP"
	args = append(args, id)

	res, err := s.db.Exec(`UPDATE devices SET `+setClause+` WHERE id = ?`, args...)
	if err != nil {
		return fmt.Errorf("store: updating device %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: checking update result for device %d: %w", id, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func allowedDeviceColumn(col string) bool {
	switch col {
	case "hostname", "snmp_version", "community", "v3_user", "v3_auth_key", "v3_priv_key",
		"v3_auth_protocol", "v3_priv_protocol", "group_name", "status", "is_public_ip", "discovered_via":
		return true
	default:
		return false
	}
}
