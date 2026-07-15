# Network Monitor

Self-hosted SNMP network monitoring: Telegraf polls devices into InfluxDB,
Grafana visualizes it, and a small set of Go services handle configuration,
discovery, and trap collection. See the project plan for full background.

## Security & Threat Model

This is designed for a trusted home/lab LAN, not a multi-tenant or
internet-facing deployment. Concretely:

- **Credentials at rest.** SNMP community strings and v3 auth/priv keys are
  encrypted with AES-256-GCM (`internal/crypto`) before they touch SQLite. The
  key comes from the `ENCRYPTION_KEY` env var — protect it like any other
  secret; anyone with it and the SQLite file can decrypt stored credentials.
- **Credentials over the wire.** `config-api` never returns a credential in
  plaintext or ciphertext in any response — only `has_community`,
  `has_v3_auth_key`, `has_v3_priv_key` booleans (see
  `config-api/handlers/devices.go`). Even a device recorded as `failed` after a
  credential-duplication attempt only ever exposes whether *something* was
  tried, never the value.
- **`config-api` has no authentication of its own** and is wide open to CORS
  (`Access-Control-Allow-Origin: *`) because the Grafana Business Forms panels
  call it directly from the browser. It is meant to sit behind the same
  network boundary as Grafana itself — don't expose port 8080 (or Grafana's
  3000) beyond your LAN without putting a reverse proxy with auth in front of
  both.
- **SNMP v1/v2c traps have no real authentication.** `trap-receiver` accepts
  and stores any trap sent to UDP/162 regardless of community string —
  spoofing a trap from an arbitrary source IP is trivial on a shared network.
  Treat the `traps` table as informational, not as an audit log.
- **Credential duplication is opt-in and private-IP-only.** Reusing a parent
  device's SNMP credentials against a newly discovered neighbor
  (`config-watcher/discovery_sweep.go`) only happens when
  `credential_duplication_enabled` is explicitly turned on
  (`POST /settings/credential-duplication`), and never against a public IP
  (`internal/netutil.IsPublic`, RFC1918-based) — a device on the public
  internet visible via a routing table entry is never auto-probed or credentialed.
- **Discovery sweep is rate-limited.** Each sweep run inserts at most 10 new
  devices (`maxNewDevicesPerSweep`) and runs on its own slow ticker (default
  every 300s, `DISCOVERY_SWEEP_INTERVAL_SECONDS`) separate from the much
  faster Telegraf-config reconcile loop — a large or malformed routing table
  can't flood the devices table in one pass, and an already-tracked IP
  (including a previously-failed one) is never re-probed on subsequent sweeps.
- **`config-watcher` holds the Docker socket** (`/var/run/docker.sock`) so it
  can `docker exec` a SIGHUP into the `telegraf` container on config changes.
  That's root-equivalent access to the whole Docker daemon on the host, scoped
  by convention (not enforcement) to that one action — don't add other
  responsibilities to that container without revisiting this.

## Running it

```
cp .env.example .env
# edit .env: set ENCRYPTION_KEY (openssl rand -hex 32), GF_SECURITY_ADMIN_PASSWORD
docker compose up -d --build
```

First boot: create an InfluxDB admin token and put it in `.env` as
`INFLUXDB_TOKEN`, then restart `config-watcher` and `grafana` so they pick it up:

```
docker compose exec influxdb influxdb3 create token --admin
# copy the token into .env's INFLUXDB_TOKEN
docker compose up -d config-watcher grafana
```

Grafana is at `http://localhost:3000`. On the "Network Monitor" dashboard, set
the **Config API URL** variable at the top to whatever address your browser
can reach `config-api` on — `http://localhost:8080` if Grafana and Docker are
on your local machine, or `http://<host-ip>:8080` if you're accessing Grafana
remotely. This is separate from the datasource wiring (which uses Docker's
internal network) because the Business Forms panels call `config-api` directly
from your browser, not through Grafana's backend.
