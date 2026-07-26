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
- **`config-watcher` runs as root** (its `alpine`-based image, unlike the
  other Go services' `distroless` ones) so its health-check loop can open raw
  ICMP sockets for ping — Docker grants `CAP_NET_RAW` to containers by default,
  so this needs no extra `docker-compose.yml` configuration, but it's worth
  knowing if you ever harden this stack's capability set.

## Device health checking

`config-watcher` pings and SNMP-probes every device with credentials on file
on the same cadence as its config-reconcile loop (`CONFIG_WATCHER_POLL_SECONDS`,
default 10s) and updates each device's `status` in SQLite to match reality —
not just at creation/edit time like before. SNMP is authoritative for the
stored status (that's what actually determines whether Telegraf can collect
from it); ping runs too and is logged for diagnostics, but never overrides
the SNMP result, since ICMP is commonly blocked by firewalls even when SNMP
works fine. A device that goes from `active` to `failed` (or back) is
automatically added to or dropped from `telegraf.conf` on the next reconcile,
since that already only includes `active` devices — no manual intervention
needed either direction.

## Alerting & email

A `Dead-Device` alert rule (Grafana Alerting, `grafana/provisioning/alerting/`)
is provisioned by default: it fires when any credentialed device's `status`
isn't `active` — i.e. it's a direct consumer of the health-checking above.
It's wired to an email contact point ("Group-4"), but two things you need to
know before it'll actually deliver anything:

1. **SMTP is off by default.** Set `SMTP_SERVER`/`SMTP_PORT`/`SMTP_USERNAME`/
   `SMTP_PASSWORD`/`SMTP_FROM_ADDRESS` in `.env` (any standard SMTP relay
   works — e.g. SMTP2GO, SendGrid, Gmail with an app password) and restart
   Grafana. Leave them blank to keep alerting silent (the rule still evaluates
   and shows up in Grafana's UI either way, it just won't email anyone).
2. **The contact point's recipient addresses are hardcoded** in
   `grafana/provisioning/alerting/contactpoints.yml` (real addresses from this
   project's own development, not placeholders). If you deploy this somewhere
   else and turn SMTP on, **edit that file first** — otherwise real alert
   emails go to people who have nothing to do with your deployment.

## Network Assistant (chatbot)

A Grafana dashboard ("Network Assistant") backed by `chat-api` lets you ask
plain-English questions about device posture ("what's the CPU usage of R1?",
"how many times has R1 spiked in the past 6 hours?") — see
`docs/chatbot-plan.md` for the design and its known limitations. Needs
`GEMINI_API_KEY` (see "Running it" above); nothing else to configure.

## Running it

```
cp .env.example .env
# edit .env: set ENCRYPTION_KEY (openssl rand -hex 32), GF_SECURITY_ADMIN_PASSWORD,
# and GEMINI_API_KEY (free tier: https://aistudio.google.com/apikey)
docker compose up -d --build
```

`GEMINI_API_KEY` powers `chat-api` (the "Network Assistant" chatbot dashboard,
see below) — without it, `chat-api` isn't broken exactly, but it refuses to
start and sits in an endless `restart: unless-stopped` loop. `docker compose
up -d --build` will still exit 0 either way, so if you skip this, the only
sign is `chat-api` cycling in `docker compose ps`; check `docker compose logs
chat-api` if that happens.

First boot: create an InfluxDB admin token and the metrics database, put the
token in `.env` as `INFLUXDB_TOKEN`, then restart `config-watcher` and
`grafana` so they pick it up:

```
docker compose exec influxdb influxdb3 create token --admin
# copy the token into .env's INFLUXDB_TOKEN, then:
docker compose up -d influxdb  # picks up the token from .env
docker compose exec influxdb sh -c 'influxdb3 create database "$INFLUXDB_DATABASE" --retention-period 7d --token "$INFLUXDB_TOKEN"'
docker compose up -d config-watcher grafana
```

Without that `create database` step, the InfluxDB-backed panel errors with
`database not found: network_monitor` — Telegraf's writes don't create the
database on their own.

`--retention-period 7d` keeps InfluxDB from accumulating data (and Parquet
files) forever. InfluxDB 3 Core caps how many Parquet files a single query
can scan — with 30s polling across cpu/memory/interface tables, an
unbounded database crosses that cap in under two weeks, at which point every
dashboard panel and chatbot query starts failing outright with "Query would
scan N Parquet files, exceeding the file limit" rather than just being slow.
7 days keeps the file count bounded indefinitely. To change it later:

```
docker compose exec influxdb influxdb3 update database --database "$INFLUXDB_DATABASE" --retention-period 14d --token "$INFLUXDB_TOKEN"
```

Grafana is at `http://localhost:3000`. The "Add / Edit Device" and "Polling
Interval" panels talk to `config-api` at `http://localhost:8080`, and the
"Ask about your network" chatbot panel talks to `chat-api` at
`http://localhost:8082` — all hardcoded, because your *browser* needs to
reach those addresses directly, and there's no way to make them configurable
via a dashboard variable (see below). This is separate from the
Infinity/InfluxDB datasource wiring (the "Devices"/"Recent Traps" tables and
every metrics chart), which is proxied server-side through Grafana's backend
using Docker's internal network and needs no changes — only these three
panels' own custom-code `fetch()` calls run in your browser.

If Grafana isn't on the same machine as your browser (or you're not using the
default port mapping — see "Deploying on a remote server" below for the
common case of this), update the hardcoded addresses yourself:
- **Polling Interval**: open the panel → **Edit** → **Initial Request** and
  **Update Request** → change the **URL** field.
- **Add / Edit Device**: this panel doesn't use a URL field at all (see
  below) — open the panel → **Edit** → **Update Request** → edit the
  `http://localhost:8080` strings directly inside the **Code** box.
- **Ask about your network**: same as Add/Edit Device — open the panel →
  **Edit** → **Update Request** → edit the `http://localhost:8082` string
  inside the **Code** box.

A dashboard variable would be the obvious way to make this configurable
without hand-editing, but `volkovlabs-form-panel` v6.3.5 has a bug where it
runs the *entire* substituted value through `encodeURIComponent` before using
it as a URL — turning `http://localhost:8080` into
`http%3A%2F%2Flocalhost%3A8080`, which the browser then treats as a relative
path against Grafana's own origin instead of an absolute URL. Confirmed via
the plugin's own source (`FormPanel.tsx`:
`fetch(replaceVariables(url, undefined, encodeURIComponent), ...)` for both
the initial and update requests). Not fixable from the dashboard JSON side —
hence the hardcoded value instead.

### Editing an existing device

The "Add / Edit Device" form is also how you fix a device stuck at `pending`
or `failed` (there's no other UI for it — the Devices table is read-only, and
`config-api` never sends credentials back to the browser, so it can't
pre-fill a table cell to edit in place either):

1. Find the device's numeric **ID** in the Devices table.
2. Type it into the form's **Device ID** field. The non-secret fields
   (IP, hostname, SNMP version, group) auto-populate; credential fields stay
   blank on purpose.
3. Change whatever needs fixing. Leave a credential field blank to keep the
   value already stored — only fill one in if you're actually changing it.
4. Click **Save Device**. This sends a `PATCH` (not `POST`) when Device ID is
   set, and `config-api` re-probes with the resulting credentials, updating
   status to `active` or `failed` immediately.

Leave Device ID blank to add a new device instead (`POST`).

Saving (create or update) also refreshes the whole dashboard afterward, so the
Devices table picks up the change without a manual page reload.

### Deleting a device

Type the device's ID into the same **Device ID** field, then click
**Delete Device** (below Save Device). This asks for a native browser
confirmation, then sends `DELETE /devices/{id}` and clears the form.

## Deploying on a remote server

If you run this on a cloud VM/VPS rather than your own laptop, keep two
separate network paths straight — solving one doesn't solve the other:

1. **The VM reaching your actual devices** (e.g. over a VPN back to your home
   or campus network). Not covered here — this is just your VPN client
   working correctly on the VM.
2. **Your browser reaching the VM's services.** This is the one that breaks
   silently: the metrics dashboards and the "Devices"/"Recent Traps" tables
   all work fine no matter where your browser is (they're proxied
   server-side by Grafana), but the three panels above run their `fetch()`
   calls **in your browser**, hardcoded to `localhost`. Once Grafana isn't on
   the same machine as your browser, `localhost` resolves to *your own
   laptop*, not the VM, and those three panels fail outright.

What you need to update, once you've decided how the VM is reachable:

- [ ] **Add / Edit Device** panel's `http://localhost:8080` (Update Request code box)
- [ ] **Polling Interval** panel's `http://localhost:8080` (Initial Request + Update Request URL fields)
- [ ] **Ask about your network** panel's `http://localhost:8082` (Update Request code box)

Replace each with whatever address your browser can actually reach that
service at — this depends on how you expose the VM:

- **Cloudflare Tunnel (recommended over opening ports directly).** Give
  Grafana its own hostname, and give `config-api` and `chat-api` their own
  hostnames too (a tunnel can route multiple public hostnames to different
  internal ports) — then use those hostnames instead of `localhost` above.
  Put **Cloudflare Access** (their free Zero Trust auth) in front of the
  `config-api`/`chat-api` hostnames specifically: both have **no
  authentication of their own** (see Threat Model above), so exposing them
  publicly without something else guarding them means anyone who finds the
  URL can read/edit/delete your devices or query your chatbot for free.
- **A plain DNS A record + open ports.** Simpler, but this puts unauthenticated
  `config-api`/`chat-api` directly on the public internet with nothing in
  front of them — avoid this unless you add your own reverse proxy with auth,
  or at minimum firewall rules restricting those ports to your own IP.

## Colima users: enable the gRPC port-forwarder

If you're running this on colima instead
of Docker Desktop, `trap-receiver`'s UDP/162 listener will silently never
receive anything, even though `docker compose ps` shows the port published
and the sending router reports 0 drops. Colima's default port-forwarder
(`ssh`) tunnels published ports over `ssh -L`, and SSH port forwarding is
TCP-only by protocol design — it cannot carry UDP at all. Every other service
here is TCP (config-api, Grafana, InfluxDB), so this only shows up on the one
UDP-based component.

Fix: start colima with the `grpc` port-forwarder, which does support UDP:

```
colima stop
colima start --port-forwarder grpc
```

This restarts colima's VM, which briefly stops every running container until
they come back up (they have `restart: unless-stopped`, so no further action
needed). Docker Desktop, native Linux Docker, and Docker on Windows aren't
affected — they publish ports via a privileged helper process that handles
UDP natively, so this is colima-only.

## Health checks

`config-api` and `trap-receiver` both expose `GET /healthz` (trap-receiver on
`:8081` by default, separate from its UDP/162 trap listener).

## Testing

`go test ./...` runs the unit/handler tests. `scripts/integration-test.sh`
spins up a disposable copy of the metrics pipeline (InfluxDB, Telegraf,
config-api, config-watcher) plus a simulated SNMP agent
(`polinux/snmpd`), registers the agent as a device, and confirms a
Telegraf-collected metric shows up in InfluxDB — proving the
poll → InfluxDB path end-to-end. It builds its own images, uses an isolated
network/volumes, and tears everything down on exit:

```
./scripts/integration-test.sh
```
