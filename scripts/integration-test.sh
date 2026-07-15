#!/usr/bin/env bash
# Basic end-to-end integration test (plan §6 Phase 8):
#   fake SNMP agent -> Telegraf -> InfluxDB
#
# Spins up a real, disposable stack (its own network/volumes, no ports
# published to the host) alongside a simulated SNMP agent, registers it as a
# device via config-api, waits for a poll cycle, and confirms the resulting
# metric landed in InfluxDB. Tears everything down on exit regardless of outcome.
set -euo pipefail

cd "$(dirname "$0")/.."

NET=network-monitor-inttest-net
PREFIX=nmit
DB=network_monitor

cleanup() {
  echo "--- cleaning up ---"
  docker rm -f "${PREFIX}-influxdb" "${PREFIX}-telegraf" "${PREFIX}-config-api" "${PREFIX}-config-watcher" "${PREFIX}-snmpd" >/dev/null 2>&1 || true
  docker volume rm "${PREFIX}-data" "${PREFIX}-telegraf-config" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "--- building images ---"
docker build -q -f config-api/Dockerfile -t nmit-config-api:test . >/dev/null
docker build -q -f config-watcher/Dockerfile -t nmit-config-watcher:test . >/dev/null

docker network create "$NET" >/dev/null

echo "--- starting simulated SNMP agent (polinux/snmpd, community 'public') ---"
docker run -d --name "${PREFIX}-snmpd" --network "$NET" --network-alias snmp-agent polinux/snmpd >/dev/null

echo "--- starting InfluxDB 3 Core (in-memory) ---"
docker run -d --name "${PREFIX}-influxdb" --network "$NET" --network-alias influxdb influxdb:3-core \
  influxdb3 serve --node-id=node0 --object-store=memory --http-bind=0.0.0.0:8181 >/dev/null
sleep 3

TOKEN=$(docker exec "${PREFIX}-influxdb" influxdb3 create token --admin 2>&1 | grep -oE 'apiv3_[A-Za-z0-9_-]+' | head -1)
docker exec -e TOK="$TOKEN" "${PREFIX}-influxdb" sh -c "influxdb3 create database $DB --token \"\$TOK\"" >/dev/null

echo "--- starting config-api ---"
ENCKEY=$(openssl rand -hex 32)
docker volume create "${PREFIX}-data" >/dev/null
docker run -d --name "${PREFIX}-config-api" --network "$NET" --network-alias config-api \
  -e CONFIG_DB_PATH=/data/config.db -e TRAPS_DB_PATH=/data/traps.db -e ENCRYPTION_KEY="$ENCKEY" \
  -v "${PREFIX}-data:/data" \
  nmit-config-api:test >/dev/null
sleep 1

echo "--- registering the simulated agent as an active device ---"
docker run --rm --network "$NET" curlimages/curl:latest -sf -X POST http://config-api:8080/devices \
  -H "Content-Type: application/json" \
  -d '{"ip_address":"snmp-agent","snmp_version":"v2c","community":"public"}' >/dev/null
docker run --rm --network "$NET" curlimages/curl:latest -sf -X PATCH http://config-api:8080/devices/1 \
  -H "Content-Type: application/json" -d '{"status":"active"}' >/dev/null
# Shortest allowed interval, so the test doesn't have to wait out Telegraf's
# default 60s collection/flush cycle (plus round_interval's alignment delay).
docker run --rm --network "$NET" curlimages/curl:latest -sf -X POST http://config-api:8080/settings/polling-interval \
  -H "Content-Type: application/json" -d '{"polling_interval_seconds":30}' >/dev/null

echo "--- starting Telegraf ---"
docker volume create "${PREFIX}-telegraf-config" >/dev/null
# --restart unless-stopped: telegraf.conf doesn't exist until config-watcher's
# first reconcile pass writes it, so telegraf crash-loops briefly on startup by
# design (see README/Phase 3 notes) — it picks up the config on its next restart.
docker run -d --name "${PREFIX}-telegraf" --network "$NET" --restart unless-stopped \
  -v "${PREFIX}-telegraf-config:/etc/telegraf" \
  -v "$(pwd)/telegraf/mibs:/etc/telegraf/.snmp/mibs:ro" \
  telegraf:1.32 >/dev/null

echo "--- starting config-watcher (generates telegraf.conf, reloads Telegraf) ---"
docker run -d --name "${PREFIX}-config-watcher" --network "$NET" \
  -e CONFIG_DB_PATH=/data/config.db -e ENCRYPTION_KEY="$ENCKEY" \
  -e INFLUXDB_URL=http://influxdb:8181 -e INFLUXDB_DATABASE="$DB" -e INFLUXDB_TOKEN="$TOKEN" \
  -e TELEGRAF_CONTAINER_NAME="${PREFIX}-telegraf" -e CONFIG_WATCHER_POLL_SECONDS=5 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${PREFIX}-telegraf-config:/etc/telegraf" \
  --volumes-from "${PREFIX}-config-api" \
  nmit-config-watcher:test >/dev/null

echo "--- waiting for a poll cycle (up to 180s) ---"
# Checks the "snmp" measurement (sysUptime, always present on any real SNMP
# agent) rather than "interface": polinux/snmpd, the lightweight simulator this
# test uses, only implements the base SNMPv2-MIB system group and has no
# IF-MIB ifTable to walk (confirmed via snmpwalk — "No Such Object"). Against
# a real router/switch the interface table would populate too; what this test
# proves is the full pipeline (SNMP walk -> Telegraf -> InfluxDB write -> query).
ok=false
for i in $(seq 1 36); do
  sleep 5
  resp=$(docker exec -e TOK="$TOKEN" "${PREFIX}-influxdb" sh -c \
    "curl -s -H \"Authorization: Bearer \$TOK\" http://localhost:8181/api/v3/query_sql -H 'Content-Type: application/json' -d '{\"db\":\"$DB\",\"q\":\"SELECT * FROM snmp LIMIT 1\"}'" || true)
  if echo "$resp" | grep -q "uptime"; then
    echo "--- metric found in InfluxDB after $((i*5))s ---"
    echo "$resp"
    ok=true
    break
  fi
done

if [ "$ok" != "true" ]; then
  echo "--- FAILED: no interface metric appeared in InfluxDB within 180s ---"
  echo "--- config-watcher logs ---"; docker logs "${PREFIX}-config-watcher" 2>&1 | tail -30
  echo "--- telegraf logs ---"; docker logs "${PREFIX}-telegraf" 2>&1 | tail -60
  exit 1
fi

echo "--- PASS: fake SNMP agent -> Telegraf -> InfluxDB confirmed end-to-end ---"
