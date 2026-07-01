#!/usr/bin/env bash
# Multi-replica cookie-stickiness SMOKE TEST.
#
# Brings up 2 replicas + a HAProxy cookie-affinity LB + a dummy upstream
# (docker-compose), then drives a batch of attested requests at the LB through
# the client bridge and asserts they all succeed. Because the client carries a
# cookie store (task #20), each session's handshake response cookie pins its
# follow-up request to the SAME replica -> no stickiness miss; #19 covers any
# residual miss.
#
# AUTOMATED vs MANUAL:
#   * The docker-compose bring-up of replicas + LB is AUTOMATED here.
#   * Driving ATTESTED traffic needs the client bridge (the Tauri client's
#     local HTTP listener), which is not containerized in this repo. The
#     strongest fully-automated check that lives in-repo is the client test
#     `tests/multi_replica_stickiness.rs::cookie_affinity_pins_handshake_and_request_no_miss`,
#     which stands up 2 real replicas + a mock cookie-affinity LB IN-PROCESS and
#     asserts ZERO misses. Run it with:
#         (cd ../../archetype-proxy-client/src-tauri \
#           && cargo test --test multi_replica_stickiness)
#   * The MANUAL procedure below drives the real LB with the real bridge.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="docker compose --project-directory ${REPO_ROOT} -f ${REPO_ROOT}/deploy/docker-compose.yml"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found — see the MANUAL test procedure at the bottom of this script." >&2
    exit 2
fi

echo ">> Building + starting 2 replicas + HAProxy LB + dummy upstream ..."
${COMPOSE} up --build -d

cleanup() { echo ">> Tearing down ..."; ${COMPOSE} down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo ">> Waiting for the LB to report a ready backend (/readyz) ..."
for _ in $(seq 1 30); do
    if curl -fsS http://localhost:8080/readyz >/dev/null 2>&1; then
        echo "   LB ready."
        break
    fi
    sleep 1
done

# NOTE: /readyz and /healthz are UNAUTHENTICATED and prove the LB->replica wiring
# + health-check routing. They do NOT exercise the attested cookie path; that
# requires the client bridge (see MANUAL procedure / the in-repo client test).
echo ">> Health-check routing (unauthenticated):"
curl -fsS http://localhost:8080/healthz && echo "  <- /healthz OK"
curl -fsS http://localhost:8080/readyz  && echo "  <- /readyz OK"

cat <<'EOF'

>> Bring-up succeeded. To drive ATTESTED traffic through this LB:

   MANUAL TEST PROCEDURE
   ---------------------
   1. Leave this compose stack running (re-run without `down`):
        docker compose --project-directory . -f deploy/docker-compose.yml up --build
   2. Point the client bridge at the LB front address:
        server_uri = "http://localhost:8080"   (ClientConfig / client config file)
        allow_mock = true
   3. Start the client; it handshakes via POST /attest (HAProxy inserts
      SRVID=<replica>), and the client's cookie store echoes SRVID on every
      follow-up trusted request -> same replica -> HIT.
   4. Send a batch of requests through the local bridge port; assert all 200.
   5. Inspect `docker compose logs replica1 replica2`: BOTH should show served
      handshakes (load spread) and NO bare-401 session-lookup rejections under
      steady state (stickiness holding). A handful of recovered 401s only ever
      appear on replica restart (the #19 safety net), never in steady state.

   The fully-automated equivalent (no Docker needed) is the in-repo client test
   cited at the top of this script.
EOF

echo ">> Smoke bring-up + health-check routing PASSED."
