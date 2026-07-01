# Multi-replica deployment artifacts (cookie-based session stickiness)

This directory holds reference load-balancer configs and a runnable smoke
harness for running `archetype-proxy-server` as **N>1 replicas** behind a
load balancer that pins each attested session to the replica that served its
handshake.

Read the server `README.md` section **"Multi-replica deployment (stickiness
model)"** first — it explains *why* sessions are replica-local and *why* a
backend-pinning **cookie** is the mechanism (header-hash on `Attest-Base-ID`
cannot work: the `AtbId` is minted inside the handshake, so the handshake
carries no routable key).

## The cookie rule in one paragraph

The LB sets a backend-pinning **affinity cookie** on the **`POST /attest`
handshake response** and routes by that cookie thereafter. The client's
`reqwest` transport carries a **cookie store** (shipped in task #20:
`session.rs` builds one long-lived `reqwest::Client` with `cookie_store(true)`
and reuses it across every handshake + trusted request and the whole session
pool), so it **echoes** the cookie on the follow-up trusted request → the
handshake and its single-use trusted request land on the **same replica**. For
WebSockets the same cookie pins the `GET` upgrade; once upgraded the socket
rides one TCP connection that the LB never rebalances, so all frames stay on
that replica for the socket's lifetime.

A residual miss (replica restart, cookie dropped, TTL race) is **not fatal**:
the client (task #19) auto-recovers by re-handshaking + retrying once on a bare
`401`/`403`, which is replay-safe (the rejection happens at the session gate,
before any upstream forward). This task makes misses **rare**; #19 makes a
residual miss **invisible**.

## Health-check routing (unauthenticated)

The server exposes three **unauthenticated** endpoints (see `proxy.rs`):

| Path       | Purpose    | LB use                                          |
|------------|------------|-------------------------------------------------|
| `/healthz` | liveness   | restart a hung replica                          |
| `/readyz`  | readiness  | **route traffic only to replicas returning 200**|
| `/metrics` | Prometheus | scrape per-replica (counters are per-replica)   |

All LB configs below health-check `/readyz` for readiness gating and `/healthz`
for liveness. **Never** put these behind attestation — the LB cannot present an
attested session.

## Files

| File | What it is |
|------|------------|
| `Dockerfile` | Builds the server image (MOCK posture, **smoke tests only**). |
| `Dockerfile.production` | Production image: feature-gated real TEE, no insecure-dev escape. See below. |
| `docker-compose.yml` | 2 replicas + a dummy upstream + an **nginx** sticky-cookie LB. Runnable smoke harness. |
| `nginx/nginx.conf` | Standalone nginx reverse proxy: sticky cookie upstream + WS Upgrade + `/readyz` health checks. |
| `haproxy/haproxy.cfg` | Alternative standalone LB: HAProxy `cookie SRVID insert indirect nocache` + per-server cookie ids + WS. |
| `k8s/` | Kubernetes manifests: Deployment (N replicas), Service, and an **nginx-ingress** Ingress with `affinity: cookie`. |
| `gateway-api/` | Kubernetes **Gateway API** manifests: inline `HTTPRoute` `sessionPersistence` + a `BackendLBPolicy`, both cookie-based (GEP-1619). **EXPERIMENTAL** + uneven controller support — read [`gateway-api/README.md`](gateway-api/README.md) first. |
| `smoke-test.sh` | Brings up `docker-compose`, points a request batch at the LB, asserts all succeed and that BOTH replicas served handshakes (proves load-spreading) with zero failures (proves stickiness). |

## Smoke image vs production image

There are two Dockerfiles, and they are NOT interchangeable:

| | `Dockerfile` (smoke) | `Dockerfile.production` |
|---|---|---|
| Attestation | MOCK only (no TEE features) | feature-gated real TEE via `--build-arg FEATURES=...` |
| `ARCHETYPE_PROXY_INSECURE_DEV` | set to `1` (in `docker-compose.yml`) so the release no-mock guard does not refuse to boot | **never set** -- a no-feature build correctly refuses to start in release |
| Builder toolchain | relies on the base image's default clang | installs `go`, `cmake`, `clang`, `libclang-dev` explicitly; pins `CC=clang` |
| Runtime user | default | dedicated non-root uid 10001 |
| Purpose | multi-replica stickiness smoke test | real deployment |

Build a production image (must pick a real TEE feature set for your platform):

```sh
# context = repo root
docker build -f deploy/Dockerfile.production \
  --build-arg FEATURES=tdx,maa \
  -t archetype-proxy-server:prod .

docker run --rm -e ARCHETYPE_PROXY_LISTEN=0.0.0.0:8443 -p 8443:8443 \
  archetype-proxy-server:prod
```

Valid `FEATURES` (comma-separated): providers `tdx sev_snp sgx trustzone
aws_nitro`; verifiers `maa ita amd_snp`; plus `kubernetes` for k8s discovery.
Each real-TEE feature needs the matching hardware SDK / system library at build
and run time. Building with **no** features yields a mock-only image that will
refuse to start in release mode -- that is the intended safety default, not a
bug; configure a real `tee_provider`+`verifier` with `allow_mock=false`.

**Build-toolchain note (both images):** the dependency graph compiles
`aws-lc-fips-sys` (Go + cmake + C compiler, via the `fips` feature inherited
from the OpenHTTPA workspace) and `oqs-sys` (bindgen, needs libclang). On Debian
bookworm the default libclang is v14, so the oqs-sys + libclang>=19 bindgen bug
does not bite (it does on bleeding-edge distros such as Arch -- see
`packaging/arch/PKGBUILD`). The production builder sets `CC=clang` because the
aws-lc-fips FIPS delocate step can abort under very new GCC/binutils.

An Arch Linux **PKGBUILD** (systemd unit, libclang<=18 + go/cmake handling) lives
in `packaging/arch/`.

## Quick start (smoke test)

```sh
cd archetype-proxy-server/deploy
./smoke-test.sh          # builds, brings up 2 replicas + nginx LB, runs the batch
```

The smoke test is documented as **automated** where Docker is available; if you
have no Docker daemon, follow the **Manual test procedure** at the bottom of
`smoke-test.sh`.

## Standalone LB choice

The compose harness uses **nginx** (`ngx_http_upstream_module` is everywhere and
the config is the most compact for a cookie + WS Upgrade combo). HAProxy is
provided as a clean alternative (`haproxy/haproxy.cfg`); its `cookie ... insert
indirect nocache` is arguably the most explicit cookie-affinity primitive.
**Traefik** sticky sessions (`loadBalancer.sticky.cookie`) also work and need no
client change beyond the cookie store — use whichever your platform favors. All
set a cookie on the first response and route by it; only the directive
names differ.

For a **Gateway API** controller (Istio, Cilium, Envoy Gateway, etc.), the same
cookie mechanism is expressed via GEP-1619 `sessionPersistence` /
`BackendLBPolicy` — see [`gateway-api/`](gateway-api/). Note that GEP-1619 is
**experimental** and controller support is **uneven**; verify your controller
implements `HTTPRouteSessionPersistence` before relying on it.
