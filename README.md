# archetype-proxy-server

A reverse proxy that puts TEE attestation in front of existing HTTP(S)
backends, built on the [OpenHTTPA](https://github.com/OpenHTTPA/openhttpa-rs)
protocol crates. It terminates attested OpenHTTPA sessions and forwards the
decrypted traffic to upstreams chosen per request from a route table.

Routes come from a TOML file and, optionally, from Docker labels or Kubernetes
Service/Ingress annotations, merged into a live table that reloads on change.
Attestation providers, TLS, discovery, rate limiting, and observability are all
configurable; see below.

## Build

```sh
cargo build
```

OpenHTTPA is a git dependency pinned to a specific commit
(`archetype-linux/openhttpa-rs`, currently `aa07d6a7`) and is not on crates.io.
This is a fork of upstream OpenHTTPA where TPM/measured-boot attestation is
being developed.

The default build is mock-only: no TEE hardware or SDKs, buildable anywhere.
Real attestation is opt-in behind cargo features (see [Attestation
providers](#attestation-providers)).

### Build environment

OpenHTTPA pins `aws-lc-rs` with the `fips` feature and depends on `oqs-sys`,
which together require:

- **Go, cmake, and a C compiler** — the `fips` feature builds `aws-lc-fips-sys`
  via Go and cmake. Set `CC=clang CXX=clang++`; the FIPS module's assembly step
  fails with recent GCC.
- **libclang ≤ 18.** `oqs-sys` 0.11 runs `bindgen` in a mode that produces a
  broken `OQS_SIG` layout assertion under libclang ≥ 19 (Fedora 44 ships clang
  22), failing the build with an `OQS_SIG` size overflow. Point `LIBCLANG_PATH`
  at a libclang ≤ 18 directory; this only affects the libclang bindgen loads,
  not your default clang.
- **Adequate `/tmp`.** The FIPS build needs more scratch space than a small
  tmpfs; set `TMPDIR` to a real-disk path if `/tmp` is tmpfs-backed.

On Fedora:

```sh
sudo dnf install clang clang18-libs cmake golang gcc

export LIBCLANG_PATH=/usr/lib64/llvm18/lib   # libclang <= 18 for oqs-sys bindgen
export CC=clang CXX=clang++                  # clang C compiler for aws-lc-fips
# export TMPDIR=/var/tmp                      # if /tmp is a small tmpfs
cargo build --release
```

`clang18-libs` supplies the libclang bindgen loads; `clang` is the C compiler
for the FIPS build. They are separate packages.

## Install

Install the release binary and the example config:

```sh
install -Dm755 target/release/archetype-proxy-server /usr/local/bin/archetype-proxy-server
install -Dm644 archetype-proxy.toml /etc/archetype-proxy/archetype-proxy.toml
```

The server reads its config from the path given on the command line, then
`ARCHETYPE_PROXY_CONFIG`, then `./archetype-proxy.toml`.

On Arch, build and install the package from `packaging/arch/`:

```sh
cd packaging/arch && makepkg -si
```

That installs the binary, the example config under `/etc/archetype-proxy/`, and
a systemd unit. A default (mock) build refuses to start in release mode; build
with a TEE feature for production (`_FEATURES="tdx,maa" makepkg -si`). Enable the
service once configured:

```sh
sudo systemctl enable --now archetype-proxy-server
```

## Configuration

Configuration has two tiers, following Traefik's model:

- **Static** (`[server]`, `[attestation]`, `[discovery]`) — how the proxy boots
  and which discovery providers run. Read once at startup.
- **Dynamic** (`[[route]]`) — the attested routes. Comes from the file and from
  discovery providers, and reloads when a provider reports a change.

See `archetype-proxy.toml` for the full annotated schema.

### Precedence

Highest wins:

```
CLI flag  >  ARCHETYPE_PROXY_* env var  >  discovered labels/annotations  >  TOML file  >  defaults
```

Each resolved static field records the layer that set it. Inspect the resolved
config with the `dump` subcommand:

```sh
archetype-proxy-server dump
archetype-proxy-server --config ./archetype-proxy.toml dump
```

### Environment variables

`ARCHETYPE_PROXY_CONFIG`, `_LISTEN`, `_MAX_BODY_BYTES`, `_ALLOW_MOCK`,
`_STRICT_ATTESTATION`, `_ATB_TTL_SECS`, `_ATB_EVICTION_INTERVAL_SECS`,
`_ATB_MAX_SESSIONS`, `_RATE_LIMIT_MAX_REQUESTS`, `_RATE_LIMIT_WINDOW_SECS`,
`_TEE_PROVIDER`, `_VERIFIER`, `_VERIFIER_ENDPOINT`, `_VERIFIER_API_KEY`,
`_DOCKER`, `_DOCKER_SOCKET`, `_DOCKER_POLL_SECS`, `_KUBERNETES`,
`_KUBERNETES_NAMESPACE` (all prefixed `ARCHETYPE_PROXY`).

`ARCHETYPE_PROXY_KUBERNETES_NAMESPACE` is three-state: unset inherits the lower
layer, a value sets the namespace filter, and an empty string clears it (watch
all namespaces), which lets a higher layer override a file-set namespace.

### CLI flags

```
[config-path]        positional config file path
--config <path>      config file (takes precedence over the positional path)
--listen <addr>
--max-body-bytes <n>
--docker             enable Docker discovery (default off)
--kubernetes         enable Kubernetes discovery (default off)
--log-level <level>  off | error | warn | info | debug | trace
-v / -vv / -vvv      debug / trace / trace
dump                 print the resolved config and exit
```

`--docker` and `--kubernetes` enable their provider; omitting a flag inherits
the TOML/env layers. To disable a provider a lower layer enabled, set it false
there. Invalid flag values exit non-zero. Run `--help` for full usage.

### Routing

A request matches the most specific route by host (exact, case-insensitive) and
path prefix; a host match beats a catch-all, and a longer prefix wins. Path
prefixes match on segment boundaries, so `/v1` matches `/v1` and `/v1/foo` but
not `/v123`. On an exact host+prefix tie, a discovered route overrides a file
route. No match returns `404`. A legacy `[upstream] target` becomes a catch-all
route.

## Attestation providers

The server builds its quote provider and verifier from `[attestation]`:

```toml
[attestation]
tee_provider = "mock"   # mock | tdx | sev_snp | sgx | trustzone | aws_nitro | tpm
verifier     = "mock"   # mock | maa | ita | amd_snp | tpm
# verifier_endpoint = "https://sharedeus2.eus2.attest.azure.net"  # MAA / ITA
# verifier_api_key  = "..."                                       # ITA only
```

Non-mock variants compile only with the matching cargo feature, because the
underlying crates link hardware SDKs:

| feature     | provider / verifier                |
|-------------|------------------------------------|
| `tdx`       | Intel TDX                          |
| `sev_snp`   | AMD SEV-SNP                        |
| `sgx`       | Intel SGX                          |
| `trustzone` | ARM TrustZone                      |
| `aws_nitro` | AWS Nitro Enclaves                 |
| `maa`       | Azure Microsoft Attestation        |
| `ita`       | Intel Trust Authority              |
| `amd_snp`   | AMD SEV-SNP VCEK chain verifier    |
| `tpm`       | TPM 2.0 measured-boot provider + verifier |

```sh
cargo build --release --features tdx,maa
cargo build --release --features sev_snp,amd_snp
cargo build --release --features tpm
```

These require confidential-compute hardware and their SDKs at build time. If a
provider is selected at runtime without its feature compiled in, the server
exits with a message naming the required feature. `dcap` and `nvidia` verifiers
are rejected: the pinned OpenHTTPA revision has no production verifier for them.

### TPM 2.0 measured boot (`tpm` feature)

> **Caveat: measured boot is not enclave isolation.** A TPM quote attests the
> host's *boot state* (firmware/bootloader/kernel measurements in the PCRs). It
> does **not** prove the session-terminating process runs in confidential,
> integrity-protected memory the way a TDX/SEV-SNP/SGX enclave attestation does.
> It is a different, weaker guarantee.

The `tpm` feature enables a real `tss-esapi`-backed quote provider
(`openhttpa-tee/tpm`) and a **fail-closed** verifier
(`openhttpa-attestation/tpm`). Select it in `[attestation]` and supply a
reference policy under `[attestation.tpm]`:

```toml
[attestation]
tee_provider = "tpm"
verifier     = "tpm"

[attestation.tpm]
# AK trust (choose exactly one of the three modes below — see "AK trust").
# 1. Pin the AK public key (uncompressed SEC1, 0x04 || X || Y, hex):
# pinned_ak_sec1_hex = "04abcd..."
# 2. Chain the AK to trusted EK/manufacturer root cert(s) (PEM or DER files):
# trusted_ek_root_paths = ["/etc/archetype/ek-root.pem"]
# 3. Accept an unpinned AK (INSECURE, dev/test only):
# allow_unpinned_ak = false

# Optional: PCR indices the provider quotes (advisory; the verifier's
# authority is expected_pcrs). Defaults to SHA-256 PCRs 0-7.
# pcr_selection = [0, 1, 2, 3, 4, 5, 6, 7]

# Expected PCR values: index -> hex SHA-256 digest. REQUIRED and non-empty.
# The verifier reconstructs the composite in ascending index order and
# compares it to the signed pcrDigest. Every listed index must match.
[attestation.tpm.expected_pcrs]
0 = "0000000000000000000000000000000000000000000000000000000000000000"
7 = "0000000000000000000000000000000000000000000000000000000000000000"
```

Env equivalents (highest-precedence layers still win as usual):

```sh
ARCHETYPE_PROXY_TPM_EXPECTED_PCRS="0:0000...,7:0000..."
ARCHETYPE_PROXY_TPM_PINNED_AK_SEC1_HEX="04abcd..."
ARCHETYPE_PROXY_TPM_PCR_SELECTION="0,1,2,3,4,5,6,7"
# Trusted EK root cert files, separated by commas or colons:
ARCHETYPE_PROXY_TPM_TRUSTED_EK_ROOT_PATHS="/etc/archetype/ek-root.pem"
ARCHETYPE_PROXY_TPM_ALLOW_UNPINNED_AK="false"
```

#### AK trust

The verifier authenticates the boot state (PCRs) *and* the attestation key
(AK) that signed the quote. Because a quote signed by an unknown AK proves
nothing about *which* TPM produced it, the verifier **fails closed** unless the
AK is trusted by one of three modes. Configure exactly one:

1. **Pin the AK** (`pinned_ak_sec1_hex` /
   `ARCHETYPE_PROXY_TPM_PINNED_AK_SEC1_HEX`) — the AK's public key must
   byte-match this uncompressed SEC1 value. Trust-on-first-use; simplest for a
   single known host.
2. **Chain to a trusted EK root** (`trusted_ek_root_paths` /
   `ARCHETYPE_PROXY_TPM_TRUSTED_EK_ROOT_PATHS`) — a list of PEM or DER X.509
   root-CA files (TPM-manufacturer / EK roots). An unpinned AK is accepted if
   its certificate chain (carried in the evidence) walks up to one of these
   roots. Cert files are read and DER-validated at startup; an unreadable or
   malformed file is a fatal startup error naming the file.
3. **Allow an unpinned AK** (`allow_unpinned_ak = true` /
   `ARCHETYPE_PROXY_TPM_ALLOW_UNPINNED_AK=true`) — **INSECURE, dev/test only.**
   Accepts any AK (boot-state/PCR checks still run, but AK authenticity is not
   verified, so a rogue TPM cannot be detected). The server logs a loud warning
   banner at startup when this is in effect.

If `verifier = "tpm"` or `tee_provider = "tpm"` and
`[attestation.tpm].expected_pcrs` is missing or empty, **or** none of the three
AK-trust modes above is configured, the server refuses to start with an
actionable config error (rather than failing closed per request at runtime with
a confusing message).

**Build dependencies.** The `tpm` feature links `tss-esapi` against the system
tpm2-tss libraries. The swtpm integration test additionally needs a software
TPM:

```sh
dnf install -y tpm2-tss-devel tpm2-tss tpm2-tools swtpm swtpm-tools
cargo build --features tpm
cargo test  --features tpm --test tpm_swtpm   # skips cleanly if swtpm is absent
```

**Deferred (documented follow-ups):** EK-certificate -> AK cert-chain
provisioning (AK pinning is the milestone-1 substitute), TCG event-log replay to
derive expected PCRs (raw PCR comparison only for now), and live vTPM/hardware
validation.

### Mock attestation guard

Mock attestation provides no security — quotes are not bound to real hardware.
A release build refuses to start when mock attestation is in effect
(`allow_mock = true`, `tee_provider = "mock"`, or `verifier = "mock"`):

| build   | mock in effect | `ARCHETYPE_PROXY_INSECURE_DEV` | result             |
|---------|----------------|--------------------------------|--------------------|
| release | no             | —                              | starts             |
| release | yes            | unset                          | refuses to start   |
| release | yes            | `1`                            | starts, warns      |
| debug   | yes            | —                              | starts, warns      |
| debug   | no             | —                              | starts             |

```sh
ARCHETYPE_PROXY_INSECURE_DEV=1 ./archetype-proxy-server   # release + mock
```

## Observability

Three unauthenticated endpoints (no attestation, so probes and scrapers work
directly):

- `GET /healthz` — liveness.
- `GET /readyz` — readiness.
- `GET /metrics` — Prometheus text exposition.

| metric                                     | type      | meaning                          |
|--------------------------------------------|-----------|----------------------------------|
| `archetype_proxy_handshakes_total`         | counter   | successful `POST /attest`        |
| `archetype_proxy_active_sessions`          | gauge     | live sessions in the registry    |
| `archetype_proxy_decrypt_failures_total`   | counter   | trusted-request decrypt failures |
| `archetype_proxy_upstream_requests_total`  | counter   | upstream requests attempted      |
| `archetype_proxy_upstream_errors_total`    | counter   | upstream transport failures      |
| `archetype_proxy_upstream_latency_seconds` | histogram | upstream round-trip latency      |

### Logging

`tracing` events go to stderr. Filter precedence, highest first: `RUST_LOG`
(full `EnvFilter` syntax), then `--log-level`, then `-v`/`-vv`/`-vvv`, then the
default `info`.

```sh
RUST_LOG=archetype_proxy_server=debug,openhttpa_server=debug archetype-proxy-server
archetype-proxy-server --log-level debug
archetype-proxy-server -vv
```

To debug a client that cannot connect, run both sides with `-vv`. The server
logs its bound address at startup; confirm it matches the client's
`--server-uri`. A `Transport` error on the client means the server is not
reachable at that address; an attestation error usually means `allow_mock`
differs between the two.

## TLS

The proxy always terminates the inner attested OpenHTTPA session. Public
transport TLS in front of it is configured separately, three ways:

- **In-process** — set `[server.tls]` and the server terminates TLS itself via
  `axum-server` and rustls (aws-lc-rs backend). All endpoints serve over TLS.
- **Behind an ingress or load balancer** — omit `[server.tls]` and let nginx,
  Envoy, a cloud LB, or a Kubernetes ingress terminate TLS, forwarding to the
  plaintext listener on a trusted network.
- **Upstream** — use `https://` upstream URLs when the upstream is not
  same-host or on a trusted network.

If `[server.tls]` is set but the cert or key is missing, unreadable, or invalid,
the server aborts at startup rather than falling back to plaintext.

A `[server.tls]` block must configure exactly one cert source — static PEM
files or ACME, never both or neither. `TlsConfig::validate()` enforces this at
startup.

### Static certificate

```toml
[server.tls]
cert_path = "/etc/archetype/tls/fullchain.pem"
key_path  = "/etc/archetype/tls/privkey.pem"
```

### ACME

With `[server.tls.acme] enabled = true` the server obtains and renews its
certificate from an ACME CA (Let's Encrypt by default). Renewal runs in the
background and re-issues when under 30 days remain; a valid cached cert under
`cache_dir` is reused across restarts. If there is no usable cached cert and
issuance fails, the server aborts rather than serve plaintext or an expired
cert.

```toml
[server.tls.acme]
enabled   = true
domains   = ["proxy.example.com"]       # cert SANs; at least one
contact   = "ops@example.com"
challenge = "tls-alpn-01"               # tls-alpn-01 (default) | http-01 | dns-01
staging   = true                        # Let's Encrypt staging while testing
cache_dir = "/var/lib/archetype/acme"
# directory_url = "https://acme.example/dir"   # explicit CA; overrides `staging`
```

| challenge     | requirement                                                       | wildcard |
|---------------|-------------------------------------------------------------------|----------|
| `tls-alpn-01` | CA reaches inbound `:443` (served via the `acme-tls/1` ALPN)      | no       |
| `http-01`     | CA reaches inbound `:80` (or `http01_listen`) for the token path  | no       |
| `dns-01`      | a `_acme-challenge` TXT record is published                       | yes      |

`http-01` uses `http01_listen` (default `<listen-ip>:80`). `dns-01` supports
wildcards and takes a `[server.tls.acme.dns]` block with a `provider` of
`manual` or `cloudflare`.

The `manual` provider runs `hook_command` to publish the TXT record (passing
`ACME_DNS_DOMAIN`, `ACME_DNS_NAME`, `ACME_DNS_VALUE` in the environment), or
logs the record for out-of-band publication.

The `cloudflare` provider publishes the record via the Cloudflare API:

```toml
[server.tls.acme.dns]
provider      = "cloudflare"
api_token_env = "CF_API_TOKEN"          # env var holding the token (preferred)
# api_token   = "..."                    # inline token (works, discouraged)
# zone_id     = "..."                     # explicit zone; else auto-discovered
```

The token needs `Zone:DNS:Edit`, plus `Zone:Read` if `zone_id` is omitted (the
provider then discovers the zone from the record name). Prefer `api_token_env`
over an inline `api_token`.

Use `staging = true` while testing: Let's Encrypt production
[rate limits](https://letsencrypt.org/docs/rate-limits/) are strict and a
misconfiguration can lock you out for a week. Live issuance requires the CA to
reach the challenge endpoint, so it can only be exercised against a publicly
reachable deployment. The challenge dispatch, config validation, HTTP-01 token
store, TLS-ALPN-01 validation cert, DNS hook, and the Cloudflare provider
(against a local API stub) are unit-tested; live issuance — including DNS-01
against a real Cloudflare token/zone and public DNS propagation — is not.

## Discovery

Discovery providers push a full route snapshot when they observe a change; a
route manager merges file routes with the latest snapshot into a hot-swappable
table. A provider that is unreachable or misconfigured logs a warning and the
proxy keeps serving file and env routes.

### Docker

```toml
[discovery]
docker = true
```

Polls the Docker socket for `archetype.*` container labels:

```
archetype.enable = true
archetype.attestation.strict = true                 # optional container default
archetype.route.<name>.upstream = http://api:8080   # required per route
archetype.route.<name>.host = api.internal          # optional
archetype.route.<name>.pathprefix = /v1             # optional
archetype.route.<name>.strict = true               # optional per-route
```

A container may declare multiple routes via distinct `<name>` segments. An
enabled container with no `archetype.route.*` keys but a top-level
`archetype.upstream` (with optional `archetype.host` and
`archetype.pathprefix`) yields one implicit route.

Docker discovery is off by default because it requires access to the Docker
socket, which is root-equivalent on the host. Prefer a read-only
[docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
exposing only container listing, and point `docker_socket` at it.

### Kubernetes

Requires the `kubernetes` cargo feature (kept out of the default build to avoid
the `kube`/`k8s-openapi` dependencies):

```sh
cargo build --release --features kubernetes
```

```toml
[discovery]
kubernetes = true
```

A kube-rs watcher lists and watches Services and Ingresses, mapping
`archetype.li/*` annotations to routes:

```
archetype.li/enable = "true"
archetype.li/upstream = "http://svc:80"   # required
archetype.li/host = "api.internal"        # optional
archetype.li/path-prefix = "/v1"          # optional
archetype.li/strict = "true"              # optional
```

Setting `kubernetes = true` on a binary built without the feature logs a
warning and serves file/env routes only. The `kube` dependency selects
`rustls-tls` with `aws-lc-rs` to keep `ring` out of the tree.

`kubernetes_namespace` is three-state (see [Environment
variables](#environment-variables)): unset watches the lower layer's namespace,
a value watches that namespace, an empty string watches all namespaces.

The proxy's ServiceAccount needs `get`/`list`/`watch` on `services` (core) and
`ingresses` (`networking.k8s.io`) — a `Role` for a single namespace or a
`ClusterRole` for all. Example RBAC is under [`deploy/`](deploy/).

## Request handling

### Error sealing

Once a request passes the session gate and decrypts, every proxy-side error is
sealed into the same response envelope as a normal upstream reply and returned
over an attested `200`, carrying the real status:

| condition                    | sealed status |
|------------------------------|---------------|
| no matching route            | `404`         |
| upstream unreachable         | `502`         |
| upstream timeout             | `504`         |
| request/response body too large | `413`      |
| invalid method               | `400`         |

The OpenHTTPA client reports any bare non-2xx as a transport error, so sealing
the real status lets the client recover it. Only a genuine transport or
handshake failure surfaces as an error. Pre-session responses are not sealed:
the handshake endpoint, session-gate rejections, and `/healthz`.

### Limits and hardening

- The encrypted request envelope is size-capped before hex-decoding, so a
  client cannot force unbounded buffering ahead of the plaintext body check.
- The upstream response body is streamed and aborted once it exceeds
  `max_body_bytes` (sealed `413`); an oversized `Content-Length` is rejected up
  front.
- Hop-by-hop headers, including those named in the upstream `Connection` header,
  are stripped before sealing.
- A background task evicts expired sessions from the registry (`atb_ttl_secs`,
  `atb_eviction_interval_secs`, `atb_max_sessions`).
- An optional per-IP sliding-window rate limit
  (`[rate_limit] max_requests` / `window_secs`, `0` disables) applies to all
  routes.

### Streaming and WebSocket

Responses stream as chunked AEAD frames, so a large upstream response is not
buffered whole. Requests are sealed monolithically: the client draws a random
per-request nonce under a sliding-window guard, which cannot be decoded as a
stream, so request streaming is out of scope pending an OpenHTTPA change.

Attested WebSocket passthrough is supported: an attested `GET` upgrade carrying
`Attest-Base-ID` is dialed through to the route's upstream WebSocket, with
frames sealed under an ordered-counter nonce. One session carries the whole
socket.

## Multi-replica deployment

The session registry is in-memory per replica; OpenHTTPA exposes no shared-store
hook, so running N replicas behind a load balancer relies on session
stickiness.

The handshake mints a random session ID inside the handler and stores the
session in the registry of the replica that served it. Every later trusted
request (and any WebSocket upgrade) carries that ID and is looked up in the
local registry; if it lands on a different replica the lookup misses and the
request is rejected with a bare `401` before it reaches the upstream. So the
load balancer must route a session's requests back to its handshake replica.

**Use cookie-based stickiness.** The handshake response carries no session ID,
so the LB cannot hash requests by it; instead the LB sets a backend-affinity
cookie on the `/attest` response and routes by that cookie thereafter. The
client echoes the cookie (its `reqwest` transport is built once with a cookie
store and reused across the handshake, trusted requests, and session pool). A
WebSocket upgrade is pinned by the same cookie, then rides one TCP connection
the LB will not rebalance. L4 source-IP affinity works as a coarser fallback and
needs no client cookie support.

Stickiness is best-effort. If a trusted request still lands on the wrong replica
(LB misconfiguration or a replica restart), the client recovers: a bare
`401`/`403` triggers one fresh handshake and retry. This is replay-safe because
the rejection happens before the request reaches the upstream (bare non-2xx
responses are always pre-forward here). Ambiguous errors — a bare `5xx` or
timeout, which may occur after the upstream saw the request — are surfaced, not
retried.

Other per-replica state to account for: the rate limit is per replica (global
limit is `max_requests × N`), `/metrics` are per replica (scrape and aggregate
all replicas), and eviction and replay guarding are per session and correct
under stickiness.

Reference load-balancer configs and a smoke harness are under
[`deploy/`](deploy/) — see [`deploy/README.md`](deploy/README.md):

- **Kubernetes** ([`deploy/k8s/`](deploy/k8s/)): 3-replica Deployment + Service +
  ingress-nginx Ingress with cookie affinity and WebSocket timeouts; probes on
  `/readyz` and `/healthz`.
- **HAProxy** ([`deploy/haproxy/`](deploy/haproxy/)): `cookie SRVID insert
  indirect nocache` with per-server cookie IDs; `/attest` load-spreads via round
  robin, follow-ups pin by cookie; readiness via `option httpchk GET /readyz`.
- **nginx** ([`deploy/nginx/`](deploy/nginx/)): native `sticky cookie` (NGINX
  Plus) with a stock-OSS cookie-hash fallback. Traefik's
  `loadBalancer.sticky.cookie` works equivalently.
- **Gateway API** ([`deploy/gateway-api/`](deploy/gateway-api/)): the same cookie
  mechanism via GEP-1619, as inline `HTTPRoute` `sessionPersistence` and as
  `BackendLBPolicy`. GEP-1619 is in the experimental channel and controller
  support varies — confirm your controller implements it. See
  <https://gateway-api.sigs.k8s.io/geps/gep-1619/>.

The smoke harness ([`deploy/docker-compose.yml`](deploy/docker-compose.yml),
[`deploy/smoke-test.sh`](deploy/smoke-test.sh)) runs 2 replicas behind HAProxy.
The equivalent automated check lives in the client repo
(`archetype-proxy-client/src-tauri/tests/multi_replica_stickiness.rs`).

## Shared types

`src/envelope.rs` (`StreamFrame`) is duplicated in `archetype-proxy-client` and
must stay in sync between the two.
