# archetype-proxy-server

A Rust reverse proxy that uses the [OpenHTTPA](https://github.com/OpenHTTPA/openhttpa-rs)
protocol crates to add TEE attestation in front of existing HTTP(S) backends.
It terminates attested OpenHTTPA sessions and reverse-proxies the DECRYPTED
traffic to configured upstreams selected per-request from a route table.

> Status: attested reverse-proxy with a layered, Traefik-style configuration
> system, real TEE provider/verifier selection (behind cargo features), a
> no-mock-in-release safety guard, `/healthz` + `/readyz` + Prometheus
> `/metrics`, Docker label discovery, attested error sealing, DoS/body-size
> hardening, AtB registry eviction, and optional per-IP rate limiting. Docker
> label discovery and (behind the `kubernetes` cargo feature) a Kubernetes
> Service/Ingress annotation watcher both feed the live route table. Full
> streaming/WS passthrough lands in a later task (see deferred follow-ups
> below).

## Build

```sh
cargo build
```

OpenHTTPA is consumed as a git dependency pinned to an exact commit
(`ae6d3909c23cd240962c10e9439eb7ac207ca4c3`); it is not published to crates.io.

The DEFAULT build is **mock-only**: it requires no TEE hardware or SDKs and is
CI-buildable on a normal box. Real hardware attestation is opt-in behind cargo
features (see **Real TEE providers** below).

## CRITICAL build-environment notes

The OpenHTTPA tree pins `aws-lc-rs` with the `fips` feature at its workspace
root, and depends on `oqs-sys`. Both impose hard environment requirements:

1. **Go + cmake + a C toolchain are required** (the aws-lc-rs `fips` feature
   builds aws-lc-fips-sys via Go and cmake).

2. **`oqs-sys` 0.11 breaks with libclang > 18.** `oqs-sys`'s `build.rs` runs
   `bindgen` with `allowlist_recursively(false)`; a too-new system libclang
   (clang >= 19, e.g. Fedora's clang 22) makes bindgen emit the `OQS_SIG`
   struct as opaque (size 1) while still writing an 88-byte layout assertion,
   which fails const-eval with:

   ```
   error[E0080]: attempt to compute `1_usize - 88_usize`, which would overflow
     ["Size of OQS_SIG"][size_of::<OQS_SIG>() - 88usize];
   ```

   `liboqs` itself builds fine — it is purely a bindgen x libclang mismatch.
   The fix is to point `LIBCLANG_PATH` at a **libclang <= 18** (this only
   redirects the libclang that bindgen loads; your system clang stays the
   default for everything else). Point it at the **directory**, not the file.

3. **Do not build on a small tmpfs.** The aws-lc-fips build needs more scratch
   space than a typical tmpfs-backed `/tmp`. If your `/tmp` is a small tmpfs,
   point `TMPDIR` at a real-disk dir (e.g. `export TMPDIR=/var/tmp`).

### Prerequisites on Fedora (e.g. Fedora 44 with clang 22)

Install the build toolchain plus a libclang <= 18 compat package. `clang18-libs`
provides `libclang.so.18` under `/usr/lib64/llvm18/lib` and pulls in
`llvm18-libs`; it does **not** displace your default clang:

```sh
sudo dnf install clang18-libs cmake golang gcc
```

Then build with `LIBCLANG_PATH` pointed at the clang 18 lib directory:

```sh
export LIBCLANG_PATH=/usr/lib64/llvm18/lib
# only if your /tmp is a small tmpfs:
# export TMPDIR=/var/tmp
cargo build
```

(`clang17-libs` / `clang15-libs` are also available as fallbacks if a future
`oqs` bump changes the supported libclang range.)

Cargo re-resolves dependencies fresh from the OpenHTTPA git dep (it does not
inherit OpenHTTPA's `Cargo.lock`); a clean resolve locks the latest
1.88-compatible versions, which is expected.

## Configuration (layered, Traefik-style)

Config is split into two tiers, mirroring Traefik:

- **Static** (`[server]`, `[attestation]`, `[discovery]`): how the proxy boots
  and which discovery providers are enabled. Read **once at boot**; does not
  hot-reload.
- **Dynamic** (`[[route]]` table): the set of attested routes
  (match rule -> upstream). Sourced from the file **and** discovery providers;
  **hot-reloads** on discovery events.

### Precedence (highest wins)

```
CLI flag  >  env (ARCHETYPE_PROXY_*)  >  discovered labels/annotations  >  TOML file  >  built-in defaults
```

Every resolved static field records the layer that set it (provenance). Inspect
it with the `dump` subcommand or the startup debug log:

```sh
archetype-proxy-server dump            # prints resolved config + [source] per field, then exits
archetype-proxy-server --config ./archetype-proxy.toml dump
RUST_LOG=archetype_proxy_server=debug archetype-proxy-server   # logs the same dump at startup
```

### Environment variables

`ARCHETYPE_PROXY_CONFIG` (path), `ARCHETYPE_PROXY_LISTEN`,
`ARCHETYPE_PROXY_MAX_BODY_BYTES`, `ARCHETYPE_PROXY_ALLOW_MOCK`,
`ARCHETYPE_PROXY_STRICT_ATTESTATION`, `ARCHETYPE_PROXY_ATB_TTL_SECS`,
`ARCHETYPE_PROXY_ATB_EVICTION_INTERVAL_SECS`, `ARCHETYPE_PROXY_ATB_MAX_SESSIONS`,
`ARCHETYPE_PROXY_RATE_LIMIT_MAX_REQUESTS`, `ARCHETYPE_PROXY_RATE_LIMIT_WINDOW_SECS`,
`ARCHETYPE_PROXY_TEE_PROVIDER`, `ARCHETYPE_PROXY_VERIFIER`,
`ARCHETYPE_PROXY_VERIFIER_ENDPOINT`, `ARCHETYPE_PROXY_VERIFIER_API_KEY`,
`ARCHETYPE_PROXY_DOCKER`, `ARCHETYPE_PROXY_DOCKER_SOCKET`,
`ARCHETYPE_PROXY_DOCKER_POLL_SECS`, `ARCHETYPE_PROXY_KUBERNETES`,
`ARCHETYPE_PROXY_KUBERNETES_NAMESPACE`.

`ARCHETYPE_PROXY_KUBERNETES_NAMESPACE` is three-state: unset = inherit the
lower layer; a non-empty value sets the namespace filter; an **empty** value
(`ARCHETYPE_PROXY_KUBERNETES_NAMESPACE=`) explicitly **clears** it (watch all
namespaces), letting a higher layer override a file-set namespace.

### CLI flags

`[config-path]` (positional), `--config <path>`, `--listen <addr>`,
`--max-body-bytes <n>`, `--docker`, `--kubernetes`,
`--log-level <level>`, `-v`/`-vv`/`-vvv`, `dump`.
Parsed with clap; run `archetype-proxy-server --help` / `--version` for the
auto-generated usage. `--config` takes precedence over the positional path.
`--docker` and `--kubernetes` are enable-only flags (both default off): passing
the flag force-enables that provider; omitting it inherits the TOML/env layers.
To disable a provider that a TOML/env layer enabled, set it false there.
`--log-level`/`-v` set the default tracing filter (see Observability);
`RUST_LOG` overrides them.

### Routing

Each request selects the **most-specific** matching route by host (exact,
case-insensitive) and path prefix (host-match beats catch-all; longer prefix
wins). Path prefixes match on **segment boundaries**: `/v1` matches `/v1` and
`/v1/foo` but not `/v123`. On an exact (host, prefix) tie, a **discovered**
route overrides a file route (dynamic precedence: file < discovered). No match
-> `404`. A legacy `[upstream] target` is still accepted and becomes a
catch-all route. See `archetype-proxy.toml.example` for the full schema.

Invalid CLI flag values (e.g. `--max-body-bytes nope`) cause a non-zero exit
rather than silently falling back — CLI is the highest-precedence layer.

## Real TEE providers (task #7)

The server constructs its `TeeProvider` (quote generation) and `QuoteVerifier`
(quote validation) from `[attestation]`:

```toml
[attestation]
tee_provider = "mock"   # mock | tdx | sev_snp | sgx | trustzone | aws_nitro
verifier     = "mock"   # mock | maa | ita | amd_snp
# verifier_endpoint = "https://sharedeus2.eus2.attest.azure.net"  # MAA / ITA
# verifier_api_key  = "..."                                        # ITA only
```

Real (non-mock) variants exist **only when this crate is built with the
matching cargo feature**, because the underlying openhttpa crates pull in
hardware SDKs / system libraries that cannot build or link on a box without
that hardware. The default build is therefore mock-only and CI-buildable.

### Cargo feature mapping

| this crate feature | enables                          | provider / verifier             |
|--------------------|----------------------------------|---------------------------------|
| `tdx`              | `openhttpa-tee/tdx`              | `TdxTeeProvider`                |
| `sev_snp`          | `openhttpa-tee/sev_snp`          | `SevSnpTeeProvider`             |
| `sgx`              | `openhttpa-tee/sgx`              | `SgxTeeProvider`                |
| `trustzone`        | `openhttpa-tee/trustzone`        | `TrustZoneTeeProvider`          |
| `aws_nitro`        | `openhttpa-tee/aws_nitro`        | `AwsNitroTeeProvider`           |
| `maa`              | `openhttpa-attestation/maa`      | `MaaVerifier` (Azure MAA)       |
| `ita`              | `openhttpa-attestation/ita`      | `ItaVerifier` (Intel Trust Auth)|
| `amd_snp`          | `openhttpa-attestation/amd_snp`  | `SevSnpVerifier` (VCEK chain)   |

Build for a given platform with the matching feature(s), e.g.:

```sh
cargo build --release --features tdx,maa        # Intel TDX + Azure MAA
cargo build --release --features sev_snp,amd_snp # AMD SEV-SNP + VCEK verify
```

These hardware features require confidential-compute hardware (e.g. Azure
DCsv5/ECsv5, GCP Confidential VM) plus the relevant SDKs at build time
(`tdx_attest`, `sev`, the SGX SDK, …) and **will not build on a box without
them** — that is expected.

If a variant is selected at runtime but its feature was not compiled in, the
server **fails fast** with a clear message, e.g.
`tee_provider=tdx requires building with --features tdx`. `verifier=dcap`,
`tpm`, and `nvidia` are rejected: the pinned openhttpa revision has no
production-ready verifier type for them (there is only an empty `dcap` feature
flag and documented stubs).

## No-mock-in-release guard (production safety)

Mock attestation provides **ZERO security** — quotes are not bound to any real
TEE and must never be trusted. To prevent the #1 production footgun (shipping a
release that silently runs mock), startup is gated by a pure, unit-tested
policy function `startup_attestation_decision(is_release, cfg, insecure_dev)`:

| build   | mock in effect? | `ARCHETYPE_PROXY_INSECURE_DEV` | result                        |
|---------|-----------------|--------------------------------|-------------------------------|
| release | no (real TEE)   | —                              | boots (Secure)                |
| release | yes             | unset                          | **refuses to start (fatal)**  |
| release | yes             | `=1`                           | boots + LOUD warning banner   |
| debug   | yes             | —                              | boots + warning (dev default) |
| debug   | no              | —                              | boots (Secure)                |

"Mock in effect" means **any** of: `allow_mock = true`, `tee_provider = "mock"`,
or `verifier = "mock"`. Release = `debug_assertions` off (`--release`).

The escape hatch is intentionally explicit:

```sh
ARCHETYPE_PROXY_INSECURE_DEV=1 ./archetype-proxy-server   # release build, mock, INSECURE
```

The server also registers a hook on `openhttpa-tee`'s telemetry so the crate's
own `security=true` ERROR on mock fallback is surfaced (never silently
swallowed), and logs a prominent `INSECURE / MOCK ATTESTATION MODE` banner
whenever mock is active.

## Observability

Three unauthenticated endpoints (they do NOT require attestation, so probes /
scrapers work without a handshake):

* `GET /healthz` — **liveness**: process is up (`200 ok`).
* `GET /readyz` — **readiness**: router built and serving (`200 ready`).
* `GET /metrics` — **Prometheus** text exposition (`text/plain; version=0.0.4`).

Metrics (hand-rolled atomics; no extra deps), incremented at the proxy edges
without touching the crypto path:

| series                                       | type      | meaning                                   |
|----------------------------------------------|-----------|-------------------------------------------|
| `archetype_proxy_handshakes_total`           | counter   | successful `POST /attest` handshakes      |
| `archetype_proxy_active_sessions`            | gauge     | live AtB sessions (sampled from registry) |
| `archetype_proxy_decrypt_failures_total`     | counter   | trusted-request decrypt/MAC failures      |
| `archetype_proxy_upstream_requests_total`    | counter   | upstream requests attempted               |
| `archetype_proxy_upstream_errors_total`      | counter   | upstream transport failures               |
| `archetype_proxy_upstream_latency_seconds`   | histogram | upstream round-trip latency               |

### Logging / verbosity

Structured `tracing` events go to **stderr** via a `tracing_subscriber` fmt
subscriber. Filter precedence (highest first):

1. **`RUST_LOG`** environment variable -- full `EnvFilter` syntax, e.g.
   `RUST_LOG=archetype_proxy_server=debug,openhttpa_server=debug`. When set, it
   OVERRIDES the flags below.
2. **`--log-level <level>`** (`off`/`error`/`warn`/`info`/`debug`/`trace`) --
   sets the default directive (`archetype_proxy_server=<level>`).
3. **`-v`/`-vv`/`-vvv`** -- shorthand: `-v`=debug, `-vv`/`-vvv`=trace.
4. Default: `info`.

```sh
archetype-proxy-server -vv                       # trace the whole crate
archetype-proxy-server --log-level debug
RUST_LOG=debug archetype-proxy-server            # RUST_LOG overrides --log-level/-v
```

### Troubleshooting: client can't connect to server

If the archetype-proxy-client shows no sign of connecting, run BOTH sides with
`-vv` (server: `archetype-proxy-server -vv`; client: `archetype-proxy-client -vv
--connect-on-start`) and check:

1. **Is this server listening on the client's `--server-uri`?** This server logs
   `listening (plaintext; ...)` (or the TLS variant) with its bound address at
   startup. Defaults align (server `127.0.0.1:8443`, client
   `http://127.0.0.1:8443`); if either was overridden they must match.
2. **Connection refused** in the client log (a `Transport` error) means this
   server isn't up on that address/port -- start it first.
3. **Attestation rejected** (an attestation/verifier error, not a transport one)
   means `allow_mock` differs. The MVP ships Mock attestation **on** on both
   sides; keep them consistent.
4. `--connect-on-start` on the client connects at launch so you can watch the
   logs without clicking Connect.

## TLS posture

The proxy terminates **attested OpenHTTPA sessions** (the inner, end-to-end
encrypted channel). For the **public/transport TLS** in front of it, there are
two supported postures:

* **In-process TLS termination** (`[server.tls]`): set `cert_path` + `key_path`
  (PEM) and the server terminates public TLS itself via `axum-server` + rustls
  (the **aws-lc-rs** crypto backend). All routes — `/healthz`, `/readyz`,
  `/metrics`, and the attested routes — serve over the TLS listener.
* **Run behind a TLS-terminating ingress / load balancer** (omit
  `[server.tls]`): nginx, Envoy, a cloud LB, or a Kubernetes ingress
  terminates public TLS and forwards to this server's plaintext listener on a
  trusted network.
* **Upstream connections**: the reverse-proxy `reqwest` client supports HTTPS
  upstreams (rustls). Use `https://` upstream URLs unless the upstream is
  same-host / on a trusted network.

**FAIL-FAST:** if `[server.tls]` is set but the cert/key is missing,
unreadable, or invalid PEM, the server aborts at startup with a clear error —
it never falls back to plaintext on a port the operator believes is TLS.

**Crypto backend:** rustls is driven with the **aws-lc-rs** provider, installed
explicitly (the dependency tree enables both rustls crypto features —
`aws_lc_rs` from the OpenHTTPA crates and `ring` transitively for cert-path
verification — so rustls has no unambiguous process default; we pin aws-lc-rs
rather than rely on a default that would otherwise panic).

**Cert source seam:** the certificate origin is abstracted behind `CertSource`
(`src/tls.rs`). Both variants resolve to a single `Arc<dyn ResolvesServerCert>`
that the listener consumes. `StaticFiles` reads a PEM pair at startup;
`Dynamic` is the runtime-swappable resolver the ACME path installs into, so
renewals take effect on the live listener **without restarting** and **without
rewriting the listener wiring**.

**EXACTLY ONE cert source.** A `[server.tls]` block must configure *either*
static PEM files *or* ACME — never both, never neither. `TlsConfig::validate()`
enforces this at startup and aborts with a clear error otherwise (static +
ACME both set, neither set, a half-specified static pair, ACME enabled with no
`domains`, or a wildcard domain on a non-DNS-01 challenge).

### Static PEM files

```toml
[server.tls]
cert_path = "/etc/archetype/tls/fullchain.pem"
key_path  = "/etc/archetype/tls/privkey.pem"
```

### ACME automatic provisioning (`[server.tls.acme]`)

When `[server.tls.acme] enabled = true`, the server obtains and auto-renews its
public certificate from an ACME CA (Let's Encrypt by default). The issued cert
is installed into the `Dynamic` resolver and renewed in the background (the
renewal check runs twice a day and re-issues when <30 days of validity remain);
renewals swap the live cert with no restart. A still-valid cached cert under
`cache_dir` is reused on boot, so a restart does not re-hit the CA.

**FAIL-FAST:** if there is no usable cached cert and live issuance fails, the
server aborts at startup — it never serves plaintext or an expired cert on a
TLS-labelled port.

```toml
[server.tls.acme]
enabled    = true
domains    = ["proxy.example.com"]   # SANs on the issued cert; >=1 required
contact    = "ops@example.com"        # stored as mailto: on the ACME account
challenge  = "tls-alpn-01"            # tls-alpn-01 (default) | http-01 | dns-01
staging    = true                     # use LE staging while testing (see below)
cache_dir  = "/var/lib/archetype/acme" # persists account key + issued cert
# directory_url = "https://acme.example/dir"  # explicit CA; overrides `staging`
```

**Challenge types** (RFC 8555 / RFC 8737) and their prerequisites:

| challenge      | network / DNS prerequisite | wildcard? |
|----------------|----------------------------|-----------|
| `tls-alpn-01` (default) | the CA must reach **inbound :443**; the validation cert is served on the existing TLS listener via the `acme-tls/1` ALPN protocol (no extra port) | no |
| `http-01`      | the CA must reach **inbound :80** (or `http01_listen`); a tiny plaintext responder serves `GET /.well-known/acme-challenge/{token}` | no |
| `dns-01`       | a `_acme-challenge.<domain>` **TXT record** must be published (manual or via a `[server.tls.acme.dns] hook_command`) | **yes — only DNS-01 can issue wildcards** |

HTTP-01 responder address (only used when `challenge = "http-01"`):

```toml
[server.tls.acme]
enabled       = true
domains       = ["proxy.example.com"]
challenge     = "http-01"
http01_listen = "0.0.0.0:80"   # defaults to <listen-ip>:80 if omitted
```

DNS-01 (the only wildcard-capable challenge):

```toml
[server.tls.acme]
enabled   = true
domains   = ["*.example.com", "example.com"]
challenge = "dns-01"

[server.tls.acme.dns]
provider         = "manual"          # only `manual` (hook/log) is implemented
# hook_command is run to PUBLISH the record; receives ACME_DNS_DOMAIN,
# ACME_DNS_NAME, ACME_DNS_VALUE in the environment. Without it, the required
# record is logged and you must publish it out of band before propagation.
hook_command     = "/usr/local/bin/publish-txt.sh"
cleanup_command  = "/usr/local/bin/cleanup-txt.sh"   # optional best-effort
propagation_secs = 60                 # wait before telling the CA to validate
```

**Staging vs. production + rate limits.** Set `staging = true` while testing:
Let's Encrypt **production** enforces tight [rate
limits](https://letsencrypt.org/docs/rate-limits/) (notably *Certificates per
Registered Domain* and *Duplicate Certificate*) and burning them on a
misconfiguration locks you out for up to a week. The staging environment issues
untrusted certs but has far higher limits — validate the full issuance flow
there first, then flip `staging = false` (or omit it) for a trusted cert.

**Live validation is not possible on a headless/un-routable host.** ACME
requires the CA to reach the challenge endpoint (`:443`, `:80`, or public DNS),
so issuance can only be exercised against a publicly reachable deployment. To
validate manually:

1. Point a real DNS `A`/`AAAA` record for `domains` at the host.
2. Open the relevant inbound port (`:443` for tls-alpn-01, `:80` for http-01)
   or arrange TXT publication (dns-01).
3. Start with `staging = true` and confirm the server logs
   *"ACME certificate issued and installed"* and serves the staging cert.
4. Flip to production and restart; the cached staging cert is replaced.

The pure logic — challenge dispatch, config validation, the HTTP-01 token
store, the TLS-ALPN-01 validation-cert build, and the DNS hook — is unit-tested
(`src/acme.rs`, `src/config.rs`); **live CA issuance is not and cannot be
tested in CI.**

## Discovery

Providers implement a shared `DiscoveryProvider` trait, each pushing a full
route snapshot over a channel; a `RouteManager` merges file routes + the latest
per-provider snapshot into a hot-swappable route table (`ArcSwap`). A backend
being absent or down **never crashes the proxy** — it logs a warning and serves
file/env routes only.

### Docker label discovery (`[discovery] docker = true`)

Polls the Docker socket and reads `archetype.*` container labels:

```
archetype.enable = true
archetype.attestation.strict = true                  # optional container-global default
archetype.route.<name>.host = api.internal           # optional
archetype.route.<name>.upstream = http://api:8080    # required per route
archetype.route.<name>.pathprefix = /v1              # optional
archetype.route.<name>.strict = true                 # optional per-route override
```

A container may declare multiple routes via distinct `<name>` segments. As a
shorthand, an enabled container with no `archetype.route.*` keys but a top-level
`archetype.upstream` (plus optional `archetype.host` / `archetype.pathprefix`)
yields a single implicit route.

> **RISK — read before enabling.** Docker discovery requires access to the
> Docker socket, which is **root-equivalent on the host**. Mounting
> `/var/run/docker.sock` into a security-sensitive proxy materially expands its
> attack surface: anyone who compromises the proxy can control the daemon.
> Discovery is therefore **OFF by default** and gated behind an explicit
> `[discovery] docker = true` opt-in. If you enable it, put a **read-only
> [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)**
> between this process and the real socket and point `docker_socket` at it,
> exposing only `CONTAINERS=1` (list). Never give the proxy write access to the
> daemon.

### Kubernetes discovery (`[discovery] kubernetes = true`)

Annotation-based discovery over `archetype.li/*` annotations on
Services/Ingresses:

```
archetype.li/enable = "true"
archetype.li/upstream = "http://svc:80"   # required
archetype.li/host = "api.internal"        # optional
archetype.li/path-prefix = "/v1"          # optional
archetype.li/strict = "true"              # optional
```

A kube-rs `watcher` lists+watches Services AND Ingresses, resyncing and
reconnecting with backoff on disconnect (handled by kube-rs internally). Each
object's annotations run through the same `route_from_annotations` mapping; the
provider pushes a full route snapshot to the route manager on every change
(same full-snapshot-on-change mechanism as Docker discovery). An object that
loses its opt-in annotations (or is deleted) drops its route on the next
snapshot.

**Build:** the watcher is gated behind the `kubernetes` cargo feature so the
DEFAULT build stays lean (no `kube` / `k8s-openapi`) and CI-fast — mirroring how
the real-TEE providers are feature-gated. Build it with:

```sh
cargo build --release --features kubernetes
```

If you set `[discovery] kubernetes = true` on a binary built WITHOUT the
feature, the proxy logs a warning and serves file/env routes only (it does not
crash).

**TLS stack:** kube's default features pull `ring` as the rustls crypto
provider. To preserve this crate's single-provider (`aws-lc-rs`) posture from
tasks #11/#12, the `kube` dependency disables default features and selects
`rustls-tls` + `aws-lc-rs`. `cargo tree -i ring --features kubernetes` confirms
`ring` is still absent.

**Resilience:** an unreachable cluster, missing kubeconfig / in-cluster
ServiceAccount, or RBAC-denied watch never crashes the proxy — it logs a
warning and serves file/env routes only. Transient watch errors are logged and
ridden through (kube-rs resyncs/reconnects).

**Namespace filter** (`[discovery] kubernetes_namespace`, three-state — see
Environment variables above): unset/absent watches the namespace from the lower
config layer (default: all namespaces); a non-empty value watches that single
namespace (`Api::namespaced`); an empty value watches all namespaces
(`Api::all`).

**RBAC.** The ServiceAccount the proxy runs as needs `get`/`list`/`watch` on
`services` (core API group `""`) and `ingresses` (`networking.k8s.io`). Use a
namespaced `Role` + `RoleBinding` when a single namespace is configured, or a
`ClusterRole` + `ClusterRoleBinding` when watching all namespaces:

```yaml
# Cluster-scoped (watching all namespaces). For a single namespace, use
# kind: Role / RoleBinding in that namespace instead.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: archetype-proxy-discovery
rules:
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: archetype-proxy-discovery
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: archetype-proxy-discovery
subjects:
  - kind: ServiceAccount
    name: archetype-proxy
    namespace: <proxy-namespace>
```

**Manual cluster validation** (not exercised in CI — no cluster on the build
box; only the object→route reconciliation is unit-tested against synthetic
`k8s-openapi` Service/Ingress values):

1. Build with `--features kubernetes` and deploy with the ServiceAccount +
   RBAC above (or run locally against a kind/minikube cluster with a kubeconfig
   that has the listed verbs).
2. Set `[discovery] kubernetes = true` (optionally `kubernetes_namespace`).
3. Annotate a Service: `kubectl annotate svc my-svc archetype.li/enable=true
   archetype.li/upstream=http://my-svc:80 archetype.li/host=api.internal`.
4. Watch the logs for `route table updated provider=kubernetes`; confirm the
   route count rises. Remove the annotations and confirm the route is dropped
   on the next snapshot.
5. Kill the API connection (or `kubectl delete`/recreate) to confirm the
   watcher resyncs without crashing the proxy.

## Attested error sealing (fidelity guarantee)

Once a request has a valid attested session (it passed `TrRequestLayer` and
decrypt), **every** proxy-generated error is SEALED into the same
`{status, headers, body}` envelope as a normal upstream response and returned
as a normal `200` attested reply carrying the real error status:

| Condition                         | Sealed status |
|-----------------------------------|---------------|
| No matching route                 | `404`         |
| Upstream unreachable / connect fail | `502`       |
| Upstream timeout                  | `504`         |
| Request / upstream body too large | `413`         |
| Invalid method                    | `400`         |

The OpenHTTPA client surfaces ANY bare non-2xx from the attested server as a
transport error (indistinguishable from a real transport failure, and possibly
retried — risking replay of non-idempotent requests). Sealing the error status
instead means the client always decodes a `SealedResponse`; only a TRUE
handshake/transport failure (cannot reach the attested server at all) surfaces
as `Err`. The pre-session surfaces are unchanged: the `ATTEST` handshake
endpoint, `TrRequestLayer` rejection of an invalid/expired session (those are
legitimately not sealable), and the unauthenticated `/healthz` plain `200`.

## DoS / fidelity hardening

* **Pre-decrypt body cap.** The encrypted request envelope is read with a cap
  of `~2*(max_body_bytes+16) + JSON_OVERHEAD` (overflow-safe) BEFORE
  hex-decoding/buffering, so a malicious client cannot force unbounded memory
  ahead of the plaintext `max_body_bytes` check.
* **Streamed upstream read.** The upstream response body is streamed and
  aborted once accumulated bytes exceed `max_body_bytes` (sealed `413`); an
  oversized `Content-Length` is rejected before any buffering.
* **Connection-nominated hop-by-hop stripping.** In addition to the static
  hop-by-hop list, the comma-separated tokens of the upstream `Connection`
  header are lowercased and those header names stripped too, BEFORE sealing —
  so `Connection: X-Hop` + `X-Hop: secret` cannot leak into the envelope. The
  server does this itself (the client cannot, since the server strips
  `Connection` before sealing).
* **AtB registry eviction.** The client uses single-use sessions (one handshake
  per bridged request). A background task reaps expired sessions on
  `atb_eviction_interval_secs` so the registry (capacity `atb_max_sessions`,
  TTL `atb_ttl_secs`) is never exhausted by a long-running bridge.
* **Rate limiting.** An optional per-IP sliding-window limit
  (`[rate_limit] max_requests`/`window_secs`, `0` = disabled) is layered onto
  all routes.

## Streaming / WebSocket — status

* **Response streaming (SHIPPED, task #13).** The RESPONSE is sealed as a
  sequence of chunked AEAD frames (`seal_stream`: `[len][counter][ciphertext]`,
  server-write key, XOR-counter nonce, cumulative-SHA384 AAD) and the client
  decodes them incrementally, so a large upstream response never buffers fully
  in memory. The REQUEST is still sealed MONOLITHICALLY: the client SDK draws a
  random per-request nonce under a `SlidingWindow` guard, which the server
  cannot decode as a request stream — so request streaming stays out of scope
  pending an OpenHTTPA change. Body-size caps bound both directions.
* **Attested WebSocket passthrough (SHIPPED, task #14).** An attested WS is an
  HTTP `GET` upgrade carrying `Attest-Base-ID`; the server (`ws.rs`) dials the
  route's upstream WS and pumps frames both ways, each frame AEAD-sealed with an
  ORDERED counter nonce (strict-monotonic inbound). The client hand-rolls the
  upgrade (`session.rs` `attested_ws_connect`) over tokio-tungstenite. One
  attested session carries the whole socket (ordered nonces, unlike the
  random-nonce request path).
* **FS / Redis replay guards (NOT wired, task #17).** The proxy relies on
  OpenHTTPA's per-session `SlidingWindow` replay strategy (single-use
  sessions), which is inherently replica-local-correct under stickiness. The
  crate's `FileReplayGuard` / Redis guard wiring behind a config knob is a
  low-priority follow-up; it becomes relevant only if reusable / 0-RTT
  resumable sessions are introduced (see *Multi-replica deployment*).

## Multi-replica deployment (stickiness model)

The attested session registry (`AtbRegistry`) is **in-memory, per replica**
(an `Arc<DashMap<AtbId, AttestSession>>`; see the pinned
`openhttpa-server::atb_registry`). It is NOT backed by Redis or any shared
store, and the pinned OpenHTTPA crate exposes no hook to make it shared.
**Sharing session state across replicas would require forking OpenHTTPA, which
is out of scope.** Therefore the supported model for running N replicas behind
a load balancer is **session stickiness**.

### Why a session is replica-local

1. The `ATTEST` handshake mints a fresh random `AtbId` (UUIDv4) *inside the
   handler* and stores the `AttestSession` in **the registry of whichever
   replica served the handshake** — call it replica X.
2. Every subsequent trusted request carries that `AtbId` in the
   `Attest-Base-ID` header. The server looks it up in the **local** registry
   (`TrRequestLayer`). If the request lands on replica Y ≠ X, the lookup misses
   and the request is rejected with a bare `401` (empty body) **before** it is
   forwarded upstream.

So the load balancer MUST route a session's trusted requests (and its attested
WebSocket upgrade) back to the **same replica that served its handshake**.

### Chosen mechanism

**Primary: cookie-based L7 stickiness for HTTP, connection-pinning for WS.**

| Candidate | Verdict |
|-----------|---------|
| **(A) L7 header-hash on `Attest-Base-ID`** | **Does NOT work.** The `AtbId` is *minted* by the replica during the handshake; the handshake request carries **no** `Attest-Base-ID`, so the LB cannot hash the handshake by it and routes it by some unrelated rule. The follow-up's `hash(AtbId)` is statistically independent of where the handshake landed → ~`(N-1)/N` miss rate. A mint-then-route key cannot drive header-hash affinity. |
| **(B) Cookie-based L7 affinity** | **Recommended.** The LB sets a backend-pinning cookie on the handshake **response** and routes by it thereafter. Robust and the standard primitive (Traefik sticky sessions, nginx `sticky cookie`, HAProxy `cookie`, k8s `sessionAffinity` via ingress). Requires the client to **echo the cookie** (see below). |
| **(C) L4 source-IP hash** | Works but coarse: every client behind one NAT/egress IP pins to one replica (hot-spotting), and rebalancing on replica add/remove breaks live sessions. Acceptable fallback when the LB cannot do L7 cookies. |

**Exact LB requirement:**
* **HTTP:** enable cookie-based sticky sessions on the proxy backend. The cookie
  is set on the `POST /attest` response and honored for all subsequent trusted
  requests (`POST /<path>` carrying `Attest-Base-ID`).
* **WebSocket (task #14):** an attested WS is an HTTP `GET` upgrade carrying
  `Attest-Base-ID`; the **same** stickiness rule pins the upgrade to the
  handshake's replica. Once upgraded, the WS rides **one TCP connection** that
  the LB will not rebalance, so all frames stay on that replica for the socket's
  lifetime. The only window needing affinity is the upgrade request itself —
  covered by the same cookie/L4 rule as HTTP. **Mid-stream rebalancing of an
  established WS does not occur** (the connection is pinned); if the replica
  *dies*, the socket drops and the client must reconnect (re-handshake), which
  is the correct failure mode.

### Does the client need a change?

For **(B) cookie** stickiness, yes: the client's `reqwest` transport must carry
a cookie store so the LB's affinity cookie is echoed. The client's
`ReqwestTransport` is built from `reqwest::Client::new()` (no cookie store);
`ReqwestTransport::with_client(client)` accepts an injected client, so a
`reqwest::Client::builder().cookie_store(true).build()` can be supplied (this
also needs the `cookies` reqwest feature, not currently enabled). **This change
**was shipped in task #20**: `archetype-proxy-client` `session.rs` builds ONE
long-lived `reqwest::Client` with `.cookie_store(true)` (reqwest `cookies`
feature) and injects it via `ReqwestTransport::with_client(...)`. That single
client — and its cookie jar — is reused across EVERY handshake and trusted
request and the whole session pool (it is never rebuilt per request, which
would reset the jar and break stickiness). So the LB's affinity cookie, set on
the `/attest` response, is echoed on the follow-up trusted request → both land
on the same replica. The `cookies` feature pulls only the pure-Rust
`cookie_store` (no crypto provider, no `ring`). For **(C) L4 source-IP**, no
client change is required.

### Stickiness-miss hardening (client, shipped)

Stickiness is best-effort: a misconfigured/over-eager LB, or a replica restart,
can still land a trusted request on a replica that never saw the handshake. The
client (`archetype-proxy-client` `session.rs`) now **recovers automatically**:
a bare `401`/`403` (the unknown-session rejection) triggers ONE fresh handshake
+ retry. This is **replay-safe**: the rejection happens at the session gate
*before* the request is forwarded upstream, and this server seals every
post-forward outcome into a transport-`200` envelope (see *Attested error
sealing*), so a bare non-2xx is provably pre-forward. Ambiguous intermediary
errors (a bare `5xx`/timeout, which an LB can emit *after* the request may have
reached the upstream) are **surfaced, never retried**, to avoid replaying a
non-idempotent request. So auto-recovery makes a *transient* miss invisible,
but stickiness must still be configured for steady-state correctness.

### Per-replica caveats

State other than sessions is also per-replica. None blocks multi-replica
operation, but operators should know:

* **Rate limiting** (`[rate_limit]`) is a **per-replica** per-IP sliding window.
  Effective global limit is `max_requests × N` replicas. Size accordingly, or
  enforce a global limit at the LB if a hard cluster-wide cap is required.
* **`/metrics`** are **per-replica** counters/histograms. Scrape every replica
  and aggregate (sum counters, merge histograms) in Prometheus; do not expect
  one replica's `/metrics` to reflect cluster totals. `openhttpa_active_sessions`
  is that replica's registry size only.
* **AtB eviction** (TTL + background reaper) is per-replica and correct as-is:
  each replica reaps only its own sessions.
* **Replay guards.** Trusted requests rely on OpenHTTPA's per-session
  `SlidingWindow` strategy, which is per-session and therefore inherently
  replica-local-correct under stickiness (a session lives on one replica). The
  crate's `ticket_engine_fs` + `replay_guard_fs`/`replay_guard_redis` are **not
  wired** (that is task #17). They become relevant only if *reusable / 0-RTT
  resumable* sessions are ever introduced — at which point a **shared** replay
  guard (Redis) is the path to making a resumption ticket safely redeemable on
  *any* replica, i.e. the one place shared state would relax the stickiness
  requirement. Until then, single-use sessions + stickiness are sufficient.

### Summary

Run N replicas, terminate TLS and apply **cookie-based sticky sessions** at the
LB (or L4 source-IP affinity as a coarse fallback), routing each session's
trusted requests and WS upgrade back to its handshake replica. The client
tolerates transient misses by re-handshaking. Shared session state is
explicitly out of scope (needs an OpenHTTPA fork), so stickiness is the
supported model.

### Concrete LB configs (task #20)

Ready-to-use reference configs and a runnable smoke harness live under
[`deploy/`](deploy/) — see [`deploy/README.md`](deploy/README.md):

* **Kubernetes** ([`deploy/k8s/deployment.yaml`](deploy/k8s/deployment.yaml)):
  a 3-replica Deployment + Service + **ingress-nginx** Ingress with
  `nginx.ingress.kubernetes.io/affinity: "cookie"`,
  `affinity-mode: persistent`, `session-cookie-name: APROXYID`, and WS
  `proxy-read/send-timeout: 3600`. Readiness/liveness probes hit `/readyz` and
  `/healthz` so K8s routes only to ready replicas.
* **Standalone HAProxy** (primary —
  [`deploy/haproxy/haproxy.cfg`](deploy/haproxy/haproxy.cfg)):
  `cookie SRVID insert indirect nocache` + per-server `cookie r1`/`cookie r2`
  ids. The cookie-less `/attest` handshake load-spreads via `balance
  roundrobin`; HAProxy inserts `SRVID` naming the chosen replica and routes
  follow-ups (and the WS upgrade) by it. `option httpchk GET /readyz` gates
  rotation on readiness; `timeout tunnel 3600s` keeps an attested WS alive.
* **Standalone nginx** (alternative —
  [`deploy/nginx/nginx.conf`](deploy/nginx/nginx.conf)): native `sticky cookie`
  (NGINX Plus / sticky-module) is the clean path; a stock-OSS
  cookie-keyed-`hash` fallback is documented with its consistency caveat. WS
  `Upgrade`/`Connection` mapping + 3600s timeouts included. **Traefik**
  (`loadBalancer.sticky.cookie`) also works with no further client change.
* **Kubernetes Gateway API** ([`deploy/gateway-api/`](deploy/gateway-api/)):
  the same cookie mechanism expressed via **GEP-1619** -- both an inline
  `HTTPRoute` `sessionPersistence` (`sessionName: APROXYID`, `type: Cookie`)
  and a `BackendLBPolicy` form (controller support varies). No client change
  beyond the cookie store. **Caveats:** GEP-1619 ships in the Gateway API
  **experimental channel** (not standard) and **controller support is uneven**
  -- verify your controller (Istio/Cilium/Envoy Gateway/etc.) implements
  `HTTPRouteSessionPersistence` before relying on it. See
  <https://gateway-api.sigs.k8s.io/geps/gep-1619/>.

**How the cookie keys HTTP + WS stickiness:** the LB sets the affinity cookie
on the `POST /attest` response; the client's cookie-store transport echoes it
on the follow-up trusted request → same replica. For WS, the same cookie pins
the `GET` upgrade; thereafter the socket rides one TCP connection the LB never
rebalances, so all frames stay on that replica for the socket's lifetime.

A smoke harness ([`deploy/docker-compose.yml`](deploy/docker-compose.yml) +
[`deploy/smoke-test.sh`](deploy/smoke-test.sh)) stands up 2 replicas + the
HAProxy LB + a dummy upstream. The fully-automated, no-Docker equivalent is the
client test `tests/multi_replica_stickiness.rs::cookie_affinity_pins_handshake_and_request_no_miss`,
which asserts a request batch hits the minting replica with ZERO misses;
`recovers_from_stickiness_miss` covers the residual-miss safety net.

## Shared types

`src/envelope.rs` defines the sealed response envelope (`{status, headers,
body}`) that the server seals inside the OpenHTTPA response body. It is
intentionally DUPLICATED in `archetype-proxy-client` and the two copies must
stay in sync. Promotion to a shared `archetype-proxy-common` crate is a future
option.
