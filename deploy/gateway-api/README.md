# Kubernetes Gateway API deployment (cookie session persistence, GEP-1619)

This directory is the **Gateway API** equivalent of the ingress-nginx example
in [`../k8s/deployment.yaml`](../k8s/deployment.yaml). It pins each attested
session to the replica that served its handshake using a **backend-pinning
cookie** — the **same** mechanism the HAProxy/nginx/Ingress examples use.

Read the server `README.md` section **"Multi-replica deployment (stickiness
model)"** first: it explains *why* sessions are replica-local and *why* a
cookie (not header-hash on `Attest-Base-ID`) is the mechanism — the `AtbId` is
minted inside the handshake, so the handshake carries no routable key. **No
client change is needed:** the client's `reqwest` transport already ships a
cookie store that echoes the affinity cookie on the follow-up trusted request
and the WS `GET` upgrade.

---

## ⚠️ READ FIRST — critical caveats (verified against GEP-1619)

> **GEP-1619 session persistence is EXPERIMENTAL.** The `sessionPersistence`
> field and `BackendLBPolicy` ship **only in the Gateway API EXPERIMENTAL
> CHANNEL CRDs**, not the standard channel. You **must install the experimental
> bundle** or these fields/kinds will not exist in your cluster. The API may
> change before GA.
>
> ```sh
> # Experimental channel CRDs (required for sessionPersistence / BackendLBPolicy):
> kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/vX.Y.Z/experimental-install.yaml
> ```

> **Controller support is UNEVEN.** A stable Gateway API spec does **NOT**
> guarantee that your controller (Istio, Cilium, Envoy Gateway, etc.)
> implements `sessionPersistence` or `BackendLBPolicy`. Some controllers
> implement the inline `HTTPRoute` field, some implement `BackendLBPolicy`,
> some implement neither yet. **You MUST verify your controller implements
> GEP-1619 before relying on this** — check your controller's Gateway API
> conformance report for the `HTTPRouteSessionPersistence` feature.
>
> Spec + conformance reference: <https://gateway-api.sigs.k8s.io/geps/gep-1619/>

> **Support tiers:** `type: Cookie` is **Core** support. `type: Header` is
> **Extended** support. `cookieConfig` is **Core**; `absoluteTimeout` is
> **Extended** (`Duration`).

If your controller does not implement GEP-1619, use one of the proven
alternatives instead — same cookie mechanism, no client change:
[`../k8s/deployment.yaml`](../k8s/deployment.yaml) (ingress-nginx
`affinity: cookie`), [`../haproxy/haproxy.cfg`](../haproxy/haproxy.cfg)
(`cookie SRVID insert`), or [`../nginx/nginx.conf`](../nginx/nginx.conf)
(`sticky cookie`).

---

## Two expression forms (apply ONE)

Controller support varies, so both forms are provided:

| File | Form | When to use |
|------|------|-------------|
| [`httproute.yaml`](httproute.yaml) | **Inline** `HTTPRoute.rules[].sessionPersistence` | Controllers that implement persistence as an inline HTTPRoute field. Includes the full Deployment/Service/ConfigMap/Gateway/HTTPRoute. |
| [`backendlbpolicy.yaml`](backendlbpolicy.yaml) | **`BackendLBPolicy`** (Direct Policy Attachment) | Controllers that implement persistence via a policy attached to the backend Service. Reuse the workload manifests from `httproute.yaml`; drop its inline `sessionPersistence` block to avoid two competing configs. |

Both set a cookie named **`APROXYID`** of `type: Cookie`. They are equivalent;
do not apply both at once for the same backend.

### GEP-1619 field reference (as used here)

- `HTTPRoute` rule `sessionPersistence`:
  - `sessionName` (string) — the cookie name (`APROXYID`).
  - `type` (`Cookie` | `Header`, **default `Cookie`**) — `Cookie` is Core.
  - `cookieConfig` (Core) — `lifetimeType` defaults to `Session` (no
    `Expires`/`Max-Age` emitted → per-process pin). `Permanent` is Extended.
  - `absoluteTimeout` (`Duration`, **Extended**) — only meaningful with
    `lifetimeType: Permanent`; do not combine with `Session` lifetime.
- `BackendLBPolicy`: `spec.targetRefs` (the backend Service) + the same
  `sessionPersistence`.

---

## WebSockets

The cookie pins the attested WS `GET` upgrade to the handshake replica. Once
upgraded, the socket rides **one TCP connection** that the Gateway never
rebalances, so every frame stays on that replica for the socket's lifetime.

Set **long-lived timeouts** on the Gateway/HTTPRoute so an idle attested WS is
not dropped mid-conversation. These are **controller-specific knobs** — Gateway
API's portable `HTTPRoute.rules[].timeouts` (`request`, `backendRequest`) are
about request completion, not long-lived tunnels, so consult your controller's
docs for the connection/stream-idle timeout (e.g. Envoy Gateway
`ClientTrafficPolicy`/`BackendTrafficPolicy`, Istio idle-timeout annotations).

## Health-check routing (unauthenticated)

Health/readiness routing in Gateway API is a **Service/controller concern**
(there is no Gateway-level health field). The server exposes two
**unauthenticated** endpoints (see `proxy.rs`):

| Path       | Purpose   | Use                                              |
|------------|-----------|--------------------------------------------------|
| `/readyz`  | readiness | route traffic only to replicas returning 200     |
| `/healthz` | liveness  | restart a hung replica                           |

The Deployment in `httproute.yaml` wires these as `readinessProbe` /
`livenessProbe`, so kube-proxy/EndpointSlices only advertise ready replicas to
the Gateway. **Never** put these behind attestation — the LB cannot present an
attested session.

## Residual-miss safety net

A residual miss (replica restart, cookie dropped, `absoluteTimeout` race) is
**not fatal**: the client (task #19) auto-recovers by re-handshaking + retrying
once on a bare `401`/`403`, which is replay-safe (the rejection happens at the
session gate, before any upstream forward). Cookie persistence makes misses
**rare**; the client makes a residual miss **invisible**.
