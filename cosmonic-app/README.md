# The sandboxed half: a hijacked log shipper behind a one-host egress allow-list

The branded demo. It runs the **same vulnerable shipper** as the
[native baseline](../native-demo/README.md), compiled to `wasm32-wasip2`, as a WebAssembly
component whose only outbound authority is one hostname. A second, separate workload plays the
legitimate destination.

| Component | Directory | Workload | Filesystem | Network out | HTTP in | Role |
|-----------|-----------|----------|------------|-------------|---------|------|
| **shipper** | [`shipper/`](shipper/) | `egress-exfil-sandbox` | none | `egress-exfil-logsink.localhost` only | exports `wasi:http/handler` | The UI and the vulnerable shipper. Makes the outbound POST. |
| **logsink** | [`logsink/`](logsink/) | `egress-exfil-logsink` | none | deny-all | exports `wasi:http/handler` | The allow-listed destination. `POST /ingest` returns a receipt; nothing is stored. |

When the page calls `/run`, the shipper hands itself a log batch, routes it with
[`workspace::route`](shipper/src/workspace.rs), and POSTs through `wasi:http/client`. A poisoned
batch redirects that POST to the attacker and attaches the workspace. The component never checks
the destination. The host does: it compares the request's authority to the Workload's
`allowedHosts` and answers `ErrorCode::HttpRequestDenied` for anything else.

> We deliberately did **not** add an allow-list, URL validation or a "trusted sink" check to the
> shipper. The point is to prove the **sandbox** contains the exfiltration when the application
> does nothing to stop it.

## Why two workloads, not two linked components

The zip demo links two components inside one workload over a private WIT interface. Here the thing
under test is *HTTP egress*, so the legitimate destination has to be a real HTTP host, reached the
same way the attacker's would be. The sink is therefore its own workload with its own ingress
hostname, and the shipper reaches it with an ordinary request to
`http://egress-exfil-logsink.localhost:8200/ingest`. The two keep disjoint grants: the shipper can
call out to one host and cannot store anything; the sink can call out to nothing.

`.localhost` names resolve to loopback, where Desktop's ingress listens, so the allowed request
never leaves the machine. Allow-listing the name is enough; `allowedHostLoopbackPorts` and the
Settings → Security loopback switch are not involved.

## What the report is made of

Nothing in a verdict is a canned string about the outcome. For each attempt the shipper records:

- `outcome`: `denied` (the runtime's `HTTP-request-denied` or `destination-IP-prohibited`),
  `rejected` (the runtime would not accept the request as valid, for example `set-authority`
  failed), `transport-error` (past the policy, then DNS / refused / timeout), or `connected`.
- `runtime_error`: the `error-code` the host returned, printed with `{:?}`.
- `http_status` and `response`: what the destination answered, when one did.
- `passed_policy`: true for `connected` and `transport-error`. The fuzz counts a hostile variant
  with `passed_policy: true` as an escape even if nothing answered.

The verdict line and its counts are assembled from those fields ([`shipper/src/lib.rs`](shipper/src/lib.rs) `run`).

The outbound request is built on the raw `wasi:http` request resource
([`shipper/src/egress.rs`](shipper/src/egress.rs)), not through the `http` crate, so the authority
reaches the host exactly as written. That matters for the fuzz: a client-side URL parser would
reject or normalise half the corpus before the runtime ever saw it.

## Routes

- `GET /`: the page. `/#all`, `/#exfil`, `/#domain`, `/#allowed`, `/#fuzz` press a button on load.
- `GET /run?mode=exfil|domain|allowed|fuzz|all`: the JSON verdict.
- `GET /fuzz`: the compiled-in corpus, every result.
- `GET /probe?authority=<percent-encoded>&path=<path>`: one raw outbound attempt; what `fuzz/run.py` drives.
- `GET /corpus.txt`: the corpus this build was compiled with.

`/probe` will try any authority you give it. That is safe to expose for the same reason the demo
works: the request still has to get past `allowedHosts`.

## The interface (WIT)

[`wit/egress-demo.wit`](wit/egress-demo.wit) writes the two worlds down:

```wit
package cosmonic:egress-demo@0.1.0;
world shipper { import wasi:http/client@0.3.0; export wasi:http/handler@0.3.0; }
world logsink { export wasi:http/handler@0.3.0; }
```

It is the readable contract, not a build input: both crates get their bindings from the `wasip3`
crate. BUILD_INSTRUCTIONS sketches the shipper as `include wasi:http/proxy@0.2.0`; this is the p3
form of the same shape (one inbound handler, one outbound client), chosen because it is what the
reference demo's web component and Desktop's `rust-http` template use. The manifest's
`hostInterfaces` binds `interfaces: [handler]`, matching the `wasi:http/handler@0.3.0` export that
`cosmonic_image_inspect` reports. Outbound HTTP is not a `hostInterfaces` entry on Desktop: it is
implicit and gated only by `allowedHosts`.

## Build & deploy

```bash
(cd shipper && wash build)
(cd logsink && wash build)
# push (bump the tag on every rebuild)
wash oci push --insecure oci.localhost:8200/apps/egress-exfil-sandbox-shipper:0.1.2 shipper/target/wasm32-wasip2/release/egress_exfil_shipper.wasm
wash oci push --insecure oci.localhost:8200/apps/egress-exfil-sandbox-logsink:0.1.0 logsink/target/wasm32-wasip2/release/egress_exfil_logsink.wasm
# apply (update the digests in the manifests first), sink first:
#   cosmonic_workload_apply(../deploy/egress-exfil-logsink.workload.yaml)
#   cosmonic_workload_apply(../deploy/egress-exfil-sandbox.workload.yaml)
```

### Command-line check

```bash
curl -s -H 'Host: egress-exfil-sandbox.localhost' 'http://127.0.0.1:8200/run?mode=all' | python3 -m json.tool
python3 ../fuzz/run.py
```

## Layout

- `wit/egress-demo.wit`: the two worlds, written down.
- `shipper/src/workspace.rs`: the fake workspace, the log batches and the routing bug (`VULN:`). No dependencies; `native-demo/` compiles this same file.
- `shipper/src/egress.rs`: the one outbound call, and how the runtime's answer is classified.
- `shipper/src/fuzz.rs`: runs `../../fuzz/corpus.txt` (compiled in) against the runtime.
- `shipper/src/lib.rs`, `page.rs`: routes, the report, the UI.
- `logsink/src/lib.rs`: the sink.
- `../deploy/`: the three Workload manifests.
