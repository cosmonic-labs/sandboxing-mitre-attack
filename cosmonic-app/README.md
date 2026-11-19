# The component: one sandbox, five attempts, measured

The branded demo. One WebAssembly component, `miner`, in one workload. It serves the page and it is
also the "hijacked" code: when you press a button it makes the attempt for real, inside its own
sandbox, and returns what happened.

| Component | Directory | Filesystem | Network | HTTP | Role |
|-----------|-----------|------------|---------|------|------|
| **miner** | [`miner/`](miner/) | none | deny-all | exports `wasi:http/handler` | The UI and every probe. |

A single component is deliberate. The question this demo asks is what one sandbox can do with the
resources it has, so there is nothing to split.

## The probes

All in [`miner/src/probes.rs`](miner/src/probes.rs). None of them is simulated and no verdict is
hard-coded; the summary strings are computed from the results.

| Probe | What it really does | Class |
|---|---|---|
| CPU | `digest = SHA-256(digest ‖ counter)` in a loop, checking the clock every 1,024 hashes | bounded |
| Threads | `std::thread::Builder::spawn`, 8 times, plus `available_parallelism()` | removed |
| Processes | `std::process::Command::spawn` for `/bin/sh -c nproc` and two worker commands | removed |
| Memory | raw `memory.grow` in 16 MiB steps, writing one byte to every new page | bounded |
| Pool | one `wasi:http/client` request each to `203.0.113.66:3333` and `pool.attacker.example:3333` | removed |
| Persist | returns the response, then keeps hashing in a task spawned with `spawn_local` | bounded |

### The safety budget

Every probe is capped inside the component, whatever the platform does:

- **CPU:** `CPU_BUDGET_MS = 3000`. No request hashes for longer, and `?ms=` can only lower it.
- **Memory:** `MEMORY_CEILING_MB = 64`. Growth stops there if the runtime has not refused first. It
  is deliberately above the manifest's `memoryLimitMb: 32`, so a host that enforces the declared
  limit shows up as `stopped_by: platform`, and small enough for a shared host.
- **Idle and heartbeat:** 120 s at most, and neither uses CPU.

Each result carries `stopped_by`, which is `in-component cap` or `platform`. On Cosmonic Desktop
0.5.33 it was `in-component cap` every time for CPU and memory. The top-level
[README](../README.md#contained-not-removed) has the full table of what was and was not enforced.

### How background work is observed

A component with no disk and no egress cannot leave a note for anyone. The one trace it can leave is
a *refused* request: the host logs every egress denial with a timestamp. So each step of the
`persist` probe ends with a dial to `slice-NN.run-ID.pool.attacker.example`, and the host's own log
shows how far the work got:

```
outgoing request to host 'slice-12.run-1794908131.pool.attacker.example' denied: allowed_hosts policy is empty (deny-all)
```

With the default pool, all 12 slices appeared. With `maxInvocations: 1`, none did.

## Live

- **UI:** http://resource-hijack-sandbox.localhost:8200/
- `GET /run?mode=miner|cpu|spawn|memory|pool|persist|status|idle`
- `GET /probe` and `GET /probe?variant=NAME` (driven by [`../probe/run.sh`](../probe/run.sh))

```bash
curl -s -H 'Host: resource-hijack-sandbox.localhost' http://127.0.0.1:8200/run?mode=miner
```

## The world (WIT)

[`wit/resource-demo.wit`](wit/resource-demo.wit) writes down the world the component targets. The
crate takes its bindings from the `wasip3` crate, so nothing is generated from that file; it is
there to be read. The list that matters is what is absent: no thread interface, no process
interface, no `wasi:sockets`, no filesystem preopen.

## Build and deploy

```bash
cd miner
wash build
# push (bump the tag on every rebuild)
wash oci push --insecure oci.localhost:8200/apps/resource-hijack-sandbox-miner:0.1.3 \
  target/wasm32-wasip2/release/resource_hijack_miner.wasm
# apply (update the digest in the manifest first):
#   cosmonic_workload_apply(../deploy/resource-hijack-sandbox.workload.yaml)
```

No volume is involved, so `cosmonic dev` also works for iterating. Deploy the manifest for anything
you measure: `maxInvocations: 1` is in the manifest, not in the image, and it changes the result of
the Persist and Grow memory probes.

## Layout

- `wit/resource-demo.wit`: the component's world, for reading.
- `miner/src/lib.rs`: routing and the JSON envelope.
- `miner/src/probes.rs`: the probes, the safety budget and the evasion variants.
- `miner/src/page.rs`: the UI. `miner/src/hero.png` is rendered by `../docs/hero/render.sh`.
- `../deploy/resource-hijack-sandbox.workload.yaml`: the Workload.
