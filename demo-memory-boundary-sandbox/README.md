# Memory you can't name: a memory-boundary sandbox demo (MITRE ATT&CK T1055)

**Read the full story on the Cosmonic blog:** [TODO: blog post title](https://cosmonic.com/blog/TODO-memory-boundary-sandbox/) (placeholder URL)

<!-- TODO: hero image at docs/images/memory-boundary-sandbox-hero.png -->

## Status

**This repo is a scaffold. The headline scenario is not implemented.**

| | |
|---|---|
| **Implemented and running** | The three-component workload (`parser` in C, `vault` and `web` in Rust), auto-linked by the host through a private `cosmonic:memory-demo@0.1.0` package; disjoint, empty grant sets; the C → `wasm32-wasip2` component toolchain; the branded page and its `/run` API; the deployment manifest. |
| **Shown by this build** | The structural half of the boundary: the built `parser` component has **no imports at all** (confirmed with `cosmonic_image_inspect`, below), and `vault` keeps its secret in a separate component with its own linear memory. |
| **Not implemented** | The deliberate out-of-bounds write (CWE-787) in `parser`. The `parser` here is a correct, bounds-checked parser with no `// VULN:` marker, because it has no vulnerability. |
| **Not implemented** | The demonstration of that write trapping at the Wasm linear-memory bound. No trap is produced or shown anywhere in this build. |
| **Not included** | The native AddressSanitizer baseline. [`native-demo/`](native-demo/README.md) holds a README only. |

Why: the agent building this repo was stopped by a safety control while writing the vulnerable
parser, and did not retry it in any form. That piece is left for the repo owner to add. Until it
is, **nothing in this repo runs a memory-corruption attempt**, and the "Send an oversized record"
button shows a safe parser's ordinary rejection, not a contained attack. The evidence for the
linear-memory bound itself is the upstream testing cited in
[Where the memory bound is tested](#where-the-memory-bound-is-tested).

## What the demo is about

Process injection (ATT&CK [T1055](https://attack.mitre.org/techniques/T1055/)) and its relatives
depend on one process being able to reach another's memory: a shared address space, `ptrace`,
`/proc/<pid>/mem`, a writable library path. A memory-safety bug in a native service (an
out-of-bounds write, [CWE-787](https://cwe.mitre.org/data/definitions/787.html)) is dangerous
largely because of what sits next to the buffer in that shared space.

A WebAssembly component has none of that to reach for. Each component instance has its own linear
memory, every access is bounds-checked against that one memory, and the only things a component
can touch outside it are the functions its world imports.

> **You can't execute what you don't have.** A sandbox doesn't have to recognize the attack. It
> starts with nothing and hands the code only the capabilities you grant. Here the component that
> handles untrusted bytes is granted nothing, and imports nothing. See
> [principles of secure agent platforms](https://cosmonic.com/ai-sandbox/principles/).

This is a **structural** boundary: it holds because a capability is absent, not because a check
on a string or a path succeeds.

## The scenarios

| Button | Vulnerability (CWE / ATT&CK) | What the record does | In the sandbox (this build) |
|---|---|---|---|
| **Send a valid record** | none | A 19-byte payload in a well-formed record. | `parser` returns the decoded field. `vault.reveal()` returns the same secret before and after. |
| **Send an oversized record** | none in this build. The intended scenario is CWE-787 / T1055, **not implemented**. | A 200-byte payload for a 64-byte buffer, with a truthful length header. | `parser`'s bounds check refuses it with an ordinary `err(...)`. Nothing is written out of bounds and nothing traps. `vault.reveal()` returns the same secret before and after. |

### The intended contrast (not demonstrated here)

The design this scaffold is waiting on is: *native → AddressSanitizer reports the out-of-bounds
write next to an adjacent secret; component → the write traps at the linear-memory bound and the
vault is untouched.* Neither half is built in this repo. One nuance belongs with that claim when
it is built: a Wasm out-of-bounds write traps only when it leaves the linear memory. A small
overflow that stays inside the parser's own memory would corrupt the parser's own data without
trapping. The guarantee is that a component cannot address another component's memory, not that
every overflow traps.

## Quickstart

1. **Install [Cosmonic Desktop](https://cosmonic.com/desktop/).** It runs WebAssembly components
   as sandboxed workloads and listens on `127.0.0.1:8200`.
2. **Nothing to build.** The manifest pins the three published images by digest on ghcr
   (`ghcr.io/cosmonic-labs/demo-memory-boundary-sandbox/{web,parser,vault}`). To run your own
   build instead, see [Build from source](#build-from-source) and point the `image:` lines at it.
3. **Apply the manifest**,
   [`deploy/memory-boundary-sandbox.workload.yaml`](deploy/memory-boundary-sandbox.workload.yaml).
   The easiest route is an AI assistant connected to Desktop's MCP server
   ([Connect coding agents](https://cosmonic.com/docs/desktop/coding-agents/)):

   > "Apply `deploy/memory-boundary-sandbox.workload.yaml` to Cosmonic Desktop, then show me its status."

4. **Open <http://memory-boundary-sandbox.localhost:8200/>** and press the two buttons.

### From the command line

| Scenario | Run it |
|---|---|
| Send a valid record | `/run?mode=valid` (the default) |
| Send an oversized record | `/run?mode=oversized` |

```bash
B=http://127.0.0.1:8200
curl -s -H 'Host: memory-boundary-sandbox.localhost' "$B/run?mode=oversized" | python3 -m json.tool
```

Captured from the running workload:

```json
{
    "mode": "oversized",
    "build": "This build ships a bounds-checked parser. The deliberate out-of-bounds write (CWE-787) and the trap at the Wasm linear-memory bound are NOT implemented, so no memory-corruption attempt is run here.",
    "record": { "bytes": 206, "payload_bytes": 200, "capacity": 64 },
    "parser": {
        "outcome": "rejected",
        "error": "rejected: payload is longer than the 64-byte field buffer (received 206 bytes, declared payload 200, capacity 64)"
    },
    "vault": {
        "secret_before": "DEMO-ONLY-NOT-A-REAL-SECRET::vault-7f3a91c4",
        "secret_after": "DEMO-ONLY-NOT-A-REAL-SECRET::vault-7f3a91c4",
        "unchanged": true
    },
    "attack_run": false,
    "verdict": "The parser's bounds check refused the record; nothing was written past its buffer. vault.reveal() returned the same secret before and after: true."
}
```

`mode=valid` returns `"parser": {"outcome": "parsed", "report": {"field": "sensor=42;status=OK", "field_len": 19, "capacity": 64, "bounds_checked": true}}`
with the same `vault` block.

The secret is an inert placeholder, not a credential. `unchanged: true` compares two real calls
to `vault.reveal()` made in the same request; in this build nothing attempts to change it.

## How it's built

One workload, three WebAssembly components, each its own sandbox with its own linear memory. The
browser only ever talks to `web`.

| Component | Language | Filesystem | Network | HTTP | Imports | Job |
|---|---|---|---|---|---|---|
| `web` | Rust (p3) | none | no egress | serves `wasi:http/handler` | `parsing`, `secrets`, `wasi:http/types`, plus Rust std's `wasi:cli` / `wasi:io` / `wasi:random` | UI; builds the records; calls the other two |
| `parser` | C (wasi-sdk) | none | no egress | none | **none** | parses the untrusted record bytes |
| `vault` | Rust | none | no egress | none | Rust std's `wasi:cli` (environment, exit, stdio, terminal) and `wasi:io` only | holds the fake secret, exports `reveal()` |

`cosmonic_image_inspect` on the published parser image reports:

```json
{ "exports": ["cosmonic:memory-demo/parsing@0.1.0"], "imports": [] }
```

That empty list is the structural boundary. The parser has no `wasi:filesystem`, no
`wasi:sockets`, no `wasi:cli`, and no interface of any kind that takes another component's memory
as an argument. There is no `ptrace` and no `/proc` to ask for, because nothing in its world could
carry the request. `vault` and `web` do carry the standard-library imports listed above (the Rust
standard library links stdio, environment and exit); neither has a filesystem or socket import,
and all three components ship `allowedHosts: []` and no volumes.

The same manifest runs on Kubernetes with [Cosmonic Control](https://cosmonic.com/control/) once
the images are signed and the unsigned annotation is removed.

## Where the memory bound is tested

For a structural boundary the runtime half is already tested upstream, far more thoroughly than a
demo could. This repo cites that work rather than rebuilding it:

- Wasmtime [`crates/fuzzing/src/oracles/memory.rs`](https://github.com/bytecodealliance/wasmtime/blob/main/crates/fuzzing/src/oracles/memory.rs):
  the fuzzing oracle for in-bounds and out-of-bounds linear-memory access.
- Wasmtime [`crates/fuzzing/src/oracles/stacks.rs`](https://github.com/bytecodealliance/wasmtime/blob/main/crates/fuzzing/src/oracles/stacks.rs):
  the oracle that checks the runtime's view of the call stack against the guest's.
- Wasmtime [`fuzz/fuzz_targets/differential.rs`](https://github.com/bytecodealliance/wasmtime/blob/main/fuzz/fuzz_targets/differential.rs):
  differential fuzzing against the spec interpreter, wasmi and V8.
- The [WebAssembly core spec test suite](https://github.com/WebAssembly/spec/tree/main/test/core),
  which includes the linear-memory bounds cases, and Wasmtime's continuous fuzzing on
  [OSS-Fuzz](https://github.com/google/oss-fuzz/tree/master/projects/wasmtime).

This is why the memory demo is cited and not fuzzed. An *enforced* boundary (a path or host-name
check) is an implementation that evasion can defeat, so it needs an adversarial fuzz harness. A
*structural* boundary is the absence of any import that reaches another memory; there is no check
to evade, and the remaining question (does the runtime bound linear memory correctly) is the one
the upstream suites above exist to answer.

## The long tail

These techniques share the precondition that one process can reach another's memory or loader.
The statements below are about what the parser's world lacks, as shown by its empty import list.
They are not results of a test in this repo.

| Technique | What it needs | What the parser's world has |
|---|---|---|
| [T1055.008](https://attack.mitre.org/techniques/T1055/008/) ptrace system calls | `ptrace` | no system-call interface; no imports |
| [T1055.009](https://attack.mitre.org/techniques/T1055/009/) proc memory | `/proc/<pid>/mem` | no filesystem import, no volume |
| [T1055.014](https://attack.mitre.org/techniques/T1055/014/) VDSO hijacking | a mapped vDSO in a shared address space | a private linear memory; no shared mapping |
| [T1003](https://attack.mitre.org/techniques/T1003/) OS credential dumping (reading another process's memory) | read access to another process | no interface that names another component's memory |
| [T1212](https://attack.mitre.org/techniques/T1212/) exploitation for credential access | a bug whose blast radius includes the credential store | the secret lives in a different component's memory |
| [T1057](https://attack.mitre.org/techniques/T1057/) process discovery | a process table | no process concept in its world |
| [T1574](https://attack.mitre.org/techniques/T1574/) hijack execution flow | a writable loader search path or library | no filesystem; components are linked by the host from digest-pinned images |

A bug inside a component can still corrupt that component's own state and make it return wrong
answers to its callers. Isolation limits where a bug can reach; it does not make the code correct.

## Build from source

Needs a Rust toolchain with the `wasm32-wasip2` target, `wash`,
[wasi-sdk](https://github.com/WebAssembly/wasi-sdk) 25 or newer (28 was used here; set
`WASI_SDK_PATH` if it is not under `~/wasi-sdk/`), and `wit-bindgen-cli` (0.50.0 was used).

```bash
cd cosmonic-app/parser && ./build.sh                                        # C -> build/parser.wasm
cd ../vault            && cargo build --target wasm32-wasip2 --release
cd ../web              && cargo build --target wasm32-wasip2 --release
cd ..
# publish (bump the tag on every re-push, then update the digests in the manifest)
wash oci push --insecure oci.localhost:8200/apps/memory-boundary-sandbox-parser:0.1.0 parser/build/parser.wasm
wash oci push --insecure oci.localhost:8200/apps/memory-boundary-sandbox-vault:0.1.0  vault/target/wasm32-wasip2/release/memory_boundary_vault.wasm
wash oci push --insecure oci.localhost:8200/apps/memory-boundary-sandbox-web:0.1.0    web/target/wasm32-wasip2/release/memory_boundary_web.wasm
```

## Repo layout

```
.
├── deploy/memory-boundary-sandbox.workload.yaml   one workload, three components (pinned by digest)
├── cosmonic-app/
│   ├── wit/memory-demo.wit    cosmonic:memory-demo: the parsing and secrets interfaces
│   ├── parser/                C record parser (bounds-checked): src/record.c, src/component.c, build.sh
│   ├── vault/                 Rust: holds the fake secret, exports reveal()
│   └── web/                   Rust p3 UI: builds the records, calls parser and vault
├── native-demo/               README only: the ASan baseline is not included
└── docs/images/               hero image (TODO)
```

## Keep reading

[Choosing an agent sandbox](https://cosmonic.com/ai-sandbox/choosing-an-agent-sandbox/) ·
[Deny by default](https://cosmonic.com/ai-sandbox/principles/deny-by-default/) ·
[Least authority](https://cosmonic.com/ai-sandbox/least-privilege-ai-agents/) ·
[Capabilities over ambient authority](https://cosmonic.com/ai-sandbox/capabilities/)

Questions, or a case where this breaks? Find us in the [wasmCloud Slack](https://slack.wasmcloud.com/).
