# The sandboxed half: one vulnerable viewer, split across two components

The branded demo. It runs the same path join as the [native baseline](../native-demo/README.md),
a CWE-22 path traversal marked `// VULN:` in [`viewer/src/viewer.rs`](viewer/src/viewer.rs),
compiled to `wasm32-wasip2` and split into **two separate WebAssembly components** in **one
workload**, each its own sandbox with its own capability grants:

| Component | Directory | Filesystem | Network | HTTP | Role |
|-----------|-----------|------------|---------|------|------|
| **web** | [`web/`](web/) | none | deny-all | exports `wasi:http/handler` | Serves the branded UI. Forwards the requested name across the link. |
| **viewer** | [`viewer/`](viewer/) | `/var/app/config` only, read-only | deny-all | none (linked only) | The config viewer, with the bug. Reachable only via the link. |

When the page calls `/run`, `web` hands the requested name to `viewer` through the host's runtime
link (`cosmonic:path-demo/viewing.run(mode, name) -> string`). The name is a `list<u8>`, not a
`string`, so byte sequences that are not valid UTF-8 arrive exactly as the client sent them.

> We deliberately did **not** fix the viewer: no canonicalization, no `..` filter, no prefix
> check. `viewer` joins the name onto `/var/app/config` and opens it. The point is to prove the
> **sandbox** contains the traversal anyway.

## Why two components

A single component would need both HTTP and the filesystem in one grant set. Two components
**auto-linked in one workload** keep their grants **disjoint**: the component that faces the
network has no filesystem, and the component that has the one directory has no network surface at
all.

1. **Capability confinement.** `viewer`'s only filesystem authority is the single preopened
   `/var/app/config`. `..`, an absolute path or a symlink cannot name anything else; `/root`,
   `/etc` and `/` do not exist from inside. Every report runs these as live calls and shows the
   runtime's own error (`os error 63`, `os error 44`).
2. **Read-only.** The mount is `readOnly: true`; create, append and mkdir are refused.
3. **Empty environment.** No variables are passed, so none can leak.
4. **Deny-all egress.** Both components ship `allowedHosts: []`.
5. **No filesystem on `web`, no HTTP on `viewer`.** `web` imports no `wasi:filesystem`; `viewer`
   exports no `wasi:http` and has no hostname. Confirm with `cosmonic_image_inspect`.

## What the viewer reports

Every attempt is tried through two routes and three operations, and each result string is the
runtime's own answer:

- `std_fs`: the viewer's real code path, `Path::join` then `std::fs` (wasi-libc picks the preopen
  and passes the remainder to the host).
- `wasi_open_at`: `wasi:filesystem` `open-at` / `stat-at` called directly on the preopen
  descriptor with the name as given, skipping libc. Valid UTF-8 names only, since the WIT
  parameter is a `string`.

"Escaped" is decided by content. Before probing, `viewer` inventories what is really inside the
preopen (without following symlinks). A successful read must be byte-identical to one of those
files and a successful listing must equal one of those directories; anything else came from
outside. Outside content is never echoed back unless it is the fuzz canary. See
[`viewer/src/probe.rs`](viewer/src/probe.rs).

## Routes

- **UI + API:** http://path-traversal-sandbox.localhost:8200/
- `GET /run` or `/run?mode=ssh`: ask for `../../root/.ssh/id_rsa`.
- `GET /run?mode=benign`: ask for `app.conf`.
- `GET /run?mode=read&name=...`: ask for any name (percent-decoded once).
- `POST /run?mode=read`: ask for any name; the body is the raw bytes.
- `GET /run?mode=variant&id=N`, `/run?mode=corpus`, `/run?mode=fuzz`: the evasion corpus.
- `GET /run?mode=env`: environment, preopens, credential-path probes, write probes.
- `GET /run?mode=all`: all of the above, summarised.

```bash
curl -s -H 'Host: path-traversal-sandbox.localhost' http://127.0.0.1:8200/run | python3 -m json.tool
```

## The interface (WIT)

[`wit/path-demo.wit`](wit/path-demo.wit) defines the one private interface the two components share:

```wit
package cosmonic:path-demo@0.1.0;
interface viewing {
  run: func(mode: string, name: list<u8>) -> string;
}
world viewer { export viewing; }   // the config viewer
world web    { import viewing; }   // the UI
```

Each crate generates its half with `wit_bindgen::generate!`; `web` also keeps the `wasip3` HTTP
bindings for its entrypoint, so its two component-type sections are kept distinct with
`type_section_suffix`. `viewer` additionally uses the `wasip2` crate for the direct
`wasi:filesystem` calls.

## Build & deploy

Two `wash` projects, one workload. Build, push, and apply the single durable Workload:

```bash
# build
(cd viewer && cargo build --target wasm32-wasip2 --release)
(cd web    && cargo build --target wasm32-wasip2 --release)
# push (bump the tag on every rebuild)
wash oci push --insecure oci.localhost:8200/apps/path-traversal-sandbox-viewer:0.1.1  viewer/target/wasm32-wasip2/release/path_traversal_viewer.wasm
wash oci push --insecure oci.localhost:8200/apps/path-traversal-sandbox-web:0.1.2     web/target/wasm32-wasip2/release/path_traversal_web.wasm
# apply (update the digests and the hostPath in the manifest first):
#   cosmonic_workload_apply(../deploy/path-traversal-sandbox.workload.yaml)
```

The manifest carries the read-only `/var/app/config` volume on `viewer`, deny-all egress on both,
and one `wasi:http/handler` hostInterface (which binds to `web`, the only HTTP exporter). The
`cosmonic dev` loop and publish drafts strip the volume, so deploy the durable manifest in
[`../deploy/path-traversal-sandbox.workload.yaml`](../deploy/path-traversal-sandbox.workload.yaml),
not dev. The corpus in [`../fuzz/corpus.txt`](../fuzz/corpus.txt) is compiled into `viewer`
(`include_str!`), so rebuild `viewer` after editing it.

## Layout

- `wit/path-demo.wit`: the shared `cosmonic:path-demo/viewing` interface.
- `web/`: UI (`src/page.rs`) and routing (`src/lib.rs`). No disk.
- `viewer/`: the vulnerable join (`src/viewer.rs`), the live probes and inventory
  (`src/probe.rs`), the corpus loader (`src/corpus.rs`), reports (`src/lib.rs`). The volume lives here.
- `../deploy/path-traversal-sandbox.workload.yaml`: the single durable Workload (both components).
