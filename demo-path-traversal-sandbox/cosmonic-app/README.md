# The sandboxed half: one vulnerable viewer, split across components

The branded demo. It runs the same path join as the [native baseline](../native-demo/README.md),
a CWE-22 path traversal marked `// VULN:` in [`viewer/src/viewer.rs`](viewer/src/viewer.rs),
compiled to `wasm32-wasip2` and split into **two separate WebAssembly components** in **one
workload**, each its own sandbox with its own capability grants:

| Component | Directory | Filesystem | Network | HTTP | Role |
|-----------|-----------|------------|---------|------|------|
| **web** | [`web/`](web/) | none | deny-all | exports `wasi:http/handler` | Serves the branded UI. Forwards the requested name across the link. |
| **viewer** | [`viewer/`](viewer/) | `/var/app/config` only, read-only | deny-all | none (linked only) | The config viewer, with the bug. Reachable only via the link. |
| **seeder** | [`seeder/`](seeder/) | the same volume at `/seed`, read-write | deny-all | none (not linked) | The workload's run-once `service`. Writes the sample files into an empty volume at startup. |

`seeder` is not part of the web/viewer pair. It exists because the default manifest's volume is
`ephemeral` and starts empty; see [The seeder](#the-seeder).

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
4. **Deny-all egress.** All three components ship `allowedHosts: []`.
5. **No filesystem on `web`, no HTTP on `viewer`.** `web` imports no `wasi:filesystem`; `viewer`
   exports no `wasi:http` and has no hostname. Confirm with `cosmonic_image_inspect`.

## The seeder

[`seeder/`](seeder/) is a command component (`wasi:cli/run`) declared as the Workload's `service`,
so the host runs it once when the workload starts. Its mount of the volume is read-write. It
writes `database.conf`, `profiles/staging.conf`, `profiles/café.conf`, the `links/` fixtures from
[`../fuzz/links.txt`](../fuzz/links.txt), a `.seed-report.json`, and `app.conf` last; `web` waits
for `viewing.run("ready")` (does `app.conf` exist) before forwarding the first request. Everything
it writes is compiled in. It reads no request, argument or environment variable.

- **Symlinks are best effort.** `{OUT}` in a link target becomes `/outside` (there is no host
  path to use). On Cosmonic Desktop 0.5.33 the runtime refused all four absolute-target links
  with `not-permitted` and created the other twelve. Each refusal is recorded in the report
  (`/run?mode=seed-report`) and never fails the seed.
- **It must stay unlinked.** Linked components share one store and see each other's volume
  mounts. With `seeder` exporting an interface that `web` imported, `viewer` gained `/seed` as a
  second, writable preopen (measured; the write probes in `/run?mode=env` cover every preopen for
  this reason). As a service with no shared interface it has its own store.
- **In the hostPath manifest** its mount is `readOnly: true`. The directory already holds the
  sample files, so it writes nothing and exits.

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
[`viewer/src/probe.rs`](viewer/src/probe.rs). The fuzz report also lists `symlink_fixtures_absent`:
fixture links that are not in the volume, which happens on a seeded volume when the runtime
refuses to create them. Variants that name one get `No such file or directory` and test nothing.

## Routes

- **UI + API:** http://path-traversal-sandbox.localhost:8200/
- `GET /run` or `/run?mode=ssh`: ask for `../../root/.ssh/id_rsa`.
- `GET /run?mode=benign`: ask for `app.conf`.
- `GET /run?mode=read&name=...`: ask for any name (percent-decoded once).
- `POST /run?mode=read`: ask for any name; the body is the raw bytes.
- `GET /run?mode=variant&id=N`, `/run?mode=corpus`, `/run?mode=fuzz`: the evasion corpus.
- `GET /run?mode=env`: environment, preopens, credential-path probes, write probes.
- `GET /run?mode=all`: all of the above, summarised.
- `GET /run?mode=seed-report`: what the seeder wrote and which links were refused (seeded volumes only).

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

Three `wash` projects, one workload. Build, push, and apply one of the two durable Workloads:

```bash
# build
(cd viewer && wash build)
(cd web    && wash build)
(cd seeder && wash build)
# push (bump the tag on every rebuild)
wash oci push --insecure oci.localhost:8200/apps/path-traversal-sandbox-viewer:0.1.5  viewer/target/wasm32-wasip2/release/path_traversal_viewer.wasm
wash oci push --insecure oci.localhost:8200/apps/path-traversal-sandbox-web:0.1.4     web/target/wasm32-wasip2/release/path_traversal_web.wasm
wash oci push --insecure oci.localhost:8200/apps/path-traversal-sandbox-seeder:0.1.2  seeder/target/wasm32-wasip2/release/path_traversal_seeder.wasm
# apply (update the digests in both manifests first):
#   cosmonic_workload_apply(../deploy/path-traversal-sandbox.workload.yaml)        ephemeral volume
#   cosmonic_workload_apply(../deploy/path-traversal-sandbox.fuzz.workload.yaml)   hostPath + canary
```

Both manifests carry the read-only `/var/app/config` mount on `viewer`, the `seeder` service,
deny-all egress on all three, and one `wasi:http/handler` hostInterface (which binds to `web`, the
only HTTP exporter). They differ in the volume: `ephemeral` with the seeder's mount read-write
(the default, which also runs on a cluster), or `hostPath` at `../deploy/volume/config` with the
seeder's mount read-only (for `fuzz/plant.sh` and `fuzz/run.py`). The `cosmonic dev` loop and
publish drafts strip the volume, so deploy a durable manifest, not dev. The corpus in [`../fuzz/corpus.txt`](../fuzz/corpus.txt) is compiled into `viewer`
(`include_str!`), so rebuild `viewer` after editing it.

## Layout

- `wit/path-demo.wit`: the shared `cosmonic:path-demo/viewing` interface.
- `web/`: UI (`src/page.rs`) and routing (`src/lib.rs`). No disk.
- `viewer/`: the vulnerable join (`src/viewer.rs`), the live probes and inventory
  (`src/probe.rs`), the corpus loader (`src/corpus.rs`), reports (`src/lib.rs`). The volume lives here.
- `seeder/`: the run-once service (`src/main.rs`). The only write access to the volume.
- `../deploy/path-traversal-sandbox.workload.yaml`: the default durable Workload (ephemeral volume).
- `../deploy/path-traversal-sandbox.fuzz.workload.yaml`: the hostPath variant for the fuzz harness.
