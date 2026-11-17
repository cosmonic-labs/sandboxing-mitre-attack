# The component

One WebAssembly component, `runner`, in one workload. It is both the "CI runner" and the page that
drives it.

| File | What it is |
|---|---|
| `runner/src/job.rs` | The two poisoned job files and the step interpreter. The bug is here, marked `// VULN:`: the runner executes every step it is handed. |
| `runner/src/probes.rs` | What a step turns into: a file open, a directory listing, an environment lookup, a process spawn, or an HTTP `GET` through `wasi:http/client`. Each makes the real call and returns the runtime's own error. |
| `runner/src/lib.rs` | Routes (`/`, `/run`, `/job`, `/health`), the JSON report, and the import list recorded from `cosmonic_image_inspect`. |
| `runner/src/page.rs` | The branded UI. |
| `runner/.wash/config.yaml` | The build command and the grants: `allowedHosts: []`, no volumes. |

The probes are reachability probes. They name only read-only targets (`/_ping`, `/version`,
`/healthz`, a path, a variable, `docker version`, `kubectl version`), report byte or entry counts
and never content, and nothing in the component would act on a successful answer.

## Why one component

The zip demo splits `web` from `extractor` so that each gets a disjoint grant set. This demo has no
grant to separate: the runner needs nothing but inbound HTTP, so a second component would add a
link and no boundary.

## Build, publish, apply

```bash
cd runner
wash build        # cargo build --target wasm32-wasip2 --release
wash oci push --insecure oci.localhost:8200/apps/container-escape-sandbox-runner:<tag> \
  target/wasm32-wasip2/release/container_escape_runner.wasm
```

Bump the tag on every push, pin the new digest in
`../deploy/container-escape-sandbox.workload.yaml` (`cosmonic_image_inspect` prints it), and apply
that manifest. Needs Rust 1.94 or newer with the `wasm32-wasip2` target, and `wash`.

After a rebuild, check the imports again:

```bash
wasm-tools component wit runner/target/wasm32-wasip2/release/container_escape_runner.wasm | grep import
```

There should be no `wasi:sockets` line. If the list differs from `IMPORTS` in `runner/src/lib.rs`,
update the constant and the README.

## Regenerating the hero

`../docs/hero/render.sh` renders `hero.template.html` with headless Chrome into
`../docs/images/` and copies it to `runner/src/hero.png`, which the component embeds.
