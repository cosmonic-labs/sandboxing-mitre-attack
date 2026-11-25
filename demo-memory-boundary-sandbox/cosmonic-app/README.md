# The sandboxed app: three components, three linear memories

> **Scaffold.** `parser` here is a correct, bounds-checked parser. The deliberate out-of-bounds
> write and the linear-memory trap are not implemented. See [`../README.md`](../README.md#status).

One workload, **three separate WebAssembly components**, each its own sandbox with its own linear
memory and its own grant set, auto-linked by the host at runtime:

| Component | Directory | Language | Filesystem | Network | HTTP | Role |
|-----------|-----------|----------|------------|---------|------|------|
| **web** | [`web/`](web/) | Rust (p3) | none | deny-all | exports `wasi:http/handler` | Serves the UI, builds the records, calls the other two. |
| **parser** | [`parser/`](parser/) | C | none | deny-all | none (linked only) | Parses the untrusted record. **Imports nothing.** |
| **vault** | [`vault/`](vault/) | Rust | none | deny-all | none (linked only) | Holds an inert fake secret; exports `reveal()`. |

When the page calls `/run`, `web` calls `secrets.reveal()`, then `parsing.parse(record)`, then
`secrets.reveal()` again, and returns one JSON verdict built from those three answers. Both
interfaces are private to the workload; the browser never reaches `parser` or `vault`.

## Why three components and not one

A single composed component (`wac plug`) would put all three in one grant set. Kept separate and
auto-linked in one workload, the component that handles untrusted bytes is a different sandbox,
with a different linear memory, from the one holding the secret. The only things that cross are
the arguments and results of two functions.

## The interface (WIT)

[`wit/memory-demo.wit`](wit/memory-demo.wit):

```wit
package cosmonic:memory-demo@0.1.0;
interface parsing { parse: func(%record: list<u8>) -> result<string, string>; }
interface secrets { reveal: func() -> string; }
world parser { export parsing; }                  // no imports
world vault  { export secrets; }                  // no imports
world web    { import parsing; import secrets; }  // HTTP comes from the wasip3 crate
```

`record` is a WIT keyword, hence `%record`. Both functions are plain synchronous functions; no
stream crosses the link.

## The C component

[`parser/build.sh`](parser/build.sh) runs `wit-bindgen c` to generate the bindings into `gen/`,
then compiles with wasi-sdk clang:

```bash
clang --target=wasm32-wasip2 -mexec-model=reactor -O2 -Igen -Isrc \
  src/record.c src/component.c gen/parser.c gen/parser_component_type.o -o build/parser.wasm
```

With wasi-sdk 25 or newer, the `wasm32-wasip2` target links straight to a component, so there is
no separate `wasm-tools component new` step and no adapter. The C code uses no stdio, and the
resulting component has no imports:

```bash
wasm-tools component wit parser/build/parser.wasm
# world root { export cosmonic:memory-demo/parsing@0.1.0; }
```

## Build & deploy

```bash
(cd parser && ./build.sh)
(cd vault  && cargo build --target wasm32-wasip2 --release)
(cd web    && cargo build --target wasm32-wasip2 --release)
# push (bump the tag on every rebuild)
wash oci push --insecure oci.localhost:8200/apps/memory-boundary-sandbox-parser:0.1.0 parser/build/parser.wasm
wash oci push --insecure oci.localhost:8200/apps/memory-boundary-sandbox-vault:0.1.0  vault/target/wasm32-wasip2/release/memory_boundary_vault.wasm
wash oci push --insecure oci.localhost:8200/apps/memory-boundary-sandbox-web:0.1.0    web/target/wasm32-wasip2/release/memory_boundary_web.wasm
# apply (update the digests in the manifest first):
#   cosmonic_workload_apply(../deploy/memory-boundary-sandbox.workload.yaml)
```

## Layout

- `wit/memory-demo.wit` — the shared `cosmonic:memory-demo` package.
- `parser/` — `src/record.{h,c}` (the bounds-checked parser), `src/component.c` (WIT glue), `build.sh`.
- `vault/` — `src/lib.rs`.
- `web/` — `src/lib.rs`, `src/page.rs`, `src/site.js`.
- `../deploy/memory-boundary-sandbox.workload.yaml` — the single durable Workload.
