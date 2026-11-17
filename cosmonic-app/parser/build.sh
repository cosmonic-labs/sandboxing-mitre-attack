#!/usr/bin/env bash
# Build the C `parser` component: wit-bindgen (C bindings) + wasi-sdk clang.
# With wasi-sdk >= 25 the wasm32-wasip2 target links straight to a component
# (clang drives wasm-component-ld), so no separate `wasm-tools component new`.
set -euo pipefail
cd "$(dirname "$0")"

WASI_SDK="${WASI_SDK_PATH:-$HOME/wasi-sdk/wasi-sdk-28.0-arm64-macos}"
CC="$WASI_SDK/bin/clang"
[ -x "$CC" ] || { echo "wasi-sdk clang not found at $CC (set WASI_SDK_PATH)" >&2; exit 1; }

rm -rf gen build && mkdir -p gen build
wit-bindgen c ../wit --world parser --out-dir gen >/dev/null

"$CC" --target=wasm32-wasip2 -mexec-model=reactor \
  -O2 -Wall -Wextra -Werror -Wno-unused-parameter \
  -Igen -Isrc \
  src/record.c src/component.c gen/parser.c gen/parser_component_type.o \
  -o build/parser.wasm

echo "built build/parser.wasm"
