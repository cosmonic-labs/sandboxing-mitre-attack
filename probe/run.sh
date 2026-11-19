#!/usr/bin/env bash
# Resource-limit evasion probe for the resource-hijack sandbox demo.
#
# Asks the deployed component for its list of evasion variants (thread-spawn
# variants, process-spawn variants, memory-growth patterns), runs them ONE AT A
# TIME, and checks each against the budget:
#
#   worker threads created   0
#   worker processes created 0
#   linear memory            <= the ceiling the component reports
#                            (or <= MEMORY_LIMIT_MB, if you pass one, to test a
#                            limit declared in the manifest)
#
# Sequential on purpose: one request per variant, no parallelism, no load.
#
#   probe/run.sh                      # against Cosmonic Desktop on 127.0.0.1:8200
#   MEMORY_LIMIT_MB=32 probe/run.sh   # also hold memory to a declared limit
#   BASE=https://host HOST=name probe/run.sh
#
# Exit status: 0 if no variant exceeded the budget, 1 otherwise.
set -euo pipefail
BASE="${BASE:-http://127.0.0.1:8200}"
HOST="${HOST:-resource-hijack-sandbox.localhost}"
export MEMORY_LIMIT_MB="${MEMORY_LIMIT_MB:-}"

get() { curl -sS --max-time 30 -H "Host: $HOST" "$BASE$1"; }

list="$(get /probe)"
names="$(printf '%s' "$list" | python3 -I -c 'import json,sys; print("\n".join(v["variant"] for v in json.load(sys.stdin)["variants"]))')"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
for name in $names; do
  get "/probe?variant=$name" | python3 -I -c 'import json,sys; print(json.dumps(json.load(sys.stdin)))' >> "$tmp"
done

python3 -I - "$tmp" "$list" <<'PY'
import json, os, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
budget = json.loads(sys.argv[2])["budget"]
ceiling = budget["memory_ceiling_mb"]
declared = os.environ.get("MEMORY_LIMIT_MB") or ""
mem_budget = float(declared) if declared else float(ceiling)
exceeded = 0
print(f"{'variant':24} {'result':26} answer")
for r in rows:
    x = r["result"]
    if r["group"] == "memory":
        over = x["reached_mb"] > mem_budget
        result = f'{x["start_mb"]:g} -> {x["reached_mb"]:g} MiB'
        said = f'stopped by {x["stopped_by"]}'
    else:
        over = x["workers_created"] > 0
        result = f'{x["workers_created"]} of {x["attempted"]} created'
        said = (x.get("error") or {}).get("error", "no error")
    exceeded += over
    print(f'{r["variant"]:24} {result:26} {said}{"   <-- EXCEEDED" if over else ""}')
what = f"declared memoryLimitMb {declared}" if declared else f"in-component ceiling {ceiling} MiB"
print(f"\n{len(rows)} variants tried, {exceeded} exceeded the budget (0 workers; memory: {what}).")
sys.exit(1 if exceeded else 0)
PY
