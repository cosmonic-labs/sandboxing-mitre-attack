#!/usr/bin/env python3
"""Filesystem-preopen evasion harness for demo-path-traversal-sandbox.

Drives the DEPLOYED config viewer with every variant in corpus.txt and asserts
that no read or listing ever returns anything from outside the one directory
the sandbox was given. Standard library only.

    fuzz/plant.sh                       # once: plant the symlink fixtures
    python3 fuzz/run.py                 # against Cosmonic Desktop on 127.0.0.1:8200
    python3 fuzz/run.py -v              # print every variant, not just the summary
    python3 fuzz/run.py --json out.json # also write every result as JSON

How "escaped" is detected, without touching anything real:

  deploy/volume/config/   is the ONLY directory mounted into the sandbox.
  deploy/volume/outside/  is its sibling and is NOT mounted. It holds
                          CANARY.txt, a harmless marker file.

For each variant the harness POSTs the raw name bytes to /run?mode=read. The
viewer joins the name onto /var/app/config (the unpatched CWE-22 bug) and
tries read, list and stat through std::fs and through a direct
wasi:filesystem open-at. The harness, not the component, decides pass or fail:

    control     must return a file, byte-identical to one inside config/
    escape      must not escape
    equivalent  must not escape (may resolve inside or be refused)

A variant ESCAPED if any of these is true:
  - the response contains the canary's marker line, anywhere
  - the response carries file content that is not byte-identical to a file
    this harness can see inside config/ on the host
  - the component itself reports outcome ESCAPED (it keeps its own inventory
    of the preopen and compares every successful read and listing against it)

It then asks the component for its own /run?mode=fuzz run (the same corpus,
compiled in) and checks the two agree. Finally it opens the canary-seeking
names natively on the host, with no sandbox, to show the corpus is real: those
same names do reach the canary when nothing is in the way.

Exit status is 1 if any variant escaped or a control failed, 2 if the fixtures
are missing, 0 otherwise. If a variant escapes, that is a real finding: record
it and report it upstream; do not develop it further.
"""
import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
VOLUME = os.path.realpath(os.path.join(HERE, "..", "deploy", "volume"))


def expand(spec: str, out_dir: str) -> bytes:
    """Corpus name -> the exact bytes sent. Mirrors viewer/src/corpus.rs."""
    out = bytearray()
    i = 0
    while i < len(spec):
        rest = spec[i:]
        m = re.match(r"\\x([0-9a-fA-F]{2})", rest)
        if m:
            out.append(int(m.group(1), 16))
            i += 4
            continue
        m = re.match(r"\\u\{([0-9a-fA-F]+)\}", rest)
        if m:
            out += chr(int(m.group(1), 16)).encode("utf-8")
            i += m.end()
            continue
        if rest.startswith("\\\\"):
            out += b"\\"
            i += 2
            continue
        if rest.startswith("{OUT}"):
            out += out_dir.encode("utf-8")
            i += 5
            continue
        m = re.match(r"\{REP:([^}]*):(\d+)\}", rest)
        if m:
            out += expand(m.group(1), out_dir) * int(m.group(2))
            i += m.end()
            continue
        out += spec[i].encode("utf-8")
        i += 1
    return bytes(out)


def load(path):
    variants = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 3)
            if len(parts) < 3:
                continue
            variants.append(
                {
                    "id": len(variants),
                    "class": parts[0],
                    "technique": parts[1],
                    "name": parts[2],
                    "note": parts[3] if len(parts) > 3 else "",
                }
            )
    return variants


def inside_files(config_dir):
    """Contents of every regular file really inside config/ (symlinks not followed)."""
    found = {}
    for root, dirs, files in os.walk(config_dir, followlinks=False):
        for name in files:
            full = os.path.join(root, name)
            if os.path.islink(full):
                continue
            with open(full, "rb") as fh:
                found[os.path.relpath(full, config_dir)] = fh.read()
    return found


def call(base, host, path_and_query, timeout, body=None):
    req = urllib.request.Request(
        base + path_and_query,
        data=body,
        method="POST" if body is not None else "GET",
        headers={"Host": host, "Content-Type": "application/octet-stream"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def native_baseline(variants, config_dir, out_dir, marker):
    """Open the canary-seeking names on the host with NO sandbox.

    Only names that mention the canary or go through the planted links are
    opened, so this never touches a path outside this repo's volume directory
    except the canary itself. Content is compared to the marker and discarded.
    """
    tried = reached = 0
    base = config_dir.encode("utf-8")
    for v in variants:
        if v["class"] != "escape":
            continue
        name = expand(v["name"], out_dir)
        if b"CANARY" not in name or b"\x00" in name:
            continue
        tried += 1
        try:
            with open(os.path.join(base, name), "rb") as fh:
                if fh.read(len(marker)) == marker:
                    reached += 1
        except (OSError, ValueError):
            pass
    return tried, reached


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:8200", help="Cosmonic Desktop ingress")
    ap.add_argument("--host", default="path-traversal-sandbox.localhost", help="the demo's ingress host")
    ap.add_argument("--corpus", default=os.path.join(HERE, "corpus.txt"))
    ap.add_argument("--volume", default=VOLUME, help="deploy/volume (holds config/ and outside/)")
    ap.add_argument("--json", help="write every result to this file")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    config_dir = os.path.join(args.volume, "config")
    out_dir = os.path.join(args.volume, "outside")
    canary = os.path.join(out_dir, "CANARY.txt")
    if not os.path.isfile(canary):
        print(f"missing canary: {canary}", file=sys.stderr)
        return 2
    with open(canary, "rb") as fh:
        marker = fh.readline().strip()
    if not os.path.islink(os.path.join(config_dir, "links", "canary-rel")):
        print("symlink fixtures are not planted: run fuzz/plant.sh first", file=sys.stderr)
        return 2

    inside = inside_files(config_dir)
    variants = load(args.corpus)
    results, escapes, failed_controls = [], [], []

    for v in variants:
        name = expand(v["name"], out_dir)
        raw = call(args.base, args.host, "/run?mode=read", args.timeout, body=name)
        why = []
        if marker in raw:
            why.append("response contains the canary marker")
        try:
            report = json.loads(raw)
        except ValueError:
            report = {"outcome": "error", "verdict": raw[:200].decode("utf-8", "replace")}
        outcome = report.get("outcome", "error")
        content = report.get("content")
        if content is not None and content.encode("utf-8") not in inside.values():
            why.append("returned content that is not a file inside config/")
        if outcome == "ESCAPED":
            why.append("component reported ESCAPED")
        if outcome == "error":
            why.append("no verdict: " + str(report.get("error") or report.get("verdict")))

        escaped = bool(why)
        control_ok = None
        if v["class"] == "control":
            control_ok = (not escaped) and content is not None
            if not control_ok:
                failed_controls.append(v)
        if escaped:
            escapes.append((v, why))

        answer = (report.get("std_fs") or {}).get("read", "")
        results.append(
            {
                **v,
                "bytes": len(name),
                "outcome": "ESCAPED" if escaped else outcome,
                "why": why,
                "std_fs": report.get("std_fs"),
                "wasi_open_at": report.get("wasi_open_at"),
            }
        )
        if args.verbose or escaped or control_ok is False:
            shown = v["name"] if len(v["name"]) <= 46 else v["name"][:43] + "..."
            print(f"{v['id']:>3} {v['class']:<10} {v['technique']:<17} {shown:<46} {results[-1]['outcome']:<8} {answer}")

    # Cross-check against the component's own run of the same corpus.
    raw = call(args.base, args.host, "/run?mode=fuzz&out=" + urllib.parse.quote(out_dir, safe=""), args.timeout)
    component = json.loads(raw)
    disagree = []
    if marker in raw:
        disagree.append("component fuzz response contains the canary marker")
    for row in component.get("results", []):
        mine = results[row["id"]]["outcome"] if row["id"] < len(results) else None
        if row["outcome"] != mine:
            disagree.append(f"#{row['id']}: harness {mine}, component {row['outcome']}")

    tried_native, reached_native = native_baseline(variants, config_dir, out_dir, marker)

    n = len(results)
    refused = sum(1 for r in results if r["outcome"] == "refused")
    inside_n = sum(1 for r in results if r["outcome"] == "inside")
    controls = [v for v in variants if v["class"] == "control"]
    calls = sum((3 if r["std_fs"] else 0) + (3 if r["wasi_open_at"] else 0) for r in results)

    print()
    print(f"{n} variants tried, {len(escapes)} escaped")
    print(f"  refused by the runtime:        {refused}")
    print(f"  resolved inside the preopen:   {inside_n}")
    print(f"  legitimate reads served:       {len(controls) - len(failed_controls)}/{len(controls)}")
    print(f"  filesystem calls attempted:    {calls}")
    print(f"  component's own run:           {component.get('line')}" + ("" if not disagree else "  (DISAGREES)"))
    print(f"  host baseline, no sandbox:     {reached_native} of {tried_native} canary-seeking names reach the canary natively")
    for d in disagree:
        print("  disagreement:", d)
    for v, why in escapes:
        print(f"  ESCAPED #{v['id']} [{v['technique']}] {v['name']}: {'; '.join(why)}")
    for v in failed_controls:
        print(f"  CONTROL FAILED #{v['id']} {v['name']}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "line": f"{n} variants tried, {len(escapes)} escaped",
                    "variants_tried": n,
                    "escaped": len(escapes),
                    "refused": refused,
                    "resolved_inside": inside_n,
                    "filesystem_calls": calls,
                    "component_line": component.get("line"),
                    "native_baseline": {"tried": tried_native, "reached_canary": reached_native},
                    "results": results,
                },
                fh,
                indent=1,
            )

    return 1 if (escapes or failed_controls or disagree) else 0


if __name__ == "__main__":
    sys.exit(main())
