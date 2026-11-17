#!/usr/bin/env python3
"""Egress allow-list evasion harness for demo-egress-exfil-sandbox.

Drives the DEPLOYED shipper component with every variant in corpus.txt and
asserts that only exact allow-list members connect. Standard library only.

    python3 fuzz/run.py                 # against Cosmonic Desktop on 127.0.0.1:8200
    python3 fuzz/run.py -v              # print every variant, not just the summary
    python3 fuzz/run.py --json out.json # also write every result as JSON

For each variant the harness calls the shipper's /probe endpoint, which makes
one real outbound wasi:http request with that exact authority and returns the
runtime's answer. The harness, not the component, decides pass or fail:

    control     must connect with HTTP 200
    attacker    must not pass the allow-list
    confusable  must not pass the allow-list
    ssrf        must not pass the allow-list
    equivalent  recorded only
    byport      recorded only

"Pass the allow-list" means the request connected, or failed later for a
transport reason (DNS, connection refused, timeout). Exit status is 1 if any
variant escaped or a control failed, 0 otherwise.

It then asks the component for its own /fuzz run (the same corpus, compiled
in) and checks the two agree.
"""
import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request

MUST_REFUSE = ("attacker", "confusable", "ssrf")
HERE = os.path.dirname(os.path.abspath(__file__))


def unescape(field: str) -> bytes:
    """Turn \\xNN escapes into raw bytes."""
    raw = field.encode("utf-8")
    return re.sub(rb"\\x([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]), raw)


def load(path):
    variants = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split(None, 3)
            if len(parts) < 3:
                continue
            variants.append(
                {
                    "class": parts[0],
                    "authority": unescape(parts[1]),
                    "technique": parts[2],
                    "note": parts[3].strip() if len(parts) > 3 else "",
                }
            )
    return variants


def get(base, host, path_and_query, timeout):
    req = urllib.request.Request(base + path_and_query, headers={"Host": host})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:8200", help="Cosmonic Desktop ingress")
    ap.add_argument("--host", default="egress-exfil-sandbox.localhost", help="the shipper's ingress host")
    ap.add_argument("--corpus", default=os.path.join(HERE, "corpus.txt"))
    ap.add_argument("--json", help="write every result to this file")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    variants = load(args.corpus)
    results, escapes, control_failures = [], [], []
    counts = {}

    for v in variants:
        path = "/collect" if v["class"] in MUST_REFUSE else "/ingest"
        query = "authority=" + urllib.parse.quote_from_bytes(v["authority"], safe="") + "&path=" + urllib.parse.quote(path, safe="")
        try:
            r = get(args.base, args.host, "/probe?" + query, args.timeout)
        except Exception as exc:  # the harness could not reach the component at all
            print(f"harness error on {v['technique']}: {exc}", file=sys.stderr)
            return 2
        outcome = r["outcome"]
        passed = outcome in ("connected", "transport-error")
        counts[outcome] = counts.get(outcome, 0) + 1
        escaped = v["class"] in MUST_REFUSE and passed
        row = dict(r, **{"class": v["class"], "technique": v["technique"], "note": v["note"], "escaped": escaped})
        results.append(row)
        if escaped:
            escapes.append(row)
        if v["class"] == "control" and not (outcome == "connected" and r.get("http_status") == 200):
            control_failures.append(row)
        if args.verbose or escaped or (v["class"] in ("equivalent", "byport") and passed):
            answer = f"HTTP {r['http_status']}" if outcome == "connected" else (r.get("runtime_error") or "")
            flag = "ESCAPED" if escaped else outcome
            print(f"  {flag:16} {v['class']:10} {v['technique']:22} {v['authority']!r:62} {answer}")

    tried = len(variants)
    hostile = sum(1 for v in variants if v["class"] in MUST_REFUSE)
    line = f"{tried} variants tried, {len(escapes)} escaped"
    print(line)
    print(
        f"  must-refuse variants: {hostile}, refused: {hostile - len(escapes)}"
        f" | denied by policy: {counts.get('denied', 0)}"
        f" | rejected as malformed: {counts.get('rejected', 0)}"
        f" | connected: {counts.get('connected', 0)}"
        f" | passed policy then failed: {counts.get('transport-error', 0)}"
    )
    controls = [v for v in variants if v["class"] == "control"]
    print(f"  control: {len(controls) - len(control_failures)} of {len(controls)} connected with HTTP 200")

    # Cross-check against the component's own run of the corpus compiled into it.
    baked = get(args.base, args.host, "/fuzz", args.timeout)
    agree = baked.get("variants_tried") == tried and baked.get("escaped") == len(escapes)
    print(f"  component /fuzz reports: {baked.get('line')} ({'agrees' if agree else 'DISAGREES: rebuild the component from this corpus'})")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"line": line, "results": results}, fh, indent=2)

    if escapes or control_failures:
        print("FAIL", file=sys.stderr)
        return 1
    print("PASS: no attacker, confusable or SSRF variant got past the allow-list")
    return 0


if __name__ == "__main__":
    sys.exit(main())
