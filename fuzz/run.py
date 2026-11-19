#!/usr/bin/env python3
"""Egress allow-list evasion harness for demo-egress-exfil-sandbox.

Drives the DEPLOYED shipper component with every variant in corpus.txt and
asserts that only exact allow-list members connect. Standard library only.

    python3 fuzz/run.py                 # against Cosmonic Desktop on 127.0.0.1:8200
    python3 fuzz/run.py -v              # print every variant, not just the summary
    python3 fuzz/run.py --json out.json # also write every result as JSON
    python3 fuzz/run.py --base https://egress-exfil-sandbox.example.com --host egress-exfil-sandbox.example.com

The corpus names the allow-listed host with placeholders ({host}, {host:upper},
...). The harness asks the deployed shipper for its configured sink (/config,
i.e. LOG_SINK_URL) and fills them in itself, so the "allowed host" variants are
built from the host that deployment really allow-lists. --sink-url overrides it.

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


LOOKALIKES = (("i", "\u0456"), ("a", "\u0430"), ("e", "\u0435"), ("o", "\u043e"), ("c", "\u0441"), ("p", "\u0440"))


class Sink:
    """The configured sink, split the same way the component splits it."""

    def __init__(self, url):
        self.https = url.startswith("https://")
        rest = url.split("://", 1)[1] if "://" in url else url
        authority = rest.split("/", 1)[0]
        host, sep, port = authority.rpartition(":")
        if sep and host and port.isascii() and port.isdigit():
            self.host, self.explicit_port = host, port
        else:
            self.host, self.explicit_port = authority, None

    @property
    def authority(self):
        return f"{self.host}:{self.explicit_port}" if self.explicit_port else self.host

    def homoglyph(self, label):
        for latin, cyrillic in LOOKALIKES:
            before, sep, after = label.rpartition(latin)
            if sep:
                return before + cyrillic + after
        return None

    def token(self, token):
        host = self.host
        if not host:
            return None
        label, dot, parent = host.partition(".")
        parent = parent if dot else None
        rejoin = lambda l: f"{l}.{parent}" if parent is not None else l
        first, tail = host[0], host[1:]
        if token == "host":
            return host
        if token == ":port":
            return f":{self.explicit_port}" if self.explicit_port else ""
        if token == "port":
            return self.explicit_port or ("443" if self.https else "80")
        if token == "host:upper":
            return host.upper()
        if token == "host:mixed":
            out, start = [], True
            for c in host:
                out.append(c.upper() if start else c)
                start = c in "-."
            return "".join(out)
        if token == "host:fullwidth":
            return chr(ord(first) + 0xFEE0) + tail if first.isascii() and first.isalnum() else None
        if token == "host:ideodot":
            return host.replace(".", "\u3002", 1) if parent is not None else None
        if token == "host:percent":
            return f"%{ord(first):02x}{tail}" if first.isascii() else None
        if token == "host:label":
            return label if parent is not None else None
        if token == "host:parent":
            return parent
        if token == "host:truncated":
            return rejoin(label[:-1]) if len(label) > 1 else None
        if token == "host:homoglyph":
            swapped = self.homoglyph(label)
            return rejoin(swapped) if swapped else None
        if token == "host:homoglyph-puny":
            swapped = self.homoglyph(label)
            return rejoin("xn--" + swapped.encode("punycode").decode("ascii")) if swapped else None
        return None

    def expand(self, field):
        out, rest = [], field
        while "{" in rest:
            before, _, after = rest.partition("{")
            out.append(before)
            if "}" not in after:
                return None
            token, _, rest = after.partition("}")
            value = self.token(token)
            if value is None:
                return None
            out.append(value)
        out.append(rest)
        return "".join(out)


def load(path, sink):
    """Read the corpus and fill in its placeholders. Returns (variants, skipped)."""
    variants = []
    skipped = 0
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split(None, 3)
            if len(parts) < 3:
                continue
            expanded = sink.expand(parts[1])
            if expanded is None:
                skipped += 1
                continue
            # A hostile variant that came out as the allow-listed host itself
            # is not a variant for this host.
            if parts[0] in MUST_REFUSE and expanded.lower() in (sink.authority.lower(), sink.host.lower()):
                skipped += 1
                continue
            variants.append(
                {
                    "class": parts[0],
                    "authority": unescape(expanded),
                    "technique": parts[2],
                    "note": parts[3].strip() if len(parts) > 3 else "",
                }
            )
    return variants, skipped


def get(base, host, path_and_query, timeout):
    req = urllib.request.Request(base + path_and_query, headers={"Host": host})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:8200", help="ingress base URL (default: Cosmonic Desktop)")
    ap.add_argument("--host", default="egress-exfil-sandbox.localhost", help="the shipper's ingress host")
    ap.add_argument("--corpus", default=os.path.join(HERE, "corpus.txt"))
    ap.add_argument("--sink-url", help="the shipper's LOG_SINK_URL (default: ask the shipper's /config)")
    ap.add_argument("--json", help="write every result to this file")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    sink_url = args.sink_url or get(args.base, args.host, "/config", args.timeout)["sink_url"]
    sink = Sink(sink_url)
    print(f"allowed host: {sink.host} (sink {sink_url})")
    variants, skipped = load(args.corpus, sink)
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
    if skipped:
        print(f"  skipped (placeholder not buildable for this host): {skipped}")
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
