# Sandboxing MITRE ATT&CK techniques

Live demos that run a real, documented attack technique inside a deny-by-default
[Cosmonic](https://cosmonic.com) sandbox and show the sandbox containing it. Each demo is a
WebAssembly component workload whose security policy is mostly what its manifest does *not* grant:
no volume, no outbound hosts, no sockets, no process spawn.

> **You can't execute what you don't have.** A sandbox doesn't have to recognize the attack. It
> starts with nothing and hands the code only the capabilities you grant. See
> [principles of secure agent platforms](https://cosmonic.com/ai-sandbox/principles/).

These are defensive demonstrations: every scenario is an attack *attempt* and the contained result
is the deliverable. Targets are inert (RFC 5737 / RFC 1918 addresses, fake secrets, sample files).

## The demos

| Demo | What it shows | References | Desktop manifest |
|---|---|---|---|
| [demo-zip-rce-sandbox](demo-zip-rce-sandbox/) | A malicious `.zip` against the vulnerable `zip` crate: setuid bits, zip slip, cloaking | RUSTSEC-2026-0367, CVE-2026-115905 | [`zip-sandbox.workload.yaml`](demo-zip-rce-sandbox/deploy/zip-sandbox.workload.yaml) |
| [demo-webshell-rce-sandbox](demo-webshell-rce-sandbox/) | A classic `/exec` webshell: command execution, reverse shell, lateral movement | T1021 and related | [`webshell-sandbox.workload.yaml`](demo-webshell-rce-sandbox/deploy/webshell-sandbox.workload.yaml) |
| [demo-egress-exfil-sandbox](demo-egress-exfil-sandbox/) | A hijacked log shipper behind a one-host egress allow-list | T1041 | [`egress-exfil-logsink.workload.yaml`](demo-egress-exfil-sandbox/deploy/egress-exfil-logsink.workload.yaml), then [`egress-exfil-sandbox.workload.yaml`](demo-egress-exfil-sandbox/deploy/egress-exfil-sandbox.workload.yaml) |
| [demo-path-traversal-sandbox](demo-path-traversal-sandbox/) | An unpatched path-traversal config viewer confined to one read-only volume | T1552, CWE-22 | [`path-traversal-sandbox.workload.yaml`](demo-path-traversal-sandbox/deploy/path-traversal-sandbox.workload.yaml) |
| [demo-container-escape-sandbox](demo-container-escape-sandbox/) | A poisoned CI job probing for `docker.sock`, the kubelet and the Kubernetes API | T1609, T1610, T1611 | [`container-escape-sandbox.workload.yaml`](demo-container-escape-sandbox/deploy/container-escape-sandbox.workload.yaml) |
| [demo-resource-hijack-sandbox](demo-resource-hijack-sandbox/) | A stand-in miner: workers and pool removed, CPU and memory bounded | T1496 | [`resource-hijack-sandbox.workload.yaml`](demo-resource-hijack-sandbox/deploy/resource-hijack-sandbox.workload.yaml) |
| [demo-memory-boundary-sandbox](demo-memory-boundary-sandbox/) | **Scaffold only.** Three components with separate linear memories; the out-of-bounds scenario is not implemented (see its README) | T1055 | [`memory-boundary-sandbox.workload.yaml`](demo-memory-boundary-sandbox/deploy/memory-boundary-sandbox.workload.yaml) |

## Run one on Cosmonic Desktop

1. Install [Cosmonic Desktop](https://cosmonic.com/desktop/). It runs WebAssembly components as
   sandboxed workloads on macOS, Windows and Linux, and listens on `127.0.0.1:8200`.
2. Clone this repo and apply the demo's manifest from its `deploy/` folder. The easiest route is an
   AI assistant connected to Desktop's MCP server
   ([Connect coding agents](https://cosmonic.com/docs/desktop/coding-agents/)):

   > "Apply `demo-container-escape-sandbox/deploy/container-escape-sandbox.workload.yaml` to
   > Cosmonic Desktop, then show me its status."

3. Open `http://<workload-name>.localhost:8200/` (the manifest's `host:` line) and press the
   buttons.

There is nothing to build: every manifest pins public images under
`ghcr.io/cosmonic-labs/demo-*-sandbox/` by digest. The images are unsigned, so the manifests carry
the `desktop.cosmonic.com/unsafe-allow-unsigned` annotation; remove it and sign the images for a
Cosmonic Control or production deployment.

## Layout of each demo

```
demo-<name>-sandbox/
├── README.md       the scenarios, what was measured, and how to rebuild
├── cosmonic-app/   the component source
├── deploy/         the Cosmonic Desktop workload manifest(s)
├── native-demo/    the same technique run natively, for contrast (where present)
└── docs/           images
```

## License

[Apache-2.0](LICENSE)
