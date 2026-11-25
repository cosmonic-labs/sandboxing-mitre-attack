# Native baseline: the socket is reachable

`probe.sh` shows the well-known misconfiguration as what it is: **reachability**. It runs a stock
`curl` container twice and, from inside each, asks the Docker API two read-only questions over the
Unix socket, `GET /_ping` and `GET /version`.

1. With `-v /var/run/docker.sock:/var/run/docker.sock`: the daemon answers.
2. Without the mount: there is nothing to connect to.

```bash
./probe.sh
```

Output from Docker Desktop 4.78.0 on macOS (engine 29.5.3), with `/version` shortened:

```
== 1. container WITH the Docker socket mounted (the misconfiguration)
GET /_ping -> OK  (curl exit 0)
GET /version -> {"Platform":{"Name":"Docker Desktop 4.78.0 (229452)"},"Version":"29.5.3","ApiVersion":"1.54","MinAPIVersion":"1.40","Os":"linux","Arch":"arm64", …}
  (curl exit 0)

== 2. container WITHOUT the mount
GET /_ping -> curl: (7) Failed to connect to localhost port 80 after 0 ms: Could not connect to server
  (curl exit 7)
GET /version -> curl: (7) Failed to connect to localhost port 80 after 0 ms: Could not connect to server
  (curl exit 7)
```

## Why that is enough

The Docker daemon runs as root on the host and does what its API is asked. It does not know or
care that the request came from inside a container. A process that gets an answer to `/_ping` on
that socket can send the daemon any other request too, and the daemon's API includes starting
containers with whatever access to the host the caller asks for. So the question "can this
container escape?" reduces to "can this container reach the socket?", and the first block above
answers it.

This script deliberately goes no further. It sends two `GET`s and exits. It does not start,
create, inspect or change any container other than its own two `--rm` probe containers, and
nothing here should be extended to do so: the demo's point is the contrast in reachability, which
is already complete.

## The contrast

| Where the job runs | `docker.sock` | Result |
|---|---|---|
| Container, socket mounted | reachable | the daemon answers: the container boundary is gone |
| Container, no mount | not reachable | `curl: (7)`; the boundary holds because of how it was configured |
| Cosmonic sandbox (the component) | cannot be expressed | no filesystem to hold the path, no `wasi:sockets` to connect with, no process to run a client, no outbound host |

The middle row is a configuration that one flag undoes. In the last row there is no flag: the
workload manifest has no field that hands a component a host socket.

## Notes

- Needs Docker. Pulls `curlimages/curl:8.11.1` (override with `IMAGE=`).
- `--user 0`: that image defaults to an unprivileged user, and the socket is `root:root 0660`.
  Most images, and most CI job containers, run as root by default, which is the case being shown.
- On Docker Desktop the path `/var/run/docker.sock` is resolved inside Desktop's Linux VM, so the
  mount works even though the Mac's own socket lives elsewhere.
