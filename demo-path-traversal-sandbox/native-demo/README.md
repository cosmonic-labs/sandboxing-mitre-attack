# native-demo: watch the traversal work, with no sandbox

A small Rust CLI (no dependencies) that runs the config viewer's path join as an ordinary
process, so you can see the bug succeed before you watch the sandbox contain it.

- **The bug:** [CWE-22](https://cwe.mitre.org/data/definitions/22.html), path traversal. The
  viewer joins a user-supplied name onto its config directory with no canonicalization. The line
  is marked `// VULN:` and is the same join as
  [`cosmonic-app/viewer/src/viewer.rs`](../cosmonic-app/viewer/src/viewer.rs).

> **It touches nothing real.** The CLI builds a throwaway tree under the system temp directory:
> a `config/` folder, and beside it a fake "private key" holding inert text. It reads that fake
> key back through the bug, then deletes the tree. It never opens `~/.ssh`, `/etc`, or any other
> real file, and for the environment it prints counts only, never names or values.

## Run it

You need a Rust toolchain (`cargo`).

```bash
cd native-demo
cargo run
```

```
[legitimate]
  requested: app.conf
  result:    served (31 bytes): [server]

[dot-dot traversal]
  requested: ../../root/.ssh/id_rsa
  opened:    <tmp>/path-traversal-native-demo-<pid>/var/app/config/../../root/.ssh/id_rsa
  result:    LEAKED the fake key (118 bytes): FAKE-PRIVATE-KEY (inert demo text, not a credential)

[absolute path]
  requested: <tmp>/path-traversal-native-demo-<pid>/var/root/.ssh/id_rsa
  result:    LEAKED the fake key (118 bytes): FAKE-PRIVATE-KEY (inert demo text, not a credential)

[symlink inside the config dir]
  requested: latest
  result:    LEAKED the fake key (118 bytes): FAKE-PRIVATE-KEY (inert demo text, not a credential)

VULNERABLE: 4 of 4 requests read the fake key from outside the config directory.
Same viewer code as the sandboxed component; the only difference is what it was handed.
```

(Output abridged.) It also reports how many environment variables the process inherited and how
many have credential-looking names. In the sandbox that number is zero because the list is empty.

## The contrast

| | Native process | Sandboxed component |
|---|---|---|
| `../../root/.ssh/id_rsa` | read | `Operation not permitted (os error 63)` |
| absolute path | read (`join` discards the base) | `No such file or directory (os error 44)` |
| symlink out of the config dir | followed | `Operation not permitted (os error 63)` |
| environment | everything the parent had | empty |

Now run the same join inside the sandbox: [`../README.md`](../README.md).
