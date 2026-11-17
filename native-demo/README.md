# native-demo: the same loop, with no sandbox

A small Rust CLI that runs the demo's stand-in "miner" directly on your machine (macOS or Linux),
so you can see what the sandbox takes away. It is the same loop as the component: iterated SHA-256
over a counter. No mining protocol, no wallet, no real pool.

> **Self-limited.** It runs for 2 seconds by default (5 at most), on at most 8 threads, and then
> exits on its own. The "pool" it dials is `203.0.113.66`, in TEST-NET-3 (RFC 5737), which is never
> routed; the dial has a 1 second timeout.

## Run it

You need a Rust toolchain (`cargo`).

```bash
cd native-demo
cargo run --release                         # every core up to 8, for 2 s
cargo run --release -- --threads 4 --secs 3
```

Captured on the machine the sandbox numbers come from (10 hardware threads):

```
resource-hijack native baseline (no sandbox)
  the OS reports 10 hardware threads; using 8 for 2 s, then exiting

 STEP 1  one thread, 500 ms
    2621440 hashes  (5242880 hashes/s)

 STEP 2  start 8 worker threads (std::thread::Builder::spawn)
    8 of 8 threads started
    69316608 hashes in 2.00 s  (34647169 hashes/s)
    6.6x the single-thread rate: the loop spread across 8 cores

 STEP 3  start a child process (std::process::Command)
    spawned: child pid 20787 running as <you>

 STEP 4  dial the pool at 203.0.113.66:3333 (TEST-NET-3, never routed), 1 s timeout
    connection timed out
    nothing refused the attempt: the OS sent the connection request and nobody answered

 UNCONTAINED: 8 worker threads, 1 child process, and an outbound dial the OS allowed.
 The only limit on this run was the 2 s this program gave itself.
```

## Against the sandbox

| | Native | In the Cosmonic sandbox |
|---|---|---|
| Worker threads | 8 of 8 started | 0 of 8: `operation not supported on this platform` |
| Hash rate | 34.6 million/s on 8 cores | about 4.6 million/s on one core |
| Child process | spawned | 0 of 3: `operation not supported on this platform` |
| Pool dial | sent; timed out because nobody is there | `ErrorCode::HttpRequestDenied` before it left |
| What ended the run | the program's own 2 s | the component's own 3 s cap; with `maxInvocations: 1`, the instance is then dropped |

The last row is the honest part: in both columns the loop stopped because the code chose to stop.
What the sandbox changed is everything around it.
