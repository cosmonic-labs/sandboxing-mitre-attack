//! The resource-hijack probes (MITRE ATT&CK T1496, CWE-400).
//!
//! Every probe here REALLY makes its attempt and reports the runtime's own
//! answer. Nothing is simulated and no verdict is hard-coded: the summary
//! strings are computed from what came back.
//!
//! The "miner" is a stand-in. It is an iterated SHA-256 loop over a counter:
//! CPU-bound work with no mining protocol, no pool client, no wallet and no
//! difficulty target. The "pool" is `203.0.113.66` (TEST-NET-3, RFC 5737,
//! never routed) and `pool.attacker.example` (RFC 2606, never resolvable).
//!
//! SAFETY BUDGET. This runs on a real machine, so every probe carries its own
//! cap *inside the component*, independent of anything the platform enforces:
//!
//!   * CPU:    at most [`CPU_BUDGET_MS`] of wall-clock hashing per request.
//!   * Memory: growth stops at [`MEMORY_CEILING_MB`] if the runtime has not
//!             refused earlier.
//!
//! When a probe's JSON says `stopped_by: "in-component cap"`, that is the bound
//! that actually fired. If a platform limit fires first you see it instead: a
//! refused `memory.grow`, or (for CPU) no JSON at all, because the host ended
//! the invocation.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

/// Hard cap on CPU-bound hashing per request, in milliseconds of wall clock.
pub const CPU_BUDGET_MS: u64 = 3_000;
/// Hard cap on linear-memory growth, in MiB. Kept small on purpose: the demo
/// also runs on a shared host, where one component's memory is everyone's.
pub const MEMORY_CEILING_MB: usize = 64;
/// One WebAssembly page.
const PAGE: usize = 65_536;
const PAGES_PER_MB: usize = 16;

/// The never-routed "pool" address (TEST-NET-3, RFC 5737).
pub const POOL_IP: &str = "203.0.113.66:3333";
/// The never-resolvable "pool" name (RFC 2606 reserved TLD).
pub const POOL_NAME: &str = "pool.attacker.example:3333";

// ---- background-work bookkeeping (lives in this instance's linear memory) ----
pub static BG_RUN_ID: AtomicU64 = AtomicU64::new(0);
pub static BG_STATE: AtomicU32 = AtomicU32::new(0); // 0 none, 1 running, 2 finished
pub static BG_SLICES: AtomicU32 = AtomicU32::new(0);
pub static BG_HASHES: AtomicU64 = AtomicU64::new(0);
pub static BG_WORK_MS: AtomicU64 = AtomicU64::new(0);

// =============================================================================
// 1. CPU
// =============================================================================

/// The stand-in miner: `digest = SHA-256(digest || counter)` until the
/// wall-clock budget runs out. Returns (hashes, elapsed_ms, digest prefix).
pub fn hash_for(budget_ms: u64) -> (u64, u64, String) {
    let start = Instant::now();
    let mut digest = [0u8; 32];
    let mut counter: u64 = 0;
    loop {
        // Check the clock every 1024 hashes, not every hash.
        for _ in 0..1024 {
            let mut h = Sha256::new();
            h.update(digest);
            h.update(counter.to_le_bytes());
            digest.copy_from_slice(&h.finalize());
            counter += 1;
        }
        if start.elapsed().as_millis() as u64 >= budget_ms {
            break;
        }
    }
    let elapsed = start.elapsed().as_millis() as u64;
    let prefix: String = digest[..6].iter().map(|b| format!("{b:02x}")).collect();
    (counter, elapsed, prefix)
}

pub fn cpu(requested_ms: Option<u64>) -> Value {
    let budget = requested_ms.unwrap_or(CPU_BUDGET_MS).clamp(100, CPU_BUDGET_MS);
    let (hashes, elapsed_ms, digest) = hash_for(budget);
    let rate = if elapsed_ms > 0 { hashes * 1000 / elapsed_ms } else { 0 };
    json!({
        "class": "bounded",
        "attempt": "run a CPU-bound hashing loop for as long as the sandbox allows",
        "ran": true,
        "hashes": hashes,
        "elapsed_ms": elapsed_ms,
        "hashes_per_sec": rate,
        "last_digest_prefix": digest,
        "in_component_cap_ms": budget,
        "stopped_by": "in-component cap",
        "stopped_by_detail": format!(
            "the loop ran its full {budget} ms and stopped itself; no platform limit interrupted it within that window"
        ),
    })
}

// =============================================================================
// 2. Spawn workers: threads and processes
// =============================================================================

/// The error a spawn attempt returned. On `wasm32-wasip2` this comes from the
/// Rust standard library itself: the target has no thread or process interface
/// to call, so the attempt fails before it reaches the host. The component's
/// import list (no such interface) is the underlying fact.
fn io_err(e: &std::io::Error) -> Value {
    json!({ "kind": format!("{:?}", e.kind()), "error": e.to_string() })
}

/// Try to start `n` worker threads. Uses `thread::Builder::spawn`, which is
/// what `std::thread::spawn` calls; `thread::spawn` itself panics on the same
/// error, and a panic in a component is a trap.
pub fn threads(n: usize) -> Value {
    let mut spawned = 0usize;
    let mut errors: Vec<Value> = Vec::new();
    for i in 0..n {
        match std::thread::Builder::new()
            .name(format!("miner-worker-{i}"))
            .spawn(|| hash_for(50).0)
        {
            Ok(handle) => {
                spawned += 1;
                let _ = handle.join();
            }
            Err(e) => errors.push(io_err(&e)),
        }
    }
    let parallelism = match std::thread::available_parallelism() {
        Ok(n) => json!({ "ok": n.get() }),
        Err(e) => json!({ "err": io_err(&e) }),
    };
    let first = errors.first().cloned();
    json!({
        "class": "removed",
        "attempt": format!("start {n} worker threads with std::thread::Builder::spawn"),
        "attempted": n,
        "spawned": spawned,
        "error": first,
        "available_parallelism": parallelism,
    })
}

/// Try to start a worker *process*. There is no fork/exec in WASI.
pub fn processes() -> Value {
    let attempts: [(&str, &[&str]); 3] = [
        ("/bin/sh", &["-c", "nproc"]),
        ("./miner-worker", &["--threads", "8"]),
        ("nohup", &["./miner-worker", "&"]),
    ];
    let mut out: Vec<Value> = Vec::new();
    let mut spawned = 0usize;
    for (bin, args) in attempts {
        let line = format!("{bin} {}", args.join(" "));
        match std::process::Command::new(bin).args(args).spawn() {
            Ok(mut child) => {
                spawned += 1;
                let _ = child.kill();
                out.push(json!({ "command": line, "spawned": true }));
            }
            Err(e) => out.push(json!({ "command": line, "spawned": false, "error": io_err(&e) })),
        }
    }
    json!({
        "class": "removed",
        "attempt": "start worker processes with std::process::Command::spawn",
        "attempted": out.len(),
        "spawned": spawned,
        "attempts": out,
    })
}

// =============================================================================
// 3. Memory growth
// =============================================================================

pub fn memory_pages() -> usize {
    #[cfg(target_arch = "wasm32")]
    {
        core::arch::wasm32::memory_size::<0>()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0
    }
}

pub fn memory_mb() -> f64 {
    memory_pages() as f64 / PAGES_PER_MB as f64
}

/// `memory.grow` by `pages`. Returns the previous size in pages, or `None` if
/// the runtime refused (the instruction returned -1).
fn grow(pages: usize) -> Option<usize> {
    #[cfg(target_arch = "wasm32")]
    {
        let prev = core::arch::wasm32::memory_grow::<0>(pages);
        if prev == usize::MAX {
            None
        } else {
            Some(prev)
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = pages;
        None
    }
}

/// Write one byte into every page of a region we just grew, so the growth is
/// memory the component really uses and not just an address range.
fn touch(first_page: usize, pages: usize) {
    for p in first_page..first_page + pages {
        let addr = (p * PAGE) as *mut u8;
        // SAFETY: the page range was just returned by a successful
        // `memory.grow` in this instance, so it is in bounds, and nothing else
        // owns it (the allocator only uses memory it grew itself).
        unsafe { addr.write_volatile(0xA5) };
    }
}

/// Grow linear memory with raw `memory.grow`, `step_pages` at a time, until the
/// runtime refuses or the in-component ceiling is reached.
pub fn memory_grow_steps(step_pages: usize) -> Value {
    let start_pages = memory_pages();
    let ceiling_pages = MEMORY_CEILING_MB * PAGES_PER_MB;
    let mut grows = 0usize;
    let mut refused_at: Option<(usize, usize)> = None; // (pages held, pages asked)
    while memory_pages() < ceiling_pages {
        let ask = step_pages.min(ceiling_pages - memory_pages());
        match grow(ask) {
            Some(prev) => {
                touch(prev, ask);
                grows += 1;
            }
            None => {
                refused_at = Some((memory_pages(), ask));
                break;
            }
        }
    }
    memory_report("memory.grow", step_pages, start_pages, grows, refused_at)
}

fn memory_report(
    how: &str,
    step_pages: usize,
    start_pages: usize,
    grows: usize,
    refused_at: Option<(usize, usize)>,
) -> Value {
    let end_pages = memory_pages();
    let reached_mb = end_pages as f64 / PAGES_PER_MB as f64;
    let (stopped_by, detail) = match refused_at {
        Some((held, ask)) => (
            "platform",
            format!(
                "the runtime refused {how} at {:.1} MiB (asked for {:.2} MiB more; the grow returned -1)",
                held as f64 / PAGES_PER_MB as f64,
                ask as f64 / PAGES_PER_MB as f64
            ),
        ),
        None => (
            "in-component cap",
            format!(
                "growth reached the {MEMORY_CEILING_MB} MiB ceiling built into the component; the runtime had not refused"
            ),
        ),
    };
    json!({
        "class": "bounded",
        "attempt": format!(
            "grow linear memory with {how} in {:.2} MiB steps until refused",
            step_pages as f64 / PAGES_PER_MB as f64
        ),
        "start_mb": start_pages as f64 / PAGES_PER_MB as f64,
        "reached_mb": reached_mb,
        "successful_grows": grows,
        "in_component_ceiling_mb": MEMORY_CEILING_MB,
        "stopped_by": stopped_by,
        "stopped_by_detail": detail,
    })
}

/// Grow through the Rust allocator instead of raw `memory.grow`: keep
/// allocating `chunk` bytes with `try_reserve_exact` (which reports failure
/// instead of aborting) and touching them.
pub fn memory_alloc_chunks(chunk: usize) -> Value {
    let start_pages = memory_pages();
    let ceiling_bytes = MEMORY_CEILING_MB * 1024 * 1024;
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut held_bytes = 0usize;
    let mut refused: Option<String> = None;
    // Leave headroom so the bookkeeping itself stays under the ceiling.
    while memory_pages() * PAGE + chunk <= ceiling_bytes {
        let mut v: Vec<u8> = Vec::new();
        match v.try_reserve_exact(chunk) {
            Ok(()) => {
                v.resize(chunk, 0xA5);
                held_bytes += chunk;
                held.push(v);
            }
            Err(e) => {
                refused = Some(e.to_string());
                break;
            }
        }
    }
    let end_pages = memory_pages();
    let allocations = held.len();
    drop(held);
    let (stopped_by, detail) = match &refused {
        Some(e) => (
            "platform",
            format!(
                "the allocator could not get more memory from the runtime at {:.1} MiB: {e}",
                end_pages as f64 / PAGES_PER_MB as f64
            ),
        ),
        None => (
            "in-component cap",
            format!("allocation reached the {MEMORY_CEILING_MB} MiB ceiling built into the component; the runtime had not refused"),
        ),
    };
    json!({
        "class": "bounded",
        "attempt": format!("allocate {chunk}-byte Vec<u8> chunks with try_reserve_exact until refused"),
        "start_mb": start_pages as f64 / PAGES_PER_MB as f64,
        "reached_mb": end_pages as f64 / PAGES_PER_MB as f64,
        "allocations": allocations,
        "allocated_bytes": held_bytes,
        "allocator_error": refused,
        "in_component_ceiling_mb": MEMORY_CEILING_MB,
        "stopped_by": stopped_by,
        "stopped_by_detail": detail,
    })
}

// =============================================================================
// 4. Dial a pool
// =============================================================================

async fn dial(authority: &str) -> Value {
    use wasip3::http::types::{ErrorCode, Fields, Method, Request, RequestOptions, Scheme};

    let headers = match Fields::from_list(&[]) {
        Ok(h) => h,
        Err(e) => return json!({ "target": authority, "connected": false, "stage": "headers", "runtime_error": format!("{e:?}") }),
    };
    // Bound the attempt even if egress were ever allowed: the address is not
    // routed, so without a timeout an allowed request would just hang.
    let options = RequestOptions::new();
    let _ = options.set_connect_timeout(Some(2_000_000_000));
    let _ = options.set_first_byte_timeout(Some(2_000_000_000));

    let (_tx, trailers_rx) = wasip3::wit_future::new(|| Ok(None));
    let (request, _sent) = Request::new(headers, None, trailers_rx, Some(options));
    let _ = request.set_method(&Method::Get);
    let _ = request.set_scheme(Some(&Scheme::Http));
    if request.set_authority(Some(authority)).is_err() {
        return json!({ "target": authority, "connected": false, "stage": "set-authority",
            "runtime_error": "the runtime refused this string as a request authority" });
    }
    let _ = request.set_path_with_query(Some("/"));

    match wasip3::http::client::send(request).await {
        Ok(response) => json!({
            "target": authority,
            "connected": true,
            "status": response.get_status_code(),
        }),
        Err(code) => {
            let denied = matches!(
                code,
                ErrorCode::HttpRequestDenied | ErrorCode::DestinationIpProhibited
            );
            json!({
                "target": authority,
                "connected": false,
                "denied_by_policy": denied,
                "runtime_error": format!("{code:?}"),
            })
        }
    }
}

/// One outbound request to each "pool" address. `allowedHosts: []` denies both.
pub async fn pool() -> Value {
    let attempts = vec![dial(POOL_IP).await, dial(POOL_NAME).await];
    let connected = attempts.iter().filter(|a| a["connected"] == true).count();
    json!({
        "class": "removed",
        "attempt": "open an outbound HTTP connection to a mining pool",
        "attempted": attempts.len(),
        "connected": connected,
        "attempts": attempts,
        "note": "203.0.113.66 is TEST-NET-3 (RFC 5737) and .example is reserved (RFC 2606): neither is a real pool",
    })
}

// =============================================================================
// 5. Persistence past the request
// =============================================================================

/// Hard cap on the no-CPU heartbeat variant, in seconds.
pub const HEARTBEAT_CAP_SECS: u64 = 120;
const HEARTBEAT_EVERY_SECS: u64 = 5;

/// A component cannot write anywhere an observer can see: no disk, no egress.
/// The one trace it CAN leave is a refused pool dial, which the host logs with
/// a timestamp. So each step of background work ends with a dial to
/// `<step>.run-<id>.pool.attacker.example`; the host's own "outgoing request
/// denied" log lines are the heartbeat that shows how long the work lived.
async fn beat(kind: &str, step: u32, run_id: u64) {
    let _ = dial(&format!("{kind}-{step:02}.run-{run_id}.pool.attacker.example")).await;
}

/// Work that keeps going after the response has been returned. Hashes in
/// 250 ms slices, yielding to the host between slices. Self-capped at
/// [`CPU_BUDGET_MS`] of work.
pub async fn background_work(run_id: u64) {
    const SLICE_MS: u64 = 250;
    BG_RUN_ID.store(run_id, Ordering::Relaxed);
    BG_STATE.store(1, Ordering::Relaxed);
    BG_SLICES.store(0, Ordering::Relaxed);
    BG_HASHES.store(0, Ordering::Relaxed);
    BG_WORK_MS.store(0, Ordering::Relaxed);
    let mut worked = 0u64;
    let mut slice = 0u32;
    while worked < CPU_BUDGET_MS {
        // Yield to the host. If the host reaps the instance once the response
        // is complete, this is where the work ends.
        wasip3::clocks::monotonic_clock::wait_for(5_000_000).await;
        let (hashes, ms, _) = hash_for(SLICE_MS);
        worked += ms;
        slice += 1;
        BG_SLICES.store(slice, Ordering::Relaxed);
        BG_HASHES.fetch_add(hashes, Ordering::Relaxed);
        BG_WORK_MS.store(worked, Ordering::Relaxed);
        beat("slice", slice, run_id).await;
    }
    BG_STATE.store(2, Ordering::Relaxed);
}

/// The no-CPU variant: after the response, only sleep and leave a heartbeat
/// every 5 s, for up to `secs` (<= [`HEARTBEAT_CAP_SECS`]). It measures how
/// long a task outlives its request without burning anything.
pub async fn background_heartbeat(run_id: u64, secs: u64) {
    BG_RUN_ID.store(run_id, Ordering::Relaxed);
    BG_STATE.store(1, Ordering::Relaxed);
    BG_SLICES.store(0, Ordering::Relaxed);
    BG_HASHES.store(0, Ordering::Relaxed);
    BG_WORK_MS.store(0, Ordering::Relaxed);
    let start = Instant::now();
    let mut n = 0u32;
    while start.elapsed().as_secs() < secs.min(HEARTBEAT_CAP_SECS) {
        wasip3::clocks::monotonic_clock::wait_for(HEARTBEAT_EVERY_SECS * 1_000_000_000).await;
        n += 1;
        BG_SLICES.store(n, Ordering::Relaxed);
        BG_WORK_MS.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
        beat("beat", n, run_id).await;
    }
    BG_STATE.store(2, Ordering::Relaxed);
}

pub fn background_state() -> Value {
    let state = match BG_STATE.load(Ordering::Relaxed) {
        0 => "none in this instance",
        1 => "running",
        _ => "finished (reached its in-component cap)",
    };
    json!({
        "state": state,
        "run_id": BG_RUN_ID.load(Ordering::Relaxed),
        "steps_done": BG_SLICES.load(Ordering::Relaxed),
        "hashes": BG_HASHES.load(Ordering::Relaxed),
        "alive_ms": BG_WORK_MS.load(Ordering::Relaxed),
    })
}

// =============================================================================
// Evasion probe: one variant per request
// =============================================================================

/// The evasion variants, in the order the probe script runs them.
pub const VARIANTS: &[(&str, &str, &str)] = &[
    ("thread-builder", "threads", "std::thread::Builder::new().spawn"),
    ("thread-stack-size", "threads", "Builder::stack_size(64 KiB).spawn (a smaller stack request)"),
    ("thread-scoped", "threads", "std::thread::scope + Builder::spawn_scoped"),
    ("thread-burst", "threads", "64 Builder::spawn attempts in a row"),
    ("process-spawn", "processes", "Command::new(\"/bin/sh\").spawn"),
    ("process-output", "processes", "Command::new(\"/bin/sh\").output"),
    ("process-status", "processes", "Command::new(\"./miner-worker\").status"),
    ("memory-grow-1-page", "memory", "memory.grow one 64 KiB page at a time"),
    ("memory-grow-16mb", "memory", "memory.grow 16 MiB at a time"),
    ("memory-grow-one-jump", "memory", "one memory.grow straight to the ceiling"),
    ("memory-vec-64k", "memory", "many 64 KiB Vec allocations"),
    ("memory-vec-1mb", "memory", "many 1 MiB Vec allocations"),
    ("memory-vec-one-large", "memory", "one Vec allocation sized to the ceiling"),
];

pub fn variant_list() -> Value {
    let v: Vec<Value> = VARIANTS
        .iter()
        .map(|(name, group, what)| json!({ "variant": name, "group": group, "what": what }))
        .collect();
    json!({
        "variants": v,
        "budget": {
            "worker_threads": 0,
            "worker_processes": 0,
            "memory_ceiling_mb": MEMORY_CEILING_MB,
        },
    })
}

fn worker_result(spawned: usize, attempted: usize, err: Option<Value>) -> Value {
    json!({
        "attempted": attempted,
        "workers_created": spawned,
        "exceeded_budget": spawned > 0,
        "error": err,
    })
}

pub fn variant(name: &str) -> Option<Value> {
    let (_, group, what) = VARIANTS.iter().find(|(n, _, _)| *n == name)?;
    let result = match name {
        "thread-builder" => match std::thread::Builder::new().spawn(|| ()) {
            Ok(h) => {
                let _ = h.join();
                worker_result(1, 1, None)
            }
            Err(e) => worker_result(0, 1, Some(io_err(&e))),
        },
        "thread-stack-size" => match std::thread::Builder::new().stack_size(64 * 1024).spawn(|| ()) {
            Ok(h) => {
                let _ = h.join();
                worker_result(1, 1, None)
            }
            Err(e) => worker_result(0, 1, Some(io_err(&e))),
        },
        "thread-scoped" => std::thread::scope(|s| {
            match std::thread::Builder::new().spawn_scoped(s, || ()) {
                Ok(_) => worker_result(1, 1, None),
                Err(e) => worker_result(0, 1, Some(io_err(&e))),
            }
        }),
        "thread-burst" => {
            let mut ok = 0usize;
            let mut first: Option<Value> = None;
            for _ in 0..64 {
                match std::thread::Builder::new().spawn(|| ()) {
                    Ok(h) => {
                        ok += 1;
                        let _ = h.join();
                    }
                    Err(e) => {
                        first.get_or_insert_with(|| io_err(&e));
                    }
                }
            }
            worker_result(ok, 64, first)
        }
        "process-spawn" => match std::process::Command::new("/bin/sh").arg("-c").arg("nproc").spawn() {
            Ok(mut c) => {
                let _ = c.kill();
                worker_result(1, 1, None)
            }
            Err(e) => worker_result(0, 1, Some(io_err(&e))),
        },
        "process-output" => match std::process::Command::new("/bin/sh").arg("-c").arg("nproc").output() {
            Ok(_) => worker_result(1, 1, None),
            Err(e) => worker_result(0, 1, Some(io_err(&e))),
        },
        "process-status" => match std::process::Command::new("./miner-worker").status() {
            Ok(_) => worker_result(1, 1, None),
            Err(e) => worker_result(0, 1, Some(io_err(&e))),
        },
        "memory-grow-1-page" => memory_variant(memory_grow_steps(1)),
        "memory-grow-16mb" => memory_variant(memory_grow_steps(16 * PAGES_PER_MB)),
        "memory-grow-one-jump" => memory_variant(memory_grow_steps(MEMORY_CEILING_MB * PAGES_PER_MB)),
        "memory-vec-64k" => memory_variant(memory_alloc_chunks(64 * 1024)),
        "memory-vec-1mb" => memory_variant(memory_alloc_chunks(1024 * 1024)),
        "memory-vec-one-large" => {
            let headroom = memory_pages() * PAGE + 2 * PAGE;
            let chunk = (MEMORY_CEILING_MB * 1024 * 1024).saturating_sub(headroom);
            memory_variant(memory_alloc_chunks(chunk))
        }
        _ => return None,
    };
    Some(json!({ "variant": name, "group": group, "what": what, "result": result }))
}

/// A memory variant exceeds the budget only if the instance ends up holding
/// more than the in-component ceiling.
fn memory_variant(mut report: Value) -> Value {
    let reached = report["reached_mb"].as_f64().unwrap_or(0.0);
    report["exceeded_budget"] = json!(reached > MEMORY_CEILING_MB as f64);
    report
}
