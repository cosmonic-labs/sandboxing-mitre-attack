//! Native baseline for the resource-hijack sandbox demo (MITRE ATT&CK T1496).
//!
//! The same stand-in "miner" as the component (iterated SHA-256 over a
//! counter; no mining protocol, no wallet, no real pool), run directly on the
//! operating system with no sandbox. It shows the three things the sandbox
//! takes away:
//!
//!   1. it starts N worker threads and uses N cores,
//!   2. it starts a child process,
//!   3. the OS lets it try to reach the pool address.
//!
//! SELF-LIMITED. It runs for 2 seconds by default (5 at most) on at most 8
//! threads, then exits on its own. Usage:
//!
//!   cargo run --release                       # all cores (max 8), 2 s
//!   cargo run --release -- --threads 4 --secs 3

use sha2::{Digest, Sha256};
use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

const MAX_THREADS: usize = 8;
const MAX_SECS: u64 = 5;
/// TEST-NET-3 (RFC 5737): reserved for documentation, never routed.
const POOL: &str = "203.0.113.66:3333";

/// The same loop as `cosmonic-app/miner/src/probes.rs::hash_for`.
fn hash_for(budget: Duration) -> u64 {
    let start = Instant::now();
    let mut digest = [0u8; 32];
    let mut counter: u64 = 0;
    loop {
        for _ in 0..1024 {
            let mut h = Sha256::new();
            h.update(digest);
            h.update(counter.to_le_bytes());
            digest.copy_from_slice(&h.finalize());
            counter += 1;
        }
        if start.elapsed() >= budget {
            return counter;
        }
    }
}

fn arg(name: &str) -> Option<u64> {
    let args: Vec<String> = std::env::args().collect();
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1)?.parse().ok()
}

fn main() {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let threads = (arg("--threads").map(|n| n as usize).unwrap_or(cores)).clamp(1, MAX_THREADS);
    let secs = arg("--secs").unwrap_or(2).clamp(1, MAX_SECS);
    let budget = Duration::from_secs(secs);

    println!("resource-hijack native baseline (no sandbox)");
    println!("  the OS reports {cores} hardware threads; using {threads} for {secs} s, then exiting\n");

    // --- one thread, for the comparison with the component -----------------
    let one = hash_for(Duration::from_millis(500));
    println!(" STEP 1  one thread, 500 ms");
    println!("    {one} hashes  ({} hashes/s)\n", one * 2);

    // --- 1. worker threads ---------------------------------------------------
    println!(" STEP 2  start {threads} worker threads (std::thread::Builder::spawn)");
    let start = Instant::now();
    let mut handles = Vec::new();
    let mut spawned = 0;
    for i in 0..threads {
        match std::thread::Builder::new()
            .name(format!("miner-worker-{i}"))
            .spawn(move || hash_for(budget))
        {
            Ok(h) => {
                spawned += 1;
                handles.push(h);
            }
            Err(e) => println!("    worker {i}: spawn failed: {e}"),
        }
    }
    let total: u64 = handles.into_iter().map(|h| h.join().unwrap_or(0)).sum();
    let elapsed = start.elapsed().as_secs_f64();
    let rate = total as f64 / elapsed;
    println!("    {spawned} of {threads} threads started");
    println!("    {total} hashes in {elapsed:.2} s  ({rate:.0} hashes/s)");
    println!(
        "    {:.1}x the single-thread rate: the loop spread across {spawned} cores\n",
        rate / (one as f64 * 2.0)
    );

    // --- 2. a worker process -------------------------------------------------
    println!(" STEP 3  start a child process (std::process::Command)");
    match Command::new("/bin/sh").arg("-c").arg("echo \"child pid $$ running as $(id -un)\"").output() {
        Ok(out) => println!("    spawned: {}", String::from_utf8_lossy(&out.stdout).trim()),
        Err(e) => println!("    spawn failed: {e}"),
    }
    println!();

    // --- 3. the pool ---------------------------------------------------------
    println!(" STEP 4  dial the pool at {POOL} (TEST-NET-3, never routed), 1 s timeout");
    let addr: SocketAddr = POOL.parse().expect("literal address");
    match TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
        Ok(_) => println!("    connected (unexpected: this address is reserved)"),
        Err(e) => println!(
            "    {e}\n    nothing refused the attempt: the OS sent the connection request and nobody answered"
        ),
    }

    println!("\n UNCONTAINED: {spawned} worker threads, 1 child process, and an outbound dial the OS allowed.");
    println!(" The only limit on this run was the {secs} s this program gave itself.");
}
