//! Resource-hijack sandbox demo: the MINER component (Cosmonic Desktop, p3).
//! MITRE ATT&CK T1496 (Resource Hijacking), CWE-400.
//!
//! One component. It serves the branded UI and, when driven, behaves like code
//! that has been hijacked to burn compute: it starts a CPU-bound hashing loop,
//! tries to start worker threads and processes, grows its memory, tries to
//! reach a pool, and tries to keep working after the request ends.
//!
//! It has NO filesystem and NO network grants. See `probes.rs` for the probes
//! and for the safety budget every probe carries inside the component.
//!
//! Routes:
//!   GET /                       -> the UI
//!   GET /run?mode=miner         -> pool dial + worker spawn + CPU loop (default)
//!   GET /run?mode=cpu[&ms=N]    -> the CPU loop only (N <= 3000)
//!   GET /run?mode=spawn         -> worker threads and processes
//!   GET /run?mode=memory        -> grow memory until refused or the ceiling
//!   GET /run?mode=pool          -> dial the pool
//!   GET /run?mode=persist       -> return, then keep hashing in the background (<= 3000 ms)
//!   GET /run?mode=persist&kind=heartbeat[&secs=N]
//!                               -> return, then only sleep and leave a heartbeat (N <= 120)
//!   GET /run?mode=status        -> this instance's state (and any background work)
//!   GET /run?mode=idle[&secs=N] -> wait N seconds without using CPU (N <= 120)
//!   GET /probe                  -> the evasion variants
//!   GET /probe?variant=NAME     -> run one evasion variant
//!   GET /health                 -> "ok"

mod page;
mod probes;

use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;
use wasip3::http::types::{ErrorCode, Fields, Method, Request, Response};
use wasip3::http_compat::BodyWriter;

/// The branded hero infographic (served at `/hero.png` for the page banner).
const HERO_PNG: &[u8] = include_bytes!("hero.png");

/// Cosmonic's consent-gated analytics loader (the same logic as
/// cosmonic.com/site.js), served at `/site.js` for the page's `<head>`.
const SITE_JS: &[u8] = include_bytes!("site.js");

/// The Cosmonic icon mark, served at `/favicon.svg` as the browser-tab icon.
const FAVICON_SVG: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 38 42"><path fill="#655DC6" d="M17.47,32.38C15.36,26.74,12.59,24,6.92,21.89a.93.93,0,0,1,0-1.75c5.67-2.11,8.44-4.86,10.55-10.5a.93.93,0,0,1,1.76,0c1.7,5.7,3.67,9.57,16.62,9.82a.93.93,0,0,0,.94-.93V12.17a3.35,3.35,0,0,0-1.65-2.88L20.07.46a3.3,3.3,0,0,0-3.35,0L1.65,9.29A3.35,3.35,0,0,0,0,12.18V29.87a3.33,3.33,0,0,0,1.65,2.88l15.07,8.83a3.34,3.34,0,0,0,3.35,0l15.07-8.83a3.33,3.33,0,0,0,1.65-2.88V23.45a.93.93,0,0,0-.95-.93c-13,.25-14.91,4.12-16.61,9.81A.92.92,0,0,1,17.47,32.38Z"/></svg>"##;

/// How many requests THIS instance has served. Lives in linear memory, so it
/// resets whenever the host hands a request to a fresh instance.
static INVOCATIONS: AtomicU64 = AtomicU64::new(0);
static INSTANCE_START: OnceLock<Instant> = OnceLock::new();

/// What `/run?mode=persist` leaves running after its response.
enum Background {
    Work(u64),
    Heartbeat(u64, u64),
}

struct Component;

wasip3::http::service::export!(Component);

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let start = *INSTANCE_START.get_or_init(Instant::now);
        let invocation = INVOCATIONS.fetch_add(1, Ordering::Relaxed) + 1;
        let memory_at_entry = probes::memory_mb();

        let method = request.get_method();
        let path_q = request.get_path_with_query().unwrap_or_default();
        let (path, query) = match path_q.split_once('?') {
            Some((p, q)) => (p, q),
            None => (path_q.as_str(), ""),
        };

        // The instance block every JSON answer carries: it is how you can see
        // whether the host reused an instance or gave this request a new one.
        let instance = |extra_ms: u64| -> Value {
            json!({
                "invocation_in_this_instance": invocation,
                "instance_age_ms": start.elapsed().as_millis() as u64 + extra_ms,
                "linear_memory_mb_at_entry": memory_at_entry,
                "linear_memory_mb_now": probes::memory_mb(),
            })
        };

        match (&method, path) {
            (Method::Get, "/") | (Method::Get, "") => {
                respond(200, "text/html; charset=utf-8", page::PAGE.as_bytes().to_vec())
            }
            (Method::Get, "/health") => respond(200, "text/plain; charset=utf-8", b"ok\n".to_vec()),
            (Method::Get, "/hero.png") => respond(200, "image/png", HERO_PNG.to_vec()),
            (Method::Get, "/site.js") => {
                respond(200, "text/javascript; charset=utf-8", SITE_JS.to_vec())
            }
            (Method::Get, "/favicon.svg") => {
                respond(200, "image/svg+xml; charset=utf-8", FAVICON_SVG.to_vec())
            }

            (Method::Get, "/run") => {
                let mode = query_get(query, "mode").unwrap_or("miner");
                let mut background: Option<Background> = None;
                let mut body = match mode {
                    "miner" => {
                        let pool = probes::pool().await;
                        let threads = probes::threads(8);
                        let processes = probes::processes();
                        let cpu = probes::cpu(None);
                        let verdict = miner_verdict(&cpu, &threads, &processes, &pool);
                        json!({
                            "mode": "miner",
                            "technique": "T1496 Resource Hijacking (CWE-400)",
                            "verdict": verdict,
                            "cpu": cpu, "threads": threads, "processes": processes, "pool": pool,
                        })
                    }
                    "cpu" => {
                        let ms = query_get(query, "ms").and_then(|v| v.parse::<u64>().ok());
                        let cpu = probes::cpu(ms);
                        json!({
                            "mode": "cpu",
                            "technique": "T1496.001 Compute Hijacking (CWE-400)",
                            "verdict": format!(
                                "BOUNDED, NOT REMOVED: the loop ran. {} hashes in {} ms on one core, stopped by the {}.",
                                cpu["hashes"], cpu["elapsed_ms"], cpu["stopped_by"].as_str().unwrap_or("?")
                            ),
                            "cpu": cpu,
                        })
                    }
                    "spawn" => {
                        let threads = probes::threads(8);
                        let processes = probes::processes();
                        let made = threads["spawned"].as_u64().unwrap_or(0)
                            + processes["spawned"].as_u64().unwrap_or(0);
                        let tried = threads["attempted"].as_u64().unwrap_or(0)
                            + processes["attempted"].as_u64().unwrap_or(0);
                        json!({
                            "mode": "spawn",
                            "technique": "T1496.001 Compute Hijacking: scale out to more cores",
                            "verdict": if made == 0 {
                                format!("REMOVED: {tried} worker attempts (threads and processes), 0 created. There is no capability to ask with.")
                            } else {
                                format!("NOT CONTAINED: {made} of {tried} workers were created.")
                            },
                            "threads": threads, "processes": processes,
                        })
                    }
                    "memory" => {
                        let memory = probes::memory_grow_steps(16 * 16);
                        json!({
                            "mode": "memory",
                            "technique": "T1496 / T1499 Endpoint DoS: memory exhaustion (CWE-400, CWE-770)",
                            "verdict": format!(
                                "BOUNDED, NOT REMOVED: memory grew from {} MiB to {} MiB, stopped by the {}.",
                                memory["start_mb"], memory["reached_mb"],
                                memory["stopped_by"].as_str().unwrap_or("?")
                            ),
                            "memory": memory,
                        })
                    }
                    "pool" => {
                        let pool = probes::pool().await;
                        let connected = pool["connected"].as_u64().unwrap_or(0);
                        json!({
                            "mode": "pool",
                            "technique": "T1496 Resource Hijacking: reach the mining pool (T1071 C2)",
                            "verdict": if connected == 0 {
                                format!("REMOVED: {} pool dials, 0 connected. allowedHosts is empty, so the host refuses the request.", pool["attempted"])
                            } else {
                                format!("NOT CONTAINED: {connected} pool dials connected.")
                            },
                            "pool": pool,
                        })
                    }
                    "persist" => {
                        let run_id = wall_clock_secs();
                        let heartbeat = query_get(query, "kind") == Some("heartbeat");
                        let secs = query_get(query, "secs")
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(30)
                            .clamp(5, probes::HEARTBEAT_CAP_SECS);
                        background = Some(if heartbeat {
                            Background::Heartbeat(run_id, secs)
                        } else {
                            Background::Work(run_id)
                        });
                        let (plan, cap) = if heartbeat {
                            (
                                "no hashing: sleep, and every 5 s dial beat-NN.run-ID.pool.attacker.example (denied, and logged by the host)",
                                format!("{secs} s"),
                            )
                        } else {
                            (
                                "250 ms hashing slices, a yield to the host between each, and after each a dial to slice-NN.run-ID.pool.attacker.example (denied, and logged by the host)",
                                format!("{} ms of hashing", probes::CPU_BUDGET_MS),
                            )
                        };
                        json!({
                            "mode": "persist",
                            "technique": "T1496 Resource Hijacking: keep working after the request",
                            "verdict": format!("STARTED: this response is returned first; a background task then carries on for up to {cap}. Ask /run?mode=status to see what became of it."),
                            "persist": {
                                "class": "bounded",
                                "run_id": run_id,
                                "kind": if heartbeat { "heartbeat" } else { "work" },
                                "plan": plan,
                                "in_component_cap": cap,
                            },
                        })
                    }
                    "status" => json!({
                        "mode": "status",
                        "verdict": "This instance's own view of itself. A background run that is missing here was in an instance the host has since dropped.",
                        "background": probes::background_state(),
                    }),
                    "idle" => {
                        let secs = query_get(query, "secs")
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(5)
                            .clamp(1, 120);
                        let t = Instant::now();
                        for _ in 0..secs {
                            wasip3::clocks::monotonic_clock::wait_for(1_000_000_000).await;
                        }
                        json!({
                            "mode": "idle",
                            "verdict": format!("The invocation stayed open for {} ms without using CPU; no host timeout ended it.", t.elapsed().as_millis()),
                            "idle": { "requested_secs": secs, "elapsed_ms": t.elapsed().as_millis() as u64 },
                        })
                    }
                    other => {
                        let msg = json!({ "error": format!("unknown mode {other:?}"),
                            "modes": ["miner", "cpu", "spawn", "memory", "pool", "persist", "status", "idle"] });
                        return respond_json(400, &msg);
                    }
                };
                body["instance"] = instance(0);
                let response = respond_json(200, &body);
                match background {
                    Some(Background::Work(id)) => wasip3::spawn_local(probes::background_work(id)),
                    Some(Background::Heartbeat(id, secs)) => {
                        wasip3::spawn_local(probes::background_heartbeat(id, secs))
                    }
                    None => {}
                }
                response
            }

            (Method::Get, "/probe") => match query_get(query, "variant") {
                None => respond_json(200, &probes::variant_list()),
                Some(name) => match probes::variant(name) {
                    Some(mut v) => {
                        v["instance"] = instance(0);
                        respond_json(200, &v)
                    }
                    None => respond_json(400, &json!({ "error": format!("unknown variant {name:?}") })),
                },
            },

            _ => respond(404, "text/plain; charset=utf-8", b"not found\n".to_vec()),
        }
    }
}

/// The "Start miner" summary, computed from what the probes returned.
fn miner_verdict(cpu: &Value, threads: &Value, processes: &Value, pool: &Value) -> String {
    let workers = threads["spawned"].as_u64().unwrap_or(0) + processes["spawned"].as_u64().unwrap_or(0);
    let worker_tries =
        threads["attempted"].as_u64().unwrap_or(0) + processes["attempted"].as_u64().unwrap_or(0);
    let dials = pool["connected"].as_u64().unwrap_or(0);
    let head = if workers == 0 && dials == 0 { "CONTAINED, NOT REMOVED" } else { "NOT CONTAINED" };
    format!(
        "{head}: the miner ran. {} hashes in {} ms on one core, stopped by the {}. \
         {workers} of {worker_tries} worker threads/processes created. \
         {dials} of {} pool dials connected.",
        cpu["hashes"],
        cpu["elapsed_ms"],
        cpu["stopped_by"].as_str().unwrap_or("?"),
        pool["attempted"],
    )
}

fn wall_clock_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Tiny query lookup: the value of `key` in the raw query string.
fn query_get<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then_some(v)
    })
}

fn respond_json(status: u16, value: &Value) -> Result<Response, ErrorCode> {
    let body = serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{}".to_vec());
    build_response(
        status,
        &[
            ("content-type", b"application/json; charset=utf-8".to_vec()),
            ("cache-control", b"no-store".to_vec()),
        ],
        body,
    )
}

fn respond(status: u16, content_type: &str, body: Vec<u8>) -> Result<Response, ErrorCode> {
    build_response(status, &[("content-type", content_type.as_bytes().to_vec())], body)
}

/// Shared p3 response builder: set headers + status, then stream the one body
/// frame from a spawned component-model task (the rust-http template pattern).
fn build_response(
    status: u16,
    header_pairs: &[(&str, Vec<u8>)],
    body: Vec<u8>,
) -> Result<Response, ErrorCode> {
    let list: Vec<(String, Vec<u8>)> = header_pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect();
    let headers = Fields::from_list(&list)
        .map_err(|err| ErrorCode::InternalError(Some(format!("invalid headers: {err}"))))?;

    let (mut writer, body_rx, result_rx) = BodyWriter::new();
    let (response, _transmit) = Response::new(headers, Some(body_rx), result_rx);
    response
        .set_status_code(status)
        .map_err(|()| ErrorCode::InternalError(Some("invalid status code".into())))?;

    wasip3::spawn_local(async move {
        let frame = http_body::Frame::data(bytes::Bytes::from(body));
        let _ = writer.send_frame(frame).await;
        drop(writer.stream_writer);
        let _ = writer.result_writer.write(Ok(None)).await;
    });

    Ok(response)
}
