//! Container-escape sandbox demo: the RUNNER component (Cosmonic Desktop, p3).
//! MITRE ATT&CK T1609 (Container Administration Command) and T1610 (Deploy
//! Container), contained.
//!
//! A "CI runner": it executes the steps of whatever job it is handed. Hand it
//! a poisoned job and it goes looking for the container runtime's control
//! plane: the Docker socket, containerd's socket, the Docker API over TCP, the
//! pod's service-account token, the kubelet, the Kubernetes API server. On a
//! runner that was given the Docker socket, that is the first step of the
//! well-known container escape.
//!
//! This component is a REACHABILITY PROBE. It asks whether each of those
//! things can be reached, and reports the runtime's own answer. It contains no
//! code that creates, starts or configures a container, and would do nothing
//! further if a probe succeeded.
//!
//! Nothing is patched and nothing in the component checks a target. Every
//! probe fails because the capability it needs was never handed over: no
//! filesystem, no sockets, no process spawn, no outbound hosts.
//!
//! Routes:
//!   GET /                  -> the UI
//!   GET /run?mode=docker   -> the docker.sock job (default)
//!   GET /run?mode=kube     -> the kubelet / Kubernetes API job
//!   GET /run?mode=all      -> both jobs in one report
//!   GET /job?mode=docker   -> the job file the runner is handed (kube likewise)
//!   GET /health            -> "ok"

mod job;
mod page;
mod probes;

use wasip3::http::types::{ErrorCode, Fields, Method, Request, Response};
use wasip3::http_compat::BodyWriter;

/// The branded hero infographic (served at `/hero.png` for the page banner).
const HERO_PNG: &[u8] = include_bytes!("hero.png");

/// Cosmonic's consent-gated analytics loader (the same logic as
/// cosmonic.com/site.js). The page only requests it on a cosmonic.com host.
const SITE_JS: &[u8] = include_bytes!("site.js");

/// The Cosmonic icon mark, served at `/favicon.svg` (official purple #655DC6).
const FAVICON_SVG: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 38 42"><path fill="#655DC6" d="M17.47,32.38C15.36,26.74,12.59,24,6.92,21.89a.93.93,0,0,1,0-1.75c5.67-2.11,8.44-4.86,10.55-10.5a.93.93,0,0,1,1.76,0c1.7,5.7,3.67,9.57,16.62,9.82a.93.93,0,0,0,.94-.93V12.17a3.35,3.35,0,0,0-1.65-2.88L20.07.46a3.3,3.3,0,0,0-3.35,0L1.65,9.29A3.35,3.35,0,0,0,0,12.18V29.87a3.33,3.33,0,0,0,1.65,2.88l15.07,8.83a3.34,3.34,0,0,0,3.35,0l15.07-8.83a3.33,3.33,0,0,0,1.65-2.88V23.45a.93.93,0,0,0-.95-.93c-13,.25-14.91,4.12-16.61,9.81A.92.92,0,0,1,17.47,32.38Z"/></svg>"##;

const JSON: &str = "application/json; charset=utf-8";
const TEXT: &str = "text/plain; charset=utf-8";

/// The WASI interfaces this component imports, as `cosmonic_image_inspect`
/// reports them for the published image. A component cannot enumerate its own
/// imports at run time, so this list is a record of that inspection, not a
/// live measurement: re-run the inspection after any rebuild (see the README).
const IMPORTS: &[&str] = &[
    "wasi:cli/environment@0.2.6",
    "wasi:cli/exit@0.2.6",
    "wasi:cli/stderr@0.2.6",
    "wasi:cli/stdin@0.2.6",
    "wasi:cli/stdout@0.2.6",
    "wasi:cli/terminal-input@0.2.6",
    "wasi:cli/terminal-output@0.2.6",
    "wasi:cli/terminal-stderr@0.2.6",
    "wasi:cli/terminal-stdin@0.2.6",
    "wasi:cli/terminal-stdout@0.2.6",
    "wasi:clocks/types@0.3.0",
    "wasi:clocks/wall-clock@0.2.6",
    "wasi:filesystem/preopens@0.2.6",
    "wasi:filesystem/types@0.2.6",
    "wasi:http/client@0.3.0",
    "wasi:http/types@0.3.0",
    "wasi:io/error@0.2.6",
    "wasi:io/poll@0.2.6",
    "wasi:io/streams@0.2.6",
    "wasi:random/insecure-seed@0.2.6",
];

/// What the import list means for the two things a container escape needs.
const WORLD_NOTE: &str = "The component imports no wasi:sockets interface, so it has no call that \
opens a Unix socket or dials TCP: connecting to docker.sock is not refused, it is not expressible. \
WASI defines no interface that starts a process. Rust's standard library does pull in \
wasi:filesystem (types and preopens); the workload mounts no volume, so no \
preopened directory exists for a path to resolve under (filesystem_check lists / and . on every \
request, and both fail). The one network \
import is wasi:http/client, which the workload answers with allowedHosts: [].";

/// What this demo does and does not show (T1611).
const SCOPE: &str = "This demo shows that the capability path from the workload to a container \
runtime's control plane is absent: no socket path, no credential, no client process and no \
network route. It does not prove that the WebAssembly runtime's own isolation cannot be broken \
(T1611 Escape to Host by a runtime bug). That isolation is assumed by the threat model and is \
tested upstream in Wasmtime, not by this demo.";

struct Component;

wasip3::http::service::export!(Component);

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let method = request.get_method();
        let path_q = request.get_path_with_query().unwrap_or_default();
        drop(request);
        let (path, query) = match path_q.split_once('?') {
            Some((p, q)) => (p, q),
            None => (path_q.as_str(), ""),
        };
        if !matches!(method, Method::Get) {
            return respond(405, TEXT, b"GET only\n".to_vec());
        }

        match path {
            "/" | "" => respond(200, "text/html; charset=utf-8", page::PAGE.as_bytes().to_vec()),
            "/health" => respond(200, TEXT, b"ok\n".to_vec()),
            "/run" => {
                let mode = query_param(query, "mode").unwrap_or("docker");
                let Some(jobs) = jobs_for(mode) else {
                    let body = serde_json::json!({
                        "error": format!("unknown mode {mode} (docker | kube | all)")
                    });
                    return respond(400, JSON, pretty(&body));
                };
                let report = run(mode, &jobs).await;
                respond(200, JSON, pretty(&report))
            }
            "/job" => match query_param(query, "mode").unwrap_or("docker") {
                "docker" => respond(200, TEXT, job::DOCKER.source.as_bytes().to_vec()),
                "kube" => respond(200, TEXT, job::KUBE.source.as_bytes().to_vec()),
                _ => respond(404, TEXT, b"unknown job (docker | kube)\n".to_vec()),
            },
            "/hero.png" => respond(200, "image/png", HERO_PNG.to_vec()),
            "/site.js" => respond(200, "text/javascript; charset=utf-8", SITE_JS.to_vec()),
            "/favicon.svg" => respond(200, "image/svg+xml; charset=utf-8", FAVICON_SVG.to_vec()),
            _ => respond(404, TEXT, b"not found\n".to_vec()),
        }
    }
}

fn jobs_for(mode: &str) -> Option<Vec<&'static job::Job>> {
    match mode {
        "docker" => Some(vec![&job::DOCKER]),
        "kube" => Some(vec![&job::KUBE]),
        "all" => Some(vec![&job::DOCKER, &job::KUBE]),
        _ => None,
    }
}

/// Hand each job to the runner and build one report from the real answers.
async fn run(mode: &str, jobs: &[&'static job::Job]) -> serde_json::Value {
    let mut techniques = Vec::new();
    let (mut attempts, mut blocked) = (0usize, 0usize);

    for j in jobs {
        let steps = job::run(j).await;
        attempts += steps.len();
        blocked += steps.iter().filter(|s| s.blocked).count();
        techniques.push(serde_json::json!({
            "id": j.id,
            "name": j.name,
            "attack": j.attack,
            "payload": j.payload,
            "steps": steps.iter().map(probes::Step::to_json).collect::<Vec<_>>(),
        }));
    }

    let verdict = if blocked == attempts {
        format!(
            "MITIGATED: {blocked} of {attempts} attempts failed. The poisoned job ran, but the \
sandbox has no socket path to open, no token to read, no client to start and no route to a \
runtime API."
        )
    } else {
        format!(
            "NOT CONTAINED: {} of {attempts} attempts got an answer. Check the workload's grants.",
            attempts - blocked
        )
    };

    serde_json::json!({
        "mode": mode,
        "techniques": techniques,
        "attempts": attempts,
        "blocked": blocked,
        "world": {
            "imports": IMPORTS,
            "imports_wasi_sockets": IMPORTS.iter().any(|i| i.starts_with("wasi:sockets")),
            "source": "cosmonic_image_inspect on the published image (recorded at build time)",
            "note": WORLD_NOTE,
            // Measured on every request, not asserted: what the host actually
            // put behind the wasi:filesystem import.
            "filesystem_check": {
                "read_dir(\"/\")": dir_check("/"),
                "read_dir(\".\")": dir_check("."),
            },
        },
        "scope": SCOPE,
        "verdict": verdict,
    })
}

/// List a directory and say what came back. Used to show what, if anything,
/// the host preopened for this component.
fn dir_check(path: &str) -> String {
    match std::fs::read_dir(path) {
        Ok(entries) => format!("listed {} entries", entries.count()),
        Err(e) => e.to_string(),
    }
}

fn pretty(value: &serde_json::Value) -> Vec<u8> {
    let mut out = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    out.push('\n');
    out.into_bytes()
}

/// Tiny query reader: the raw value of `key` in the query string, if present.
fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// p3 response builder: set headers + status, then stream the one body frame
/// from a spawned component-model task (the rust-http template pattern).
fn respond(status: u16, content_type: &str, body: Vec<u8>) -> Result<Response, ErrorCode> {
    let list = vec![
        ("content-type".to_string(), content_type.as_bytes().to_vec()),
        ("cache-control".to_string(), b"no-store".to_vec()),
    ];
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
