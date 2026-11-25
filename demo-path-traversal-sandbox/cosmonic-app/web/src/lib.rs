//! Path-traversal sandbox demo: the WEB component (wasi:http p3).
//!
//! Serves the branded UI and forwards each request to the SEPARATE `viewer`
//! component through the host's runtime link:
//! `viewing::run(mode, name) -> string`. It has NO filesystem and NO network
//! grants. Before the first forward it asks the viewer whether the sample files
//! are in the volume yet (`viewing::run("ready")`) and waits briefly if not: on
//! an ephemeral volume the unlinked `seeder` service writes them at startup. The browser never talks to the viewer directly, and the requested
//! file name crosses the component boundary as raw bytes, exactly as received.
//!
//! Routes:
//!   GET  /                         -> the UI
//!   GET  /run?mode=ssh             -> ask the viewer for ../../root/.ssh/id_rsa (the default)
//!   GET  /run?mode=benign          -> ask the viewer for app.conf (the legitimate path)
//!   GET  /run?mode=read&name=...   -> ask for any name (percent-decoded once, as HTTP servers do)
//!   POST /run?mode=read            -> ask for any name; the body is the raw name bytes
//!   GET  /run?mode=variant&id=N    -> run evasion-corpus entry N
//!   GET  /run?mode=corpus          -> list the evasion corpus
//!   GET  /run?mode=fuzz            -> run the whole corpus: "N variants tried, 0 escaped"
//!                                     (&out=<host path of deploy/volume/outside> adds the
//!                                     variants that embed it; fuzz/run.py supplies it
//!                                     on the hostPath deployment)
//!   GET  /run?mode=env             -> environment variables, preopens, credential-path probes
//!   GET  /run?mode=all             -> headline + legitimate read + environment + fuzz summary
//!   GET  /health                   -> "ok"

mod page;

/// The branded hero infographic (served at `/hero.png` for the page banner).
const HERO_PNG: &[u8] = include_bytes!("hero.png");

/// Cosmonic's consent-gated analytics loader (the same logic as
/// cosmonic.com/site.js), served at `/site.js` for the page's `<head>`.
const SITE_JS: &[u8] = include_bytes!("site.js");

/// The Cosmonic icon mark, served at `/favicon.svg` as the browser-tab icon
/// (official purple #655DC6).
const FAVICON_SVG: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 38 42"><path fill="#655DC6" d="M17.47,32.38C15.36,26.74,12.59,24,6.92,21.89a.93.93,0,0,1,0-1.75c5.67-2.11,8.44-4.86,10.55-10.5a.93.93,0,0,1,1.76,0c1.7,5.7,3.67,9.57,16.62,9.82a.93.93,0,0,0,.94-.93V12.17a3.35,3.35,0,0,0-1.65-2.88L20.07.46a3.3,3.3,0,0,0-3.35,0L1.65,9.29A3.35,3.35,0,0,0,0,12.18V29.87a3.33,3.33,0,0,0,1.65,2.88l15.07,8.83a3.34,3.34,0,0,0,3.35,0l15.07-8.83a3.33,3.33,0,0,0,1.65-2.88V23.45a.93.93,0,0,0-.95-.93c-13,.25-14.91,4.12-16.61,9.81A.92.92,0,0,1,17.47,32.38Z"/></svg>"##;

/// The headline request: what the "Read /root/.ssh/id_rsa" button asks for.
const HEADLINE_NAME: &[u8] = b"../../root/.ssh/id_rsa";
/// The legitimate request: what the "View app.conf" button asks for.
const BENIGN_NAME: &[u8] = b"app.conf";

// The runtime-link interface to the viewer. Import-only world: this generates
// the `viewing::run` import binding without touching the HTTP bindings the
// `wasip3` crate provides below. The type_section_suffix keeps its
// component-type section distinct from wasip3's.
mod path_link {
    wit_bindgen::generate!({
        world: "web",
        path: "../wit",
        type_section_suffix: "path-demo-web",
        generate_all,
    });
}
use path_link::cosmonic::path_demo::viewing;

use http_body_util::BodyExt;
use wasip3::http::types::{ErrorCode, Fields, Method, Request, Response};
use wasip3::http_compat::{BodyWriter, IncomingRequestBody};

/// Set once the viewer has reported the sample files present. Nothing with
/// write access is reachable after that point, so the answer cannot change
/// for the life of this instance.
static VOLUME_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// How long a request waits for the seeder service at cold start.
const READY_WAIT_STEPS: u32 = 60;
const READY_WAIT_STEP_NS: u64 = 50_000_000; // 50 ms; 3 s in total

/// Wait until the viewer can see the sample files. A cold-start courtesy only:
/// after the wait the request is forwarded regardless, and the viewer reports
/// whatever it really finds.
async fn wait_for_volume() {
    use std::sync::atomic::Ordering;
    if VOLUME_READY.load(Ordering::Relaxed) {
        return;
    }
    for step in 0..=READY_WAIT_STEPS {
        if viewing::run("ready", &[]).contains("true") {
            VOLUME_READY.store(true, Ordering::Relaxed);
            return;
        }
        if step < READY_WAIT_STEPS {
            wasip3::clocks::monotonic_clock::wait_for(READY_WAIT_STEP_NS).await;
        }
    }
}

struct Component;

wasip3::http::service::export!(Component);

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let method = request.get_method();
        let path_q = request.get_path_with_query().unwrap_or_default();
        let (path, query) = match path_q.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (path_q.clone(), String::new()),
        };

        match (&method, path.as_str()) {
            (Method::Get, "/") | (Method::Get, "") => {
                respond(200, "text/html; charset=utf-8", page::PAGE.as_bytes().to_vec())
            }
            (Method::Get, "/health") => respond(200, "text/plain; charset=utf-8", b"ok\n".to_vec()),

            // THE demo path: hand the requested name across the runtime link to
            // the viewer and return the report the viewer computed.
            (Method::Get, "/run") => {
                let mode = query_get(&query, "mode").unwrap_or("ssh");
                let (mode, name): (&str, Vec<u8>) = match mode {
                    "ssh" => ("read", HEADLINE_NAME.to_vec()),
                    "benign" => ("read", BENIGN_NAME.to_vec()),
                    // One layer of percent-decoding, as any HTTP server applies
                    // to a query value. Whatever is left goes to the viewer raw.
                    "read" => ("read", percent_decode(query_get(&query, "name").unwrap_or(""))),
                    // `out` is the host path of the canary directory, which only
                    // the external harness knows (see fuzz/run.py). Optional.
                    "variant" => {
                        let mut arg = query_get(&query, "id").unwrap_or("").as_bytes().to_vec();
                        arg.push(b'\n');
                        arg.extend(percent_decode(query_get(&query, "out").unwrap_or("")));
                        ("variant", arg)
                    }
                    "fuzz" => ("fuzz", percent_decode(query_get(&query, "out").unwrap_or(""))),
                    other => (other, Vec::new()),
                };
                wait_for_volume().await;
                json(viewing::run(mode, &name))
            }

            // Same as GET /run?mode=read, but the name is the raw request body,
            // so the harness can send bytes and lengths a URL cannot carry.
            (Method::Post, "/run") => match read_request_body(request).await {
                Ok(name) => {
                    wait_for_volume().await;
                    json(viewing::run("read", &name))
                }
                Err(e) => respond(
                    400,
                    "application/json; charset=utf-8",
                    format!("{{\"error\":\"could not read body: {e}\"}}").into_bytes(),
                ),
            },

            // The branded infographic, served to the page's hero banner.
            (Method::Get, "/hero.png") => respond(200, "image/png", HERO_PNG.to_vec()),
            // Consent-gated analytics: HubSpot banner first, then GTM/Apollo.
            (Method::Get, "/site.js") => {
                respond(200, "text/javascript; charset=utf-8", SITE_JS.to_vec())
            }
            // The Cosmonic icon as the browser-tab favicon.
            (Method::Get, "/favicon.svg") => {
                respond(200, "image/svg+xml; charset=utf-8", FAVICON_SVG.to_vec())
            }
            _ => respond(404, "text/plain; charset=utf-8", b"not found\n".to_vec()),
        }
    }
}

fn json(body: String) -> Result<Response, ErrorCode> {
    respond(200, "application/json; charset=utf-8", body.into_bytes())
}

/// Read this component's own incoming request body into memory.
async fn read_request_body(request: Request) -> Result<Vec<u8>, String> {
    let body = IncomingRequestBody::new(request).map_err(|e| format!("bad body: {e}"))?;
    let collected = body.collect().await.map_err(|e| format!("read error: {e}"))?;
    Ok(collected.to_bytes().to_vec())
}

/// Tiny query lookup: the raw (still percent-encoded) value of `key`.
fn query_get<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == key).then_some(v)
    })
}

/// Decode `%XX` once. Malformed escapes are kept literally; `+` is not a space.
fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
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
