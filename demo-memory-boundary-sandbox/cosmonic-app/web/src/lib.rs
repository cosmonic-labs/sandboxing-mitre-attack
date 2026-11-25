//! Memory-boundary sandbox demo — the WEB component (Cosmonic Desktop, p3).
//!
//! Serves the branded UI and builds the two demo records. It has NO filesystem
//! and NO network grants. When the page calls `/run`, this component:
//!
//!   1. reads the vault            (`secrets::reveal()`),
//!   2. hands the record bytes to  (`parsing::parse(list<u8>)`), the C parser,
//!   3. reads the vault again,
//!
//! and returns one JSON verdict built from those three real answers. Both
//! calls cross the host's runtime link to SEPARATE components, each with its
//! own linear memory and its own (empty) grant set.
//!
//! STATUS: the `parser` in this build is a correct, bounds-checked parser. The
//! deliberate out-of-bounds write (CWE-787) and the trap at the linear-memory
//! bound that this demo was designed around are NOT implemented. The
//! "oversized record" button therefore shows the parser's ordinary rejection,
//! not a contained memory-corruption attempt. See the repo README, `## Status`.
//!
//! Routes:
//!   GET  /                    -> the UI
//!   GET  /run?mode=valid      -> parse a well-formed record; default
//!   GET  /run?mode=oversized  -> parse a record whose payload exceeds the buffer
//!   GET  /health              -> "ok"

mod page;

/// Cosmonic's consent-gated analytics loader (the same logic as
/// cosmonic.com/site.js), served at `/site.js` for the page's `<head>`.
const SITE_JS: &[u8] = include_bytes!("site.js");

/// The Cosmonic icon mark, served at `/favicon.svg` as the browser-tab icon.
const FAVICON_SVG: &[u8] = br##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 38 42"><path fill="#655DC6" d="M17.47,32.38C15.36,26.74,12.59,24,6.92,21.89a.93.93,0,0,1,0-1.75c5.67-2.11,8.44-4.86,10.55-10.5a.93.93,0,0,1,1.76,0c1.7,5.7,3.67,9.57,16.62,9.82a.93.93,0,0,0,.94-.93V12.17a3.35,3.35,0,0,0-1.65-2.88L20.07.46a3.3,3.3,0,0,0-3.35,0L1.65,9.29A3.35,3.35,0,0,0,0,12.18V29.87a3.33,3.33,0,0,0,1.65,2.88l15.07,8.83a3.34,3.34,0,0,0,3.35,0l15.07-8.83a3.33,3.33,0,0,0,1.65-2.88V23.45a.93.93,0,0,0-.95-.93c-13,.25-14.91,4.12-16.61,9.81A.92.92,0,0,1,17.47,32.38Z"/></svg>"##;

/// What this build is, stated in every verdict so the JSON cannot be read as
/// evidence of something it does not show.
const BUILD_NOTE: &str = "This build ships a bounds-checked parser. The deliberate out-of-bounds \
write (CWE-787) and the trap at the Wasm linear-memory bound are NOT implemented, so no \
memory-corruption attempt is run here.";

/// The parser's field buffer size (mirrors RECORD_FIELD_CAP in record.h).
const FIELD_CAP: usize = 64;

// The runtime-link interfaces to the parser and the vault. Import-only world:
// this generates the `parsing::parse` and `secrets::reveal` import bindings
// without touching the HTTP bindings the `wasip3` crate provides below.
mod memory_link {
    wit_bindgen::generate!({
        world: "web",
        path: "../wit",
        type_section_suffix: "memory-demo-web",
        generate_all,
    });
}
use memory_link::cosmonic::memory_demo::{parsing, secrets};

use wasip3::http::types::{ErrorCode, Fields, Method, Request, Response};
use wasip3::http_compat::BodyWriter;

struct Component;

wasip3::http::service::export!(Component);

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let method = request.get_method();
        let path_q = request.get_path_with_query().unwrap_or_default();
        let (path, query) = match path_q.split_once('?') {
            Some((p, q)) => (p, q),
            None => (path_q.as_str(), ""),
        };

        match (&method, path) {
            (Method::Get, "/") | (Method::Get, "") => {
                respond(200, "text/html; charset=utf-8", page::PAGE.as_bytes().to_vec())
            }
            (Method::Get, "/health") => respond(200, "text/plain; charset=utf-8", b"ok\n".to_vec()),
            (Method::Get, "/run") => {
                let (mode, payload) = if query_has(query, "mode", "oversized") {
                    // 200 payload bytes for a 64-byte field: too long, and the
                    // header says so truthfully.
                    ("oversized", vec![b'A'; 200])
                } else {
                    ("valid", b"sensor=42;status=OK".to_vec())
                };
                let verdict = run(mode, &payload);
                respond(200, "application/json; charset=utf-8", verdict.into_bytes())
            }
            (Method::Get, "/site.js") => {
                respond(200, "text/javascript; charset=utf-8", SITE_JS.to_vec())
            }
            (Method::Get, "/favicon.svg") => {
                respond(200, "image/svg+xml; charset=utf-8", FAVICON_SVG.to_vec())
            }
            _ => respond(404, "text/plain; charset=utf-8", b"not found\n".to_vec()),
        }
    }
}

/// Frame a payload as a record: "RC01", a little-endian u16 length, the bytes.
fn frame_record(payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    let mut record = Vec::with_capacity(6 + payload.len());
    record.extend_from_slice(b"RC01");
    record.extend_from_slice(&len.to_le_bytes());
    record.extend_from_slice(payload);
    record
}

/// Read the vault, run the record through the parser, read the vault again,
/// and report all three real answers as one JSON verdict.
fn run(mode: &str, payload: &[u8]) -> String {
    let record = frame_record(payload);

    // Cross-component calls: the host routes each to the other component.
    let secret_before = secrets::reveal();
    let parsed = parsing::parse(&record);
    let secret_after = secrets::reveal();

    let unchanged = secret_before == secret_after;
    let (parser_json, summary) = match &parsed {
        // The parser's ok value is already a JSON object; embed it as-is.
        Ok(report) => (
            format!("{{\"outcome\":\"parsed\",\"report\":{report}}}"),
            "The parser accepted the record.",
        ),
        Err(message) => (
            format!("{{\"outcome\":\"rejected\",\"error\":{}}}", json_string(message)),
            "The parser's bounds check refused the record; nothing was written past its buffer.",
        ),
    };
    let verdict = format!(
        "{summary} vault.reveal() returned the same secret before and after: {unchanged}."
    );

    format!(
        "{{\"mode\":{},\"build\":{},\"record\":{{\"bytes\":{},\"payload_bytes\":{},\"capacity\":{}}},\
\"parser\":{},\"vault\":{{\"secret_before\":{},\"secret_after\":{},\"unchanged\":{}}},\
\"attack_run\":false,\"verdict\":{}}}",
        json_string(mode),
        json_string(BUILD_NOTE),
        record.len(),
        payload.len(),
        FIELD_CAP,
        parser_json,
        json_string(&secret_before),
        json_string(&secret_after),
        unchanged,
        json_string(&verdict),
    )
}

/// Encode a string as a JSON string literal.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Tiny query matcher: true if `key=value` is present in the raw query string.
fn query_has(query: &str, key: &str, value: &str) -> bool {
    query.split('&').any(|pair| {
        let mut it = pair.splitn(2, '=');
        it.next() == Some(key) && it.next() == Some(value)
    })
}

/// p3 response builder: set headers + status, then stream the one body frame
/// from a spawned component-model task (the rust-http template pattern).
fn respond(status: u16, content_type: &str, body: Vec<u8>) -> Result<Response, ErrorCode> {
    let list = vec![("content-type".to_string(), content_type.as_bytes().to_vec())];
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
