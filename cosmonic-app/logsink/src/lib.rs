//! Egress-exfil sandbox demo: the LOG SINK component (Cosmonic Desktop, p3).
//!
//! The legitimate destination in the story: the one host the log shipper is
//! allow-listed to reach. It runs as its own workload on the same machine, so
//! the "send to allowed host" path is a real HTTP request that really returns
//! 200, and nothing ever leaves the laptop.
//!
//! It only receives. What it is sent is counted and dropped: there is no
//! filesystem, no key-value store and no outbound network in this component.
//!
//! Routes:
//!   POST /ingest  -> 200, a JSON receipt (bytes and lines received)
//!   GET  /        -> a one-line description
//!   GET  /health  -> "ok"

use http_body_util::BodyExt;
use wasip3::http::types::{ErrorCode, Fields, Method, Request, Response};
use wasip3::http_compat::{BodyWriter, IncomingRequestBody};

struct Component;

wasip3::http::service::export!(Component);

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let method = request.get_method();
        let path_q = request.get_path_with_query().unwrap_or_default();
        let path = path_q.split('?').next().unwrap_or("");

        match (&method, path) {
            (Method::Post, "/ingest") => {
                let body = match IncomingRequestBody::new(request) {
                    Ok(body) => body,
                    Err(e) => return receipt_error(&format!("bad body: {e:?}")),
                };
                let bytes = match body.collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(e) => return receipt_error(&format!("read error: {e:?}")),
                };
                let lines = bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()).count();
                let receipt = serde_json::json!({
                    "sink": "egress-exfil-logsink",
                    "accepted": true,
                    "received_bytes": bytes.len(),
                    "received_lines": lines,
                    "stored": false,
                });
                respond(200, "application/json; charset=utf-8", receipt.to_string().into_bytes())
            }
            (Method::Get, "/health") => respond(200, "text/plain; charset=utf-8", b"ok\n".to_vec()),
            (Method::Get, "/") | (Method::Get, "") => respond(
                200,
                "text/plain; charset=utf-8",
                b"egress-exfil-logsink: the allow-listed log sink for the egress-exfil sandbox demo. POST /ingest.\n"
                    .to_vec(),
            ),
            _ => respond(404, "text/plain; charset=utf-8", b"not found\n".to_vec()),
        }
    }
}

fn receipt_error(message: &str) -> Result<Response, ErrorCode> {
    let body = serde_json::json!({ "sink": "egress-exfil-logsink", "accepted": false, "error": message });
    respond(400, "application/json; charset=utf-8", body.to_string().into_bytes())
}

/// Build a complete p3 response: headers and status, then the one body frame
/// from a spawned component-model task.
fn respond(status: u16, content_type: &str, body: Vec<u8>) -> Result<Response, ErrorCode> {
    let headers = Fields::from_list(&[(
        "content-type".to_string(),
        content_type.as_bytes().to_vec(),
    )])
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
