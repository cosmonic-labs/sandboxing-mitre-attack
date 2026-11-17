//! The one outbound call this component can make: an HTTP POST through the
//! host's `wasi:http/client`.
//!
//! Nothing here checks the destination. The request is built on the raw
//! `wasi:http` request resource, not through the `http` crate, so the authority
//! string reaches the runtime exactly as given, with no client-side URL parser
//! in between to tidy up an evasion attempt. Whatever comes back (a response,
//! or the runtime's `error-code`) is reported verbatim.

use http_body_util::BodyExt;
use std::time::Instant;
use wasip3::http::types::{ErrorCode, Fields, Method, Request, RequestOptions, Scheme};
use wasip3::http_compat::{http_from_wasi_response, BodyWriter};

/// Give up on a connection after this long (nanoseconds). A refused request
/// never gets this far: the allow-list answers immediately.
const CONNECT_TIMEOUT_NS: u64 = 2_000_000_000;
const FIRST_BYTE_TIMEOUT_NS: u64 = 4_000_000_000;

/// How one outbound attempt ended.
pub enum Outcome {
    /// A response came back: the request left the sandbox.
    Connected { status: u16, body: String },
    /// The runtime refused the request at the egress policy.
    Denied { error: String },
    /// The runtime refused to build or send the request because it is not a
    /// valid request (bad authority syntax). It never reached the policy check
    /// as a destination, and it never reached the network.
    Rejected { stage: &'static str, error: String },
    /// The request got past the policy check and then failed for a transport
    /// reason (DNS, connection refused, timeout).
    Transport { error: String },
}

impl Outcome {
    /// Short machine-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Connected { .. } => "connected",
            Outcome::Denied { .. } => "denied",
            Outcome::Rejected { .. } => "rejected",
            Outcome::Transport { .. } => "transport-error",
        }
    }

    /// True when the runtime let the request past the egress policy.
    pub fn passed_policy(&self) -> bool {
        matches!(self, Outcome::Connected { .. } | Outcome::Transport { .. })
    }
}

/// One attempt, ready to serialise.
pub struct Attempt {
    pub scheme: &'static str,
    pub authority: String,
    pub path: String,
    pub bytes_offered: usize,
    pub elapsed_ms: u128,
    pub outcome: Outcome,
}

impl Attempt {
    pub fn to_json(&self) -> serde_json::Value {
        let (status, response, error, stage) = match &self.outcome {
            Outcome::Connected { status, body } => (Some(*status), Some(body.clone()), None, None),
            Outcome::Denied { error } => (None, None, Some(error.clone()), None),
            Outcome::Rejected { stage, error } => (None, None, Some(error.clone()), Some(*stage)),
            Outcome::Transport { error } => (None, None, Some(error.clone()), None),
        };
        serde_json::json!({
            "destination": format!("{}://{}{}", self.scheme, self.authority, self.path),
            "authority": self.authority,
            "method": "POST",
            "bytes_offered": self.bytes_offered,
            "outcome": self.outcome.label(),
            "passed_policy": self.outcome.passed_policy(),
            "http_status": status,
            "response": response,
            "runtime_error": error,
            "rejected_at": stage,
            "elapsed_ms": self.elapsed_ms,
        })
    }
}

/// Split `scheme://authority/path` by hand. Deliberately dumb: no validation,
/// no normalisation, so a hostile authority survives intact.
pub fn split_url(url: &str) -> (bool, String, String) {
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        (false, url)
    };
    match rest.split_once('/') {
        Some((authority, path)) => (https, authority.to_string(), format!("/{path}")),
        None => (https, rest.to_string(), "/".to_string()),
    }
}

/// POST `payload` to `scheme://authority/path` and report what the runtime did.
pub async fn post(https: bool, authority: &str, path: &str, payload: Vec<u8>) -> Attempt {
    let started = Instant::now();
    let bytes_offered = payload.len();
    let outcome = send(https, authority, path, payload).await;
    Attempt {
        scheme: if https { "https" } else { "http" },
        authority: authority.to_string(),
        path: path.to_string(),
        bytes_offered,
        elapsed_ms: started.elapsed().as_millis(),
        outcome,
    }
}

async fn send(https: bool, authority: &str, path: &str, payload: Vec<u8>) -> Outcome {
    let headers = match Fields::from_list(&[(
        "content-type".to_string(),
        b"text/plain; charset=utf-8".to_vec(),
    )]) {
        Ok(headers) => headers,
        Err(e) => return Outcome::Rejected { stage: "headers", error: format!("{e:?}") },
    };

    let options = RequestOptions::new();
    let _ = options.set_connect_timeout(Some(CONNECT_TIMEOUT_NS));
    let _ = options.set_first_byte_timeout(Some(FIRST_BYTE_TIMEOUT_NS));

    let (mut writer, body_rx, trailers_rx) = BodyWriter::new();
    let (request, _sent) = Request::new(headers, Some(body_rx), trailers_rx, Some(options));

    if request.set_method(&Method::Post).is_err() {
        return Outcome::Rejected { stage: "set-method", error: "the runtime refused the method".into() };
    }
    let scheme = if https { Scheme::Https } else { Scheme::Http };
    if request.set_scheme(Some(&scheme)).is_err() {
        return Outcome::Rejected { stage: "set-scheme", error: "the runtime refused the scheme".into() };
    }
    // The authority goes in raw. If the runtime will not even accept it as an
    // authority, that refusal is the answer.
    if request.set_authority(Some(authority)).is_err() {
        return Outcome::Rejected {
            stage: "set-authority",
            error: "the runtime refused this string as a request authority".into(),
        };
    }
    if request.set_path_with_query(Some(path)).is_err() {
        return Outcome::Rejected { stage: "set-path", error: "the runtime refused the path".into() };
    }

    // The body is a stream: offer it from a spawned task. If the request is
    // refused the stream is dropped unread.
    wasip3::wit_bindgen::spawn_local(async move {
        let frame = http_body::Frame::data(bytes::Bytes::from(payload));
        let _ = writer.send_frame(frame).await;
        drop(writer.stream_writer);
        let _ = writer.result_writer.write(Ok(None)).await;
    });

    match wasip3::http::client::send(request).await {
        Ok(response) => {
            let status = response.get_status_code();
            let body = match http_from_wasi_response(response) {
                Ok(resp) => match resp.into_body().collect().await {
                    Ok(collected) => {
                        let bytes = collected.to_bytes();
                        let text = String::from_utf8_lossy(&bytes);
                        text.chars().take(600).collect::<String>()
                    }
                    Err(e) => format!("(could not read the response body: {e:?})"),
                },
                Err(e) => format!("(could not read the response: {e:?})"),
            };
            Outcome::Connected { status, body }
        }
        Err(code) => classify(&code),
    }
}

/// Sort the runtime's `error-code` into "the policy said no", "this is not a
/// valid request" and "it got out and then failed". The raw code is always
/// kept, so the report shows the runtime's own words.
fn classify(code: &ErrorCode) -> Outcome {
    let error = format!("{code:?}");
    match code {
        ErrorCode::HttpRequestDenied | ErrorCode::DestinationIpProhibited => Outcome::Denied { error },
        ErrorCode::HttpRequestUriInvalid
        | ErrorCode::HttpRequestUriTooLong
        | ErrorCode::HttpRequestMethodInvalid => Outcome::Rejected { stage: "send", error },
        _ => Outcome::Transport { error },
    }
}
