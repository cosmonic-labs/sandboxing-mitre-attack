//! The reachability probes a job step can ask the runner to make.
//!
//! Every function here really makes the call (a file open, a directory read,
//! an environment lookup, a process spawn, an HTTP request through the host)
//! and reports the runtime's own answer verbatim. Nothing is simulated and
//! nothing checks the target first.
//!
//! These are probes, not an escape. The furthest any of them goes is asking a
//! read-only question (`GET /_ping`, `GET /version`, `GET /healthz`) of a
//! control plane, or opening a path. No probe creates, starts or configures a
//! container, and none would do so if it got an answer.

use wasip3::http::types::{ErrorCode, Fields, Method, Request, RequestOptions, Scheme};
use wasip3::http_compat::BodyWriter;

/// Give up on a connection after this long (nanoseconds). A denied request
/// never gets this far: the egress policy answers immediately.
const CONNECT_TIMEOUT_NS: u64 = 2_000_000_000;
const FIRST_BYTE_TIMEOUT_NS: u64 = 3_000_000_000;

const WHY_NO_FILES: &str = "No filesystem was granted: the workload mounts no volume, so the \
component has no preopened directory and there is nothing to resolve the path against. The \
socket file is not hidden or permission-denied; it does not exist in this sandbox.";
const WHY_NO_PROC: &str = "No filesystem was granted, and /proc is a kernel view of a process \
table. A component is not a process with a view of the host's: there is no /proc to mount.";
const WHY_NO_SECRETS: &str = "No filesystem was granted. A pod gets its service-account token \
as a projected volume; this workload declares no volumes, so no token is ever placed in reach.";
const WHY_NO_ENV: &str = "A component does not inherit the host's environment: it sees only \
what the workload's localResources.environment lists, and this workload lists nothing.";
const WHY_NO_PROCESS: &str = "WASI has no interface that starts a process. There is no fork, \
no exec and no $PATH, so there is no docker, kubectl, nsenter or shell to run.";
const WHY_NO_EGRESS: &str = "The only network path this component imports is the host's \
wasi:http client, and the workload grants allowedHosts: [], so the host refuses every outbound \
request before a connection is made. The component imports no wasi:sockets, so there is no \
other way to dial.";

/// One attempted step and the runtime's answer.
pub struct Step {
    /// socket | discover | secret | spawn | network
    pub block: &'static str,
    /// What was attempted, in plain terms.
    pub action: String,
    /// The path, variable, command or URL the step named.
    pub target: String,
    /// The call the component made.
    pub call: &'static str,
    /// The runtime's answer, verbatim.
    pub result: String,
    /// Why the sandbox answered that way.
    pub why: &'static str,
    /// True when the attempt got nothing.
    pub blocked: bool,
}

impl Step {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "block": self.block,
            "action": self.action,
            "target": self.target,
            "call": self.call,
            "result": self.result,
            "why": self.why,
            "blocked": self.blocked,
        })
    }
}

/// Open a Unix-socket path read/write, the first thing any client of a
/// container runtime does. (A socket file cannot be connected with `open`
/// even natively; the point is whether the path exists to be reached at all.)
pub fn open_socket(action: &str, path: &str) -> Step {
    let opened = std::fs::OpenOptions::new().read(true).write(true).open(path);
    let (result, blocked) = match opened {
        Ok(_) => ("opened".to_string(), false),
        Err(e) => (e.to_string(), true),
    };
    Step {
        block: "socket",
        action: action.to_string(),
        target: path.to_string(),
        call: "std::fs::OpenOptions::open (wasi:filesystem)",
        result,
        why: WHY_NO_FILES,
        blocked,
    }
}

/// Read a file. Only the byte count is ever reported, never the content.
pub fn read_file(block: &'static str, action: &str, path: &str) -> Step {
    let (result, blocked) = match std::fs::read(path) {
        Ok(bytes) => (format!("read {} bytes", bytes.len()), false),
        Err(e) => (e.to_string(), true),
    };
    let why = if path.starts_with("/proc") {
        WHY_NO_PROC
    } else if block == "secret" {
        WHY_NO_SECRETS
    } else {
        WHY_NO_FILES
    };
    Step {
        block,
        action: action.to_string(),
        target: path.to_string(),
        call: "std::fs::read (wasi:filesystem)",
        result,
        why,
        blocked,
    }
}

/// List a directory. Only the entry count is reported.
pub fn list_dir(action: &str, path: &str) -> Step {
    let (result, blocked) = match std::fs::read_dir(path) {
        Ok(entries) => (format!("listed {} entries", entries.count()), false),
        Err(e) => (e.to_string(), true),
    };
    Step {
        block: "discover",
        action: action.to_string(),
        target: path.to_string(),
        call: "std::fs::read_dir (wasi:filesystem)",
        result,
        why: WHY_NO_FILES,
        blocked,
    }
}

/// Look up an environment variable that would point at a control plane.
pub fn env_var(action: &str, name: &str) -> Step {
    let (result, blocked) = match std::env::var(name) {
        Ok(value) => (format!("set ({} bytes)", value.len()), false),
        Err(e) => (e.to_string(), true),
    };
    Step {
        block: "discover",
        action: action.to_string(),
        target: name.to_string(),
        call: "std::env::var (wasi:cli/environment)",
        result,
        why: WHY_NO_ENV,
        blocked,
    }
}

/// Start a client binary with a read-only subcommand.
pub fn spawn(action: &str, program: &str, args: &[&str]) -> Step {
    let (result, blocked) = match std::process::Command::new(program).args(args).output() {
        Ok(out) => (format!("ran, exit status {}", out.status), false),
        Err(e) => (e.to_string(), true),
    };
    Step {
        block: "spawn",
        action: action.to_string(),
        target: format!("{program} {}", args.join(" ")),
        call: "std::process::Command::output",
        result,
        why: WHY_NO_PROCESS,
        blocked,
    }
}

/// `GET` a read-only endpoint through the host's `wasi:http` client and report
/// what the runtime did with the request.
pub async fn http_get(action: &str, url: &str) -> Step {
    let (result, blocked) = send(url).await;
    Step {
        block: "network",
        action: action.to_string(),
        target: url.to_string(),
        call: "wasi:http/client.send",
        result,
        why: WHY_NO_EGRESS,
        blocked,
    }
}

/// Split `scheme://authority/path` by hand: no validation, no normalisation.
fn split_url(url: &str) -> (bool, &str, String) {
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        (false, url)
    };
    match rest.split_once('/') {
        Some((authority, path)) => (https, authority, format!("/{path}")),
        None => (https, rest, "/".to_string()),
    }
}

async fn send(url: &str) -> (String, bool) {
    let (https, authority, path) = split_url(url);

    let headers = match Fields::from_list(&[("accept".to_string(), b"*/*".to_vec())]) {
        Ok(headers) => headers,
        Err(e) => return (format!("the runtime refused the headers: {e:?}"), true),
    };
    let options = RequestOptions::new();
    let _ = options.set_connect_timeout(Some(CONNECT_TIMEOUT_NS));
    let _ = options.set_first_byte_timeout(Some(FIRST_BYTE_TIMEOUT_NS));

    // A GET with an empty body: the body stream is closed straight away.
    let (writer, body_rx, trailers_rx) = BodyWriter::new();
    let (request, _sent) = Request::new(headers, Some(body_rx), trailers_rx, Some(options));

    if request.set_method(&Method::Get).is_err() {
        return ("the runtime refused the method".into(), true);
    }
    let scheme = if https { Scheme::Https } else { Scheme::Http };
    if request.set_scheme(Some(&scheme)).is_err() {
        return ("the runtime refused the scheme".into(), true);
    }
    if request.set_authority(Some(authority)).is_err() {
        return ("the runtime refused this string as a request authority".into(), true);
    }
    if request.set_path_with_query(Some(&path)).is_err() {
        return ("the runtime refused the path".into(), true);
    }

    wasip3::wit_bindgen::spawn_local(async move {
        drop(writer.stream_writer);
        let _ = writer.result_writer.write(Ok(None)).await;
    });

    match wasip3::http::client::send(request).await {
        // Any response at all means the request left the sandbox.
        Ok(response) => (format!("HTTP {}", response.get_status_code()), false),
        // The egress policy said no: nothing left the sandbox.
        Err(code @ (ErrorCode::HttpRequestDenied | ErrorCode::DestinationIpProhibited)) => {
            (format!("host refused the request: {code:?}"), true)
        }
        // Any other error means the request got PAST the policy and failed
        // later (DNS, refused, timeout). That is not containment, so it is
        // not counted as blocked.
        Err(code) => (format!("passed the egress policy, then failed: {code:?}"), false),
    }
}
