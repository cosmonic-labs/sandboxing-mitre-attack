//! The egress allow-list evasion fuzz: every variant in `fuzz/corpus.txt` is
//! fired at the runtime as a real outbound request, and the runtime's answer
//! is recorded.
//!
//! The corpus is compiled into the component from the repo's `fuzz/` directory,
//! so the page, `/fuzz` and the command-line harness all run the same list.

use crate::egress::{self, Outcome};

/// The corpus, baked in at build time from `<repo>/fuzz/corpus.txt`.
pub const CORPUS: &str = include_str!("../../../fuzz/corpus.txt");

/// An inert marker body. The fuzz is about where a request may go, not what it
/// carries.
const PROBE_BODY: &str = "egress-exfil-sandbox fuzz probe (inert)\n";

pub struct Variant {
    pub class: String,
    pub authority: String,
    pub technique: String,
    pub note: String,
}

/// Parse the corpus: `<class> <authority> <technique> <note...>` per line.
pub fn variants() -> Vec<Variant> {
    CORPUS
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let class = fields.next()?.to_string();
            let authority = unescape(fields.next()?);
            let technique = fields.next()?.to_string();
            let note = fields.collect::<Vec<_>>().join(" ");
            Some(Variant { class, authority, technique, note })
        })
        .collect()
}

/// Turn `\xNN` escapes into raw bytes. The result has to be a `string` to
/// cross the WIT boundary, so anything that is not UTF-8 is replaced.
fn unescape(field: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(field.len());
    let mut bytes = field.bytes().peekable();
    while let Some(b) = bytes.next() {
        if b == b'\\' && bytes.peek() == Some(&b'x') {
            bytes.next();
            let hi = bytes.next().and_then(|c| (c as char).to_digit(16));
            let lo = bytes.next().and_then(|c| (c as char).to_digit(16));
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push(u8::try_from(hi * 16 + lo).unwrap_or(b'?'));
                continue;
            }
        }
        out.push(b);
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// True for the classes that must never get past the allow-list.
fn must_be_refused(class: &str) -> bool {
    matches!(class, "attacker" | "confusable" | "ssrf")
}

/// Run every variant and return the summary (and, when asked, every result).
pub async fn run(include_results: bool) -> serde_json::Value {
    let variants = variants();
    let mut results = Vec::with_capacity(variants.len());
    let (mut escaped, mut denied, mut rejected, mut connected, mut transport) = (0u32, 0u32, 0u32, 0u32, 0u32);
    let mut hostile = 0u32;
    let mut control_tried = 0u32;
    let mut control_connected = 0u32;
    let mut escapes: Vec<serde_json::Value> = Vec::new();

    for v in &variants {
        let path = if must_be_refused(&v.class) { "/collect" } else { "/ingest" };
        let attempt = egress::post(false, &v.authority, path, PROBE_BODY.as_bytes().to_vec()).await;
        match &attempt.outcome {
            Outcome::Connected { .. } => connected += 1,
            Outcome::Denied { .. } => denied += 1,
            Outcome::Rejected { .. } => rejected += 1,
            Outcome::Transport { .. } => transport += 1,
        }
        if v.class == "control" {
            control_tried += 1;
            if matches!(&attempt.outcome, Outcome::Connected { status: 200, .. }) {
                control_connected += 1;
            }
        }
        if must_be_refused(&v.class) {
            hostile += 1;
        }
        let is_escape = must_be_refused(&v.class) && attempt.outcome.passed_policy();
        let mut row = attempt.to_json();
        if let Some(obj) = row.as_object_mut() {
            obj.insert("class".into(), v.class.clone().into());
            obj.insert("technique".into(), v.technique.clone().into());
            obj.insert("note".into(), v.note.clone().into());
            obj.insert("escaped".into(), is_escape.into());
        }
        if is_escape {
            escaped += 1;
            escapes.push(row.clone());
        }
        results.push(row);
    }

    let tried = variants.len();
    let mut summary = serde_json::json!({
        "variants_tried": tried,
        "escaped": escaped,
        "line": format!("{tried} variants tried, {escaped} escaped"),
        "hostile_variants": hostile,
        "hostile_refused": hostile - escaped,
        "denied_by_policy": denied,
        "rejected_as_malformed": rejected,
        "connected": connected,
        "passed_policy_then_failed": transport,
        "control_tried": control_tried,
        "control_connected": control_connected,
        "escapes": escapes,
    });
    if include_results {
        if let Some(obj) = summary.as_object_mut() {
            obj.insert("results".into(), results.into());
        }
    }
    summary
}
