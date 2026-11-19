//! The egress allow-list evasion fuzz: every variant in `fuzz/corpus.txt` is
//! fired at the runtime as a real outbound request, and the runtime's answer
//! is recorded.
//!
//! The corpus is compiled into the component from the repo's `fuzz/` directory,
//! so the page, `/fuzz` and the command-line harness all run the same list.
//!
//! The corpus names the allow-listed host with placeholders (`{host}`,
//! `{host:upper}`, ...). They are filled in here from the configured sink
//! (`LOG_SINK_URL`), so the "allowed host" variants follow whatever host this
//! deployment really allow-lists, and every request uses the sink's scheme.

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

/// The configured sink, split into the parts the corpus placeholders use.
pub struct Sink {
    pub https: bool,
    /// Hostname only: what an `allowedHosts` entry is compared against.
    pub host: String,
    /// The port, if the sink URL names one.
    pub explicit_port: Option<String>,
}

impl Sink {
    pub fn from_url(url: &str) -> Sink {
        let (https, authority, _path) = egress::split_url(url);
        let (host, explicit_port) = split_host_port(&authority);
        Sink { https, host, explicit_port }
    }

    pub fn scheme(&self) -> &'static str {
        if self.https { "https" } else { "http" }
    }

    /// `host` or `host:port`, as the sink URL has it.
    pub fn authority(&self) -> String {
        match &self.explicit_port {
            Some(port) => format!("{}:{port}", self.host),
            None => self.host.clone(),
        }
    }

    /// The port in effect: the named one, else the scheme's default.
    fn port(&self) -> String {
        match &self.explicit_port {
            Some(port) => port.clone(),
            None => if self.https { "443" } else { "80" }.to_string(),
        }
    }

    /// The value of one `{placeholder}`, or `None` when it cannot be built for
    /// this host (or is not a placeholder this build knows).
    fn token(&self, token: &str) -> Option<String> {
        let host = self.host.as_str();
        let (label, parent) = match host.split_once('.') {
            Some((label, parent)) => (label, Some(parent)),
            None => (host, None),
        };
        let rejoin = |label: String| match parent {
            Some(parent) => format!("{label}.{parent}"),
            None => label,
        };
        let mut chars = host.chars();
        let first = chars.next()?;
        let tail = chars.as_str();
        Some(match token {
            "host" => host.to_string(),
            ":port" => self.explicit_port.as_ref().map(|p| format!(":{p}")).unwrap_or_default(),
            "port" => self.port(),
            "host:upper" => host.to_uppercase(),
            "host:mixed" => mixed_case(host),
            "host:fullwidth" => {
                if !first.is_ascii_alphanumeric() {
                    return None;
                }
                // The fullwidth forms sit at a fixed offset from ASCII.
                let wide = char::from_u32(u32::from(first) + 0xFEE0)?;
                format!("{wide}{tail}")
            }
            "host:ideodot" => {
                parent?;
                host.replacen('.', "\u{3002}", 1)
            }
            "host:percent" => {
                if !first.is_ascii() {
                    return None;
                }
                format!("%{:02x}{tail}", u32::from(first))
            }
            "host:label" => {
                parent?;
                label.to_string()
            }
            "host:parent" => parent?.to_string(),
            "host:truncated" => {
                let mut short = label.to_string();
                short.pop()?;
                if short.is_empty() {
                    return None;
                }
                rejoin(short)
            }
            "host:homoglyph" => rejoin(homoglyph(label)?),
            "host:homoglyph-puny" => rejoin(format!("xn--{}", punycode(&homoglyph(label)?)?)),
            _ => return None,
        })
    }

    /// Fill in every `{placeholder}` in a corpus authority field.
    pub fn expand(&self, field: &str) -> Option<String> {
        let mut out = String::with_capacity(field.len());
        let mut rest = field;
        while let Some((before, after)) = rest.split_once('{') {
            out.push_str(before);
            let (token, tail) = after.split_once('}')?;
            out.push_str(&self.token(token)?);
            rest = tail;
        }
        out.push_str(rest);
        Some(out)
    }
}

/// Split `host[:port]`. Only a trailing all-digit part counts as a port, so a
/// bracketed IPv6 literal without one is left whole.
pub fn split_host_port(authority: &str) -> (String, Option<String>) {
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (host.to_string(), Some(port.to_string()))
        }
        _ => (authority.to_string(), None),
    }
}

/// Upper-case the first letter of the name and of every word after `-` or `.`.
fn mixed_case(host: &str) -> String {
    let mut out = String::with_capacity(host.len());
    let mut start = true;
    for c in host.chars() {
        if start {
            out.extend(c.to_uppercase());
        } else {
            out.push(c);
        }
        start = c == '-' || c == '.';
    }
    out
}

/// Swap one Latin letter of `label` for its Cyrillic look-alike: the last `i`,
/// or failing that the last `a`, `e`, `o`, `c` or `p`.
fn homoglyph(label: &str) -> Option<String> {
    const LOOKALIKES: [(char, char); 6] = [
        ('i', '\u{456}'),
        ('a', '\u{430}'),
        ('e', '\u{435}'),
        ('o', '\u{43e}'),
        ('c', '\u{441}'),
        ('p', '\u{440}'),
    ];
    for (latin, cyrillic) in LOOKALIKES {
        if let Some((before, after)) = label.rsplit_once(latin) {
            return Some(format!("{before}{cyrillic}{after}"));
        }
    }
    None
}

/// Punycode (RFC 3492) for one label, without the `xn--` prefix.
fn punycode(label: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    // Punycode digits: 0..=25 are a..z, 26..=35 are 0..9.
    let digit = |d: u32| {
        if d < 26 {
            char::from_u32(u32::from(b'a') + d)
        } else {
            char::from_u32(u32::from(b'0') + d - 26)
        }
    };
    let adapt = |delta: u32, points: u32, first: bool| {
        let mut delta = if first { delta / 700 } else { delta / 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (BASE * delta) / (delta + 38)
    };

    let points: Vec<u32> = label.chars().map(u32::from).collect();
    let mut out: String = label.chars().filter(char::is_ascii).collect();
    let basic = u32::try_from(out.len()).ok()?;
    let total = u32::try_from(points.len()).ok()?;
    if basic > 0 {
        out.push('-');
    }
    let (mut n, mut delta, mut bias, mut handled) = (128u32, 0u32, 72u32, basic);
    while handled < total {
        let next = points.iter().copied().filter(|&c| c >= n).min()?;
        delta = delta.checked_add((next - n).checked_mul(handled + 1)?)?;
        n = next;
        for &c in &points {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias { TMIN } else if k >= bias + TMAX { TMAX } else { k - bias };
                    if q < t {
                        break;
                    }
                    out.push(digit(t + (q - t) % (BASE - t))?);
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit(q)?);
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta += 1;
        n += 1;
    }
    Some(out)
}

/// Parse the corpus: `<class> <authority> <technique> <note...>` per line,
/// with the authority's placeholders filled in for `sink`. Returns the
/// variants and how many lines were skipped (see `fuzz/corpus.txt`).
pub fn variants(sink: &Sink) -> (Vec<Variant>, u32) {
    let mut skipped = 0u32;
    let allowed = sink.authority().to_lowercase();
    let list = CORPUS
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let class = fields.next()?.to_string();
            let template = fields.next()?;
            let technique = fields.next()?.to_string();
            let note = fields.collect::<Vec<_>>().join(" ");
            let Some(expanded) = sink.expand(template) else {
                skipped += 1;
                return None;
            };
            let authority = unescape(&expanded);
            // A hostile variant that came out as the allow-listed host itself
            // would be a false "escape": it is not a variant for this host.
            let lower = authority.to_lowercase();
            if must_be_refused(&class) && (lower == allowed || lower == sink.host.to_lowercase()) {
                skipped += 1;
                return None;
            }
            Some(Variant { class, authority, technique, note })
        })
        .collect();
    (list, skipped)
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
pub async fn run(include_results: bool, sink: &Sink) -> serde_json::Value {
    let (variants, skipped) = variants(sink);
    let mut results = Vec::with_capacity(variants.len());
    let (mut escaped, mut denied, mut rejected, mut connected, mut transport) = (0u32, 0u32, 0u32, 0u32, 0u32);
    let mut hostile = 0u32;
    let mut control_tried = 0u32;
    let mut control_connected = 0u32;
    let mut escapes: Vec<serde_json::Value> = Vec::new();

    for v in &variants {
        let path = if must_be_refused(&v.class) { "/collect" } else { "/ingest" };
        let attempt = egress::post(sink.https, &v.authority, path, PROBE_BODY.as_bytes().to_vec()).await;
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
        "allowed_host": sink.host,
        "sink_authority": sink.authority(),
        "scheme": sink.scheme(),
        "variants_tried": tried,
        "variants_skipped": skipped,
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
