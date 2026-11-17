//! Path-traversal sandbox demo: the VIEWER component (Cosmonic Desktop).
//!
//! A "config viewer" with a classic path-traversal bug (CWE-22): it joins a
//! user-supplied name onto `/var/app/config` and reads the result (see
//! `viewer.rs`, the line marked `// VULN:`). Asked for `../../root/.ssh/id_rsa`
//! it passes exactly that to the filesystem.
//!
//! The bug is not patched. The component is deliberately starved instead: its
//! only grant is one read-only directory preopened at `/var/app/config`,
//! `allowedHosts: []` means no network, and it exports no HTTP, so nothing
//! outside the host can reach it directly. The `web` component has the opposite
//! shape (HTTP + UI, no filesystem). Two sandboxes, two disjoint grant sets.
//!
//! Every result reported here is the runtime's real answer to a real call.

mod corpus;
mod probe;
mod viewer;

wit_bindgen::generate!({
    world: "viewer",
    path: "../wit",
    // Keep this crate's component-type section from colliding with any other.
    type_section_suffix: "path-demo-viewer",
    generate_all,
});

use exports::cosmonic::path_demo::viewing::Guest;
use probe::{Inventory, Route};
use serde::Serialize;
use viewer::CONFIG_ROOT;

struct Component;

export!(Component);

impl Guest for Component {
    fn run(mode: String, name: Vec<u8>) -> String {
        let json = match mode.as_str() {
            "read" => serde_json::to_string(&attempt(&name, &Inventory::gather())),
            "variant" => serde_json::to_string(&variant(&name)),
            "corpus" => serde_json::to_string(&corpus_listing()),
            "fuzz" => serde_json::to_string(&fuzz(true, host_hint(&name))),
            "env" => serde_json::to_string(&probe::environment()),
            "all" => serde_json::to_string(&all()),
            other => Ok(format!("{{\"error\":\"unknown mode {other:?}\"}}")),
        };
        json.unwrap_or_else(|e| format!("{{\"error\":\"serialize failed: {e}\"}}"))
    }
}

// ---------------------------------------------------------------------------
// One attempt
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct RouteReport {
    read: String,
    list: String,
    stat: String,
}

impl From<&Route> for RouteReport {
    fn from(r: &Route) -> Self {
        RouteReport { read: r.read.detail.clone(), list: r.list.detail.clone(), stat: r.stat.detail.clone() }
    }
}

#[derive(Serialize)]
struct Attempt {
    /// The name as requested (non-printable bytes shown as \xNN).
    requested: String,
    requested_bytes: usize,
    /// The path the vulnerable join produced, i.e. what was handed to the filesystem.
    joined_path: String,
    /// `refused`, `inside` or `ESCAPED`.
    outcome: &'static str,
    /// `std::fs` on the joined path: the viewer's own code path.
    std_fs: RouteReport,
    /// `wasi:filesystem` `open-at` on the preopen with the name as given.
    wasi_open_at: Option<RouteReport>,
    wasi_open_at_skipped: Option<&'static str>,
    /// File contents, only when they came from inside the preopen.
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    verdict: String,
}

fn attempt(name: &[u8], inv: &Inventory) -> Attempt {
    let std = probe::std_route(name, inv);
    let raw = std::str::from_utf8(name).ok().map(|s| probe::raw_route(s, inv));

    let escaped = std.escaped() || raw.as_ref().is_some_and(Route::escaped);
    let inside = std.inside() || raw.as_ref().is_some_and(Route::inside);
    let outcome = if escaped {
        "ESCAPED"
    } else if inside {
        "inside"
    } else {
        "refused"
    };

    let shown = display(name, 200);
    let verdict = match outcome {
        "ESCAPED" => format!(
            "ESCAPED: \"{shown}\" returned something from outside {CONFIG_ROOT}. This is a real finding: \
             record the variant and report it upstream."
        ),
        "inside" => {
            let what = [&std.read, &std.list]
                .into_iter()
                .chain(raw.iter().flat_map(|r| [&r.read, &r.list]))
                .find(|op| op.ok)
                .map(|op| op.detail.clone())
                .unwrap_or_default();
            format!("OK: \"{shown}\" resolved inside {CONFIG_ROOT} ({what}).")
        }
        _ => format!(
            "CONTAINED: \"{shown}\" went to the filesystem unmodified and the sandbox answered: {}. \
             Nothing outside {CONFIG_ROOT} was read.",
            std.read.detail.trim_start_matches("refused: ")
        ),
    };

    let content = std
        .read
        .content
        .as_ref()
        .or(raw.as_ref().and_then(|r| r.read.content.as_ref()))
        .map(|b| String::from_utf8_lossy(b).into_owned());

    Attempt {
        requested: shown,
        requested_bytes: name.len(),
        joined_path: display(viewer::config_path(name).as_os_str().as_encoded_bytes(), 240),
        outcome,
        std_fs: (&std).into(),
        wasi_open_at: raw.as_ref().map(Into::into),
        wasi_open_at_skipped: raw
            .is_none()
            .then_some("name is not valid UTF-8, so it cannot be passed as a WIT string"),
        content,
        verdict,
    }
}

/// Printable rendering of a byte name: `\xNN` for anything non-printable or
/// not UTF-8, truncated in the middle when long.
fn display(bytes: &[u8], max: usize) -> String {
    let mut s = String::new();
    for chunk in bytes.utf8_chunks() {
        for ch in chunk.valid().chars() {
            if ch.is_control() || ch == '\u{feff}' || ('\u{200b}'..='\u{202e}').contains(&ch) {
                let mut buf = [0u8; 4];
                for b in ch.encode_utf8(&mut buf).bytes() {
                    s.push_str(&format!("\\x{b:02x}"));
                }
            } else {
                s.push(ch);
            }
        }
        for b in chunk.invalid() {
            s.push_str(&format!("\\x{b:02x}"));
        }
    }
    let count = s.chars().count();
    if count <= max {
        return s;
    }
    let head: String = s.chars().take(max / 2).collect();
    let tail: String = s.chars().skip(count - max / 2).collect();
    format!("{head} …[{} bytes total]… {tail}", bytes.len())
}

// ---------------------------------------------------------------------------
// Corpus and fuzz
// ---------------------------------------------------------------------------

/// Try to learn the absolute HOST path of the canary's directory from inside
/// the sandbox, by reading the planted `links/outside-abs` symlink. Some corpus
/// names embed that path (`{OUT}`). The runtime is expected to refuse: a
/// symlink with an absolute target would leak the host's layout.
fn outside_dir_from_symlink() -> Result<String, String> {
    std::fs::read_link(format!("{CONFIG_ROOT}/links/outside-abs"))
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| format!("refused: {e}"))
}

/// The host path as supplied by the external harness (`fuzz/run.py --out`),
/// which knows it because it runs on the host. Empty means "not supplied".
fn host_hint(arg: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(arg).ok()?.trim();
    s.starts_with('/').then(|| s.to_string())
}

#[derive(Serialize)]
struct CorpusEntry {
    id: usize,
    class: String,
    technique: String,
    name: String,
    note: String,
}

fn corpus_listing() -> Vec<CorpusEntry> {
    corpus::load()
        .into_iter()
        .map(|v| CorpusEntry { id: v.id, class: v.class, technique: v.technique, name: v.spec, note: v.note })
        .collect()
}

#[derive(Serialize)]
struct VariantReport {
    id: usize,
    class: String,
    technique: String,
    /// The name as written in the corpus (escapes and tokens intact).
    name: String,
    note: String,
    /// `refused`, `inside`, `ESCAPED` or `skipped`.
    outcome: &'static str,
    /// Did this variant meet its class's assertion?
    pass: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<Attempt>,
}

fn run_variant(v: &corpus::Variant, out_dir: Option<&str>, inv: &Inventory) -> VariantReport {
    let base = |outcome, pass, attempt| VariantReport {
        id: v.id,
        class: v.class.clone(),
        technique: v.technique.clone(),
        name: v.spec.clone(),
        note: v.note.clone(),
        outcome,
        pass,
        attempt,
    };
    let Some(name) = corpus::expand(&v.spec, out_dir) else {
        // The name embeds the HOST path of the canary directory, which the
        // component cannot learn from inside the sandbox. The external harness
        // (fuzz/run.py) runs these, because it knows the path.
        return base("skipped", true, None);
    };
    let mut a = attempt(&name, inv);
    a.content = None;
    let pass = match v.class.as_str() {
        "control" => a.outcome == "inside" && a.std_fs.read.starts_with("inside"),
        _ => a.outcome != "ESCAPED",
    };
    base(a.outcome, pass, Some(a))
}

/// `arg` is the corpus id, optionally followed by a newline and the host path
/// of the canary directory (see `host_hint`).
fn variant(arg: &[u8]) -> serde_json::Value {
    let mut parts = arg.splitn(2, |b| *b == b'\n');
    let id = parts.next().and_then(|b| std::str::from_utf8(b).ok()).and_then(|s| s.trim().parse::<usize>().ok());
    let out_dir = parts.next().and_then(host_hint).or_else(|| outside_dir_from_symlink().ok());
    let variants = corpus::load();
    match id.and_then(|i| variants.get(i)) {
        Some(v) => {
            let inv = Inventory::gather();
            serde_json::to_value(run_variant(v, out_dir.as_deref(), &inv)).unwrap_or_default()
        }
        None => serde_json::json!({ "error": format!("no such variant; ids are 0..{}", variants.len()) }),
    }
}

#[derive(Serialize)]
struct FuzzReport {
    /// The one-line result shown on the page.
    line: String,
    variants_tried: usize,
    escaped: usize,
    refused: usize,
    resolved_inside: usize,
    /// Variants whose name embeds the host path of the canary directory. Only
    /// the external harness can build those names, so they are not counted in
    /// `variants_tried` unless the harness supplied the path.
    host_path_variants_skipped: usize,
    /// What reading the absolute symlink `links/outside-abs` returned: the
    /// component's own attempt to learn the host path.
    host_path_from_symlink: String,
    controls_ok: usize,
    controls_total: usize,
    /// read + list + stat, through each route, for each variant.
    filesystem_calls: usize,
    /// Were the symlink fixtures (fuzz/plant.sh) present in the mount?
    symlinks_planted: bool,
    symlinks_in_preopen: usize,
    files_in_preopen: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    inventory_error: Option<String>,
    /// Variants that failed their assertion (escapes, or controls that broke).
    failures: Vec<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    results: Vec<VariantReport>,
}

fn fuzz(with_results: bool, host_hint: Option<String>) -> FuzzReport {
    let inv = Inventory::gather();
    let from_symlink = outside_dir_from_symlink();
    let out_dir = host_hint.or_else(|| from_symlink.clone().ok());
    let results: Vec<VariantReport> =
        corpus::load().iter().map(|v| run_variant(v, out_dir.as_deref(), &inv)).collect();

    let count = |o: &str| results.iter().filter(|r| r.outcome == o).count();
    let skipped = count("skipped");
    let tried = results.len() - skipped;
    let escaped = count("ESCAPED");
    let controls_total = results.iter().filter(|r| r.class == "control").count();
    let controls_ok = results.iter().filter(|r| r.class == "control" && r.pass).count();
    let filesystem_calls = results
        .iter()
        .filter_map(|r| r.attempt.as_ref())
        .map(|a| if a.wasi_open_at.is_some() { 6 } else { 3 })
        .sum();

    let mut line = format!("{tried} variants tried, {escaped} escaped");
    if inv.symlinks == 0 {
        line.push_str(" (symlink fixtures not planted: run fuzz/plant.sh)");
    }
    if controls_ok != controls_total {
        line.push_str(&format!(" ({controls_ok}/{controls_total} controls served)"));
    }

    FuzzReport {
        line,
        variants_tried: tried,
        escaped,
        refused: count("refused"),
        resolved_inside: count("inside"),
        host_path_variants_skipped: skipped,
        host_path_from_symlink: match &from_symlink {
            Ok(_) => "ok: the symlink target (a host path) was readable".into(),
            Err(e) => e.clone(),
        },
        controls_ok,
        controls_total,
        filesystem_calls,
        symlinks_planted: inv.symlinks > 0,
        symlinks_in_preopen: inv.symlinks,
        files_in_preopen: inv.files.len(),
        inventory_error: inv.error,
        failures: results.iter().filter(|r| !r.pass).map(|r| r.id).collect(),
        results: if with_results { results } else { Vec::new() },
    }
}

// ---------------------------------------------------------------------------
// Everything at once
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct All {
    verdict: String,
    headline: Attempt,
    legitimate: Attempt,
    environment: probe::Environment,
    fuzz: FuzzReport,
}

fn all() -> All {
    let inv = Inventory::gather();
    let headline = attempt(b"../../root/.ssh/id_rsa", &inv);
    let legitimate = attempt(b"app.conf", &inv);
    let environment = probe::environment();
    let fuzz = fuzz(false, None);

    let contained = headline.outcome == "refused"
        && legitimate.outcome == "inside"
        && fuzz.escaped == 0
        && fuzz.failures.is_empty()
        && environment.secret_like_env_vars.is_empty();
    let verdict = format!(
        "{}: ../../root/.ssh/id_rsa -> {}; app.conf -> {}; {} environment variable(s), {} credential-like; \
         fuzz: {}.",
        if contained { "CONTAINED" } else { "NOT CONTAINED" },
        headline.std_fs.read,
        legitimate.std_fs.read,
        environment.env_vars.len(),
        environment.secret_like_env_vars.len(),
        fuzz.line,
    );
    All { verdict, headline, legitimate, environment, fuzz }
}
