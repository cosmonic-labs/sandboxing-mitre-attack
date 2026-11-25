//! The evasion corpus, compiled in from `fuzz/corpus.txt` so the component and
//! the external harness (`fuzz/run.py`) always test the same variants.

/// The corpus file, shared verbatim with the CLI harness.
pub const CORPUS_TXT: &str = include_str!("../../../fuzz/corpus.txt");

/// The symlink fixtures (`<name> <target>`), shared with `fuzz/plant.sh` and
/// the seeder component. The viewer only uses the names, to report which
/// fixtures are missing from the volume it was given.
pub const LINKS_TXT: &str = include_str!("../../../fuzz/links.txt");

/// Names of the fixture links expected under `links/`.
pub fn link_names() -> Vec<&'static str> {
    LINKS_TXT
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().next())
        .collect()
}

#[derive(Clone)]
pub struct Variant {
    pub id: usize,
    pub class: String,
    pub technique: String,
    /// The name exactly as written in the corpus (escapes and tokens intact).
    pub spec: String,
    pub note: String,
}

/// Parse the corpus: `<class> <technique> <name> <note...>`, `#` comments.
pub fn load() -> Vec<Variant> {
    let mut out = Vec::new();
    for line in CORPUS_TXT.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = split_fields(line);
        if fields.len() < 3 {
            continue;
        }
        out.push(Variant {
            id: out.len(),
            class: fields[0].to_string(),
            technique: fields[1].to_string(),
            spec: fields[2].to_string(),
            note: fields.get(3).copied().unwrap_or("").to_string(),
        });
    }
    out
}

/// Split a corpus line into three whitespace-delimited fields plus the rest.
fn split_fields(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut rest = line;
    for _ in 0..3 {
        rest = rest.trim_start();
        if rest.is_empty() {
            return fields;
        }
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        fields.push(&rest[..end]);
        rest = &rest[end..];
    }
    let note = rest.trim();
    if !note.is_empty() {
        fields.push(note);
    }
    fields
}

/// Expand a corpus name into the bytes handed to the viewer.
///
/// `out_dir` is the absolute host path of the canary's directory, if known.
/// Returns `None` when the name needs `{OUT}` and it is not known.
pub fn expand(spec: &str, out_dir: Option<&str>) -> Option<Vec<u8>> {
    let b = spec.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if b.get(i + 1) == Some(&b'x') && i + 3 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 2..i + 4]).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 4;
            }
            b'\\' if b.get(i + 1) == Some(&b'u') && b.get(i + 2) == Some(&b'{') => {
                let close = spec[i..].find('}')? + i;
                let cp = u32::from_str_radix(&spec[i + 3..close], 16).ok()?;
                let ch = char::from_u32(cp)?;
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                i = close + 1;
            }
            b'\\' if b.get(i + 1) == Some(&b'\\') => {
                out.push(b'\\');
                i += 2;
            }
            b'{' if spec[i..].starts_with("{OUT}") => {
                out.extend_from_slice(out_dir?.as_bytes());
                i += 5;
            }
            b'{' if spec[i..].starts_with("{REP:") => {
                let close = spec[i..].find('}')? + i;
                let body = &spec[i + 5..close];
                let (unit, count) = body.rsplit_once(':')?;
                let unit = expand(unit, out_dir)?;
                let count: usize = count.parse().ok()?;
                for _ in 0..count {
                    out.extend_from_slice(&unit);
                }
                i = close + 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    Some(out)
}
