//! Path-traversal sandbox demo: the SEEDER (a run-once workload service).
//!
//! The viewer's whole filesystem is one read-only volume. On Cosmonic Desktop
//! that volume can be a `hostPath` directory of sample files; on a cluster no
//! such directory exists, so the volume is `ephemeral` and starts empty. This
//! component fills it: the same volume is mounted here read-WRITE at `/seed`,
//! and `main` writes the inert sample tree into it, leaves a JSON summary of
//! what it did in `.seed-report.json` (also printed to stdout) and exits.
//!
//! It runs as the Workload's `service`, started by the host when the workload
//! starts, and is deliberately NOT linked to `web` or `viewer`. Components that
//! are linked through an interface are instantiated in one store, and each of
//! them then sees the volume mounts of all the others. A seeder that `web`
//! called would hand its writable mount to the vulnerable viewer. A service
//! that shares no interface gets its own store, so the write access stays here.
//!
//! What it writes is fixed at build time (`include_bytes!` of
//! `deploy/volume/config`, plus the symlink list in `fuzz/links.txt`). It reads
//! no request, no argument and no environment variable.
//!
//! The symlink fixtures are created as far as the runtime allows. A runtime
//! may refuse to create some of them (an absolute target, for instance). Each
//! refusal is recorded with the runtime's own error and never fails the seed.
//!
//! `app.conf` is written LAST. Its presence is the signal the other components
//! use to know the tree is complete (`viewing.run("ready")`).

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Where the config volume is mounted in THIS component (read-write).
const SEED_ROOT: &str = "/seed";

/// Written last: its presence means the rest of the tree is in place.
const LAST: &str = "app.conf";

/// The summary of this run, left in the volume so it can be read back through
/// the viewer (`/run?mode=seed-report`). Written only when this run seeded.
const REPORT: &str = ".seed-report.json";

/// The sample files, byte-identical to `deploy/volume/config` in the repo.
/// `café.conf` is written with a precomposed (NFC) e-acute, as the corpus expects.
const FILES: &[(&str, &[u8])] = &[
    ("database.conf", include_bytes!("../../../deploy/volume/config/database.conf")),
    ("profiles/staging.conf", include_bytes!("../../../deploy/volume/config/profiles/staging.conf")),
    ("profiles/caf\u{e9}.conf", include_bytes!("../../../deploy/volume/config/profiles/café.conf")),
    (LAST, include_bytes!("../../../deploy/volume/config/app.conf")),
];

/// The symlink fixtures, shared with `fuzz/plant.sh` and the viewer.
const LINKS_TXT: &str = include_str!("../../../fuzz/links.txt");

/// `{OUT}` in a link target. `fuzz/plant.sh` uses the host path of the canary
/// directory; from inside a sandbox there is no host path to use, so absolute
/// targets point at this name, which exists nowhere.
const OUT_PLACEHOLDER: &str = "/outside";

fn main() {
    let report = seed();
    match serde_json::to_string(&report) {
        Ok(json) => println!("path-traversal-seeder: {json}"),
        Err(e) => println!("path-traversal-seeder: {{\"status\":\"error\",\"errors\":[\"serialize failed: {e}\"]}}"),
    }
}

#[derive(Serialize)]
struct Refused {
    name: String,
    target: String,
    /// The runtime's own error for the `symlink-at` call.
    error: String,
}

#[derive(Serialize, Default)]
struct Report {
    /// `seeded` (this run wrote the tree), `already-seeded` (nothing to do) or
    /// `error` (something could not be written; see `errors`).
    status: &'static str,
    /// This component's mount of the volume.
    root: &'static str,
    /// Files written by this run.
    files_written: Vec<String>,
    /// Symlinks created by this run.
    links_created: Vec<String>,
    /// Symlinks the runtime refused to create in this run.
    links_refused: Vec<Refused>,
    /// Fixture links that exist in the volume now.
    links_present: Vec<String>,
    /// Fixture links that do not exist in the volume now.
    links_absent: Vec<String>,
    errors: Vec<String>,
}

fn links() -> Vec<(String, String)> {
    LINKS_TXT
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let (name, target) = l.split_once(char::is_whitespace)?;
            Some((name.to_string(), target.trim().replace("{OUT}", OUT_PLACEHOLDER)))
        })
        .collect()
}

fn root(rel: &str) -> PathBuf {
    Path::new(SEED_ROOT).join(rel)
}

fn identical(rel: &str, bytes: &[u8]) -> bool {
    fs::read(root(rel)).is_ok_and(|b| b == bytes)
}

/// Is the tree already complete? Every sample file byte-identical and `links/`
/// present. True on a hostPath volume that already holds the sample directory,
/// in which case nothing is written at all.
fn complete() -> bool {
    FILES.iter().all(|(rel, bytes)| identical(rel, bytes)) && root("links").is_dir()
}

fn seed() -> Report {
    let mut r = Report { status: "already-seeded", root: SEED_ROOT, ..Report::default() };

    let seeding = !complete();
    let (last, rest): (Vec<_>, Vec<_>) = FILES.iter().partition(|(rel, _)| *rel == LAST);
    if seeding {
        for (rel, bytes) in rest {
            write_file(rel, bytes, &mut r);
        }
        write_links(&mut r);
    }

    for (name, _) in links() {
        if fs::symlink_metadata(root("links").join(&name)).is_ok() {
            r.links_present.push(name);
        } else {
            r.links_absent.push(name);
        }
    }

    if seeding {
        r.status = if r.errors.is_empty() { "seeded" } else { "error" };
        // `app.conf` goes last, and only if everything before it worked: it is
        // the "tree is complete" signal. The report is written just before it.
        if r.errors.is_empty() {
            // The report on disk lists `app.conf` as written because it is
            // written immediately after; if that write fails the report is
            // moot, since nothing reads the volume until `app.conf` exists.
            let written = r.files_written.clone();
            r.files_written.push(LAST.to_string());
            if let Ok(json) = serde_json::to_vec(&r) {
                if let Err(e) = fs::write(root(REPORT), json) {
                    r.errors.push(format!("write {REPORT}: {e}"));
                }
            }
            r.files_written = written;
            for (rel, bytes) in last {
                write_file(rel, bytes, &mut r);
            }
            if !r.errors.is_empty() {
                r.status = "error";
            }
        }
    }
    r
}

fn write_file(rel: &str, bytes: &[u8], r: &mut Report) {
    if identical(rel, bytes) {
        return;
    }
    let path = root(rel);
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            r.errors.push(format!("mkdir {}: {e}", parent.display()));
            return;
        }
    }
    match fs::write(&path, bytes) {
        Ok(()) => r.files_written.push(rel.to_string()),
        Err(e) => r.errors.push(format!("write {rel}: {e}")),
    }
}

fn write_links(r: &mut Report) {
    if let Err(e) = fs::create_dir_all(root("links")) {
        r.errors.push(format!("mkdir links: {e}"));
        return;
    }
    let preopen = wasip2::filesystem::preopens::get_directories()
        .into_iter()
        .find(|(_, path)| path == SEED_ROOT)
        .map(|(d, _)| d);
    let Some(preopen) = preopen else {
        r.errors.push(format!("no preopen named {SEED_ROOT}"));
        return;
    };
    for (name, target) in links() {
        if fs::symlink_metadata(root("links").join(&name)).is_ok() {
            continue;
        }
        // One link refused is recorded, not fatal: the rest are still created.
        match preopen.symlink_at(&target, &format!("links/{name}")) {
            Ok(()) => r.links_created.push(name),
            Err(e) => r.links_refused.push(Refused {
                name,
                target,
                error: format!("{} (wasi:filesystem error-code `{}`)", e.message(), e.name()),
            }),
        }
    }
}
