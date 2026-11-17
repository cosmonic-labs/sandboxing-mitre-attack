//! Live boundary probes: what does the runtime actually do with a name?
//!
//! Every attempt is a real filesystem call made from inside the sandbox, and
//! every result string is the runtime's own answer. A name is tried through two
//! routes:
//!
//!   std  the vulnerable viewer's path: `Path::join` + `std::fs` (via wasi-libc,
//!        which picks the preopen and hands the remainder to the host)
//!   raw  `wasi:filesystem` `open-at` / `stat-at` called directly on the preopen
//!        descriptor, with no libc path handling in between
//!
//! and with three operations each (read, list, stat). "Escaped" is decided by
//! content, not by trusting the error: before probing, the component inventories
//! everything really inside the preopen. A successful read must be byte-identical
//! to one of those files and a successful listing must equal one of those
//! directories. Anything else came from outside.
//!
//! Outside content is never echoed back. If a read ever returned bytes that are
//! not in the inventory, the report says so and withholds them, unless they are
//! the fuzz canary (a harmless marker that starts with `CANARY-`).

use std::fs;
use std::path::Path;

use serde::Serialize;
use wasip2::filesystem::types::{Descriptor, DescriptorFlags, DescriptorType, OpenFlags, PathFlags};

use crate::viewer::{self, CONFIG_ROOT};

/// Largest read a probe will pull back. The sample files are a few hundred bytes.
const MAX_READ: u64 = 1 << 20;

/// Everything that is really inside the preopen, gathered without following
/// symlinks.
pub struct Inventory {
    /// (path relative to the preopen, contents) for every regular file.
    pub files: Vec<(String, Vec<u8>)>,
    /// (path relative to the preopen, sorted entry names) for every directory.
    pub dirs: Vec<(String, Vec<String>)>,
    /// Number of symlinks found (the planted fuzz fixtures).
    pub symlinks: usize,
    /// Set when the walk itself failed (e.g. the volume is not mounted).
    pub error: Option<String>,
}

impl Inventory {
    pub fn gather() -> Self {
        let mut inv = Inventory { files: vec![], dirs: vec![], symlinks: 0, error: None };
        inv.walk(Path::new(CONFIG_ROOT), "");
        inv
    }

    fn walk(&mut self, dir: &Path, rel: &str) {
        let rd = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) => {
                if rel.is_empty() {
                    self.error = Some(e.to_string());
                }
                return;
            }
        };
        let mut names = Vec::new();
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let child_rel = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
            names.push(name);
            // `DirEntry::file_type` does not follow symlinks.
            match entry.file_type() {
                Ok(t) if t.is_symlink() => self.symlinks += 1,
                Ok(t) if t.is_dir() => self.walk(&entry.path(), &child_rel),
                Ok(_) => {
                    if let Ok(bytes) = fs::read(entry.path()) {
                        self.files.push((child_rel, bytes));
                    }
                }
                Err(_) => {}
            }
        }
        names.sort();
        self.dirs.push((if rel.is_empty() { ".".into() } else { rel.to_string() }, names));
    }
}

/// One operation's outcome.
pub struct Op {
    /// The call succeeded.
    pub ok: bool,
    /// The call succeeded AND returned something that is not inside the preopen.
    pub escaped: bool,
    /// Human-readable result: the runtime's error, or what came back.
    pub detail: String,
    /// The file contents, only when they are a file from inside the preopen.
    pub content: Option<Vec<u8>>,
}

impl Op {
    fn refused(err: impl std::fmt::Display) -> Self {
        Op { ok: false, escaped: false, detail: format!("refused: {err}"), content: None }
    }
}

/// read + list + stat through one route.
pub struct Route {
    pub read: Op,
    pub list: Op,
    pub stat: Op,
}

impl Route {
    pub fn escaped(&self) -> bool {
        self.read.escaped || self.list.escaped || self.stat.escaped
    }
    pub fn inside(&self) -> bool {
        self.read.ok || self.list.ok
    }
    /// A stat that succeeds while read and list are both refused would confirm
    /// that something exists where nothing should be nameable. Flag it.
    fn check_stat_leak(mut self) -> Self {
        if self.stat.ok && !self.read.ok && !self.list.ok {
            self.stat.escaped = true;
            self.stat.detail = format!(
                "ESCAPED (metadata leak): {} while read and list were refused",
                self.stat.detail
            );
        }
        self
    }
}

fn classify_read(bytes: Vec<u8>, inv: &Inventory) -> Op {
    if let Some((rel, _)) = inv.files.iter().find(|(_, b)| *b == bytes) {
        return Op {
            ok: true,
            escaped: false,
            detail: format!("inside: {} bytes, identical to {rel}", bytes.len()),
            content: Some(bytes),
        };
    }
    let detail = if bytes.starts_with(b"CANARY-") {
        let line = bytes.split(|b| *b == b'\n').next().unwrap_or(&[]);
        format!("ESCAPED: returned the canary from outside the preopen: {}", String::from_utf8_lossy(line))
    } else {
        format!(
            "ESCAPED: returned {} bytes that match no file inside the preopen (content withheld)",
            bytes.len()
        )
    };
    Op { ok: true, escaped: true, detail, content: None }
}

fn classify_list(mut names: Vec<String>, inv: &Inventory) -> Op {
    names.sort();
    if let Some((rel, _)) = inv.dirs.iter().find(|(_, n)| *n == names) {
        return Op {
            ok: true,
            escaped: false,
            detail: format!("inside: {} entries, identical to the listing of {rel}", names.len()),
            content: None,
        };
    }
    let canary = if names.iter().any(|n| n == "CANARY.txt") { ", including CANARY.txt" } else { "" };
    Op {
        ok: true,
        escaped: true,
        detail: format!(
            "ESCAPED: listed {} entries that match no directory inside the preopen{canary} (names withheld)",
            names.len()
        ),
        content: None,
    }
}

/// The vulnerable viewer's own route: join, then `std::fs`.
pub fn std_route(name: &[u8], inv: &Inventory) -> Route {
    let path = viewer::config_path(name);

    let read = match viewer::view(name) {
        Ok(bytes) => classify_read(bytes, inv),
        Err(e) => Op::refused(e),
    };

    let list = match fs::read_dir(&path) {
        Ok(rd) => {
            let mut names = Vec::new();
            let mut failed = None;
            for entry in rd {
                match entry {
                    Ok(e) => names.push(e.file_name().to_string_lossy().into_owned()),
                    Err(e) => {
                        failed = Some(e);
                        break;
                    }
                }
            }
            match failed {
                Some(e) => Op::refused(e),
                None => classify_list(names, inv),
            }
        }
        Err(e) => Op::refused(e),
    };

    let stat = match fs::metadata(&path) {
        Ok(m) => Op {
            ok: true,
            escaped: false,
            detail: format!("ok: {}, {} bytes", if m.is_dir() { "directory" } else { "file" }, m.len()),
            content: None,
        },
        Err(e) => Op::refused(e),
    };

    Route { read, list, stat }.check_stat_leak()
}

/// The preopen descriptor for `/var/app/config`, straight from the host.
fn preopen() -> Result<Descriptor, String> {
    wasip2::filesystem::preopens::get_directories()
        .into_iter()
        .find(|(_, path)| path == CONFIG_ROOT)
        .map(|(d, _)| d)
        .ok_or_else(|| format!("no preopen named {CONFIG_ROOT}"))
}

fn wasi_err(e: wasip2::filesystem::types::ErrorCode) -> String {
    format!("{} (wasi:filesystem error-code `{}`)", e.message(), e.name())
}

/// The direct route: `open-at` / `stat-at` on the preopen descriptor with the
/// name exactly as given. Only possible for valid UTF-8 (WIT `string`).
pub fn raw_route(name: &str, inv: &Inventory) -> Route {
    let root = match preopen() {
        Ok(d) => d,
        Err(e) => {
            return Route { read: Op::refused(&e), list: Op::refused(&e), stat: Op::refused(&e) };
        }
    };
    let follow = PathFlags::SYMLINK_FOLLOW;

    let read = match root.open_at(follow, name, OpenFlags::empty(), DescriptorFlags::READ) {
        Ok(file) => {
            let mut bytes = Vec::new();
            let mut failed = None;
            loop {
                match file.read(MAX_READ - bytes.len() as u64, bytes.len() as u64) {
                    Ok((chunk, eof)) => {
                        let empty = chunk.is_empty();
                        bytes.extend_from_slice(&chunk);
                        if eof || empty || bytes.len() as u64 >= MAX_READ {
                            break;
                        }
                    }
                    Err(e) => {
                        failed = Some(e);
                        break;
                    }
                }
            }
            match failed {
                Some(e) => Op::refused(wasi_err(e)),
                None => classify_read(bytes, inv),
            }
        }
        Err(e) => Op::refused(wasi_err(e)),
    };

    let list = match root.open_at(follow, name, OpenFlags::DIRECTORY, DescriptorFlags::READ) {
        Ok(dir) => match dir.read_directory() {
            Ok(stream) => {
                let mut names = Vec::new();
                let mut failed = None;
                loop {
                    match stream.read_directory_entry() {
                        Ok(Some(entry)) => names.push(entry.name),
                        Ok(None) => break,
                        Err(e) => {
                            failed = Some(e);
                            break;
                        }
                    }
                }
                match failed {
                    Some(e) => Op::refused(wasi_err(e)),
                    None => classify_list(names, inv),
                }
            }
            Err(e) => Op::refused(wasi_err(e)),
        },
        Err(e) => Op::refused(wasi_err(e)),
    };

    let stat = match root.stat_at(follow, name) {
        Ok(s) => Op {
            ok: true,
            escaped: false,
            detail: format!(
                "ok: {}, {} bytes",
                if matches!(s.type_, DescriptorType::Directory) { "directory" } else { "file" },
                s.size
            ),
            content: None,
        },
        Err(e) => Op::refused(wasi_err(e)),
    };

    Route { read, list, stat }.check_stat_leak()
}

// ---------------------------------------------------------------------------
// Environment report
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

#[derive(Serialize)]
pub struct PathProbe {
    pub path: String,
    pub looks_for: String,
    pub result: String,
}

#[derive(Serialize)]
pub struct WriteProbe {
    pub attempt: String,
    pub allowed: bool,
    pub result: String,
}

#[derive(Serialize)]
pub struct Environment {
    pub sandbox_root: &'static str,
    /// Every environment variable the component can see.
    pub env_vars: Vec<EnvVar>,
    /// Names of variables that look like credentials (KEY, TOKEN, SECRET, ...).
    pub secret_like_env_vars: Vec<String>,
    pub args: Vec<String>,
    pub cwd: String,
    /// Every directory the host preopened for this component.
    pub preopens: Vec<String>,
    /// What `read_dir("/")` returns.
    pub root_listing: String,
    /// `stat` only (never read) on well-known credential locations.
    pub credential_paths: Vec<PathProbe>,
    /// Is the mount really read-only? Attempts to create and to open for append.
    pub write_probes: Vec<WriteProbe>,
    pub verdict: String,
}

/// Well-known places credentials live on a host. Each is only `stat`ed.
const CREDENTIAL_PATHS: &[(&str, &str)] = &[
    ("/root/.ssh/id_rsa", "SSH private key (T1552.004)"),
    ("/root/.aws/credentials", "cloud credentials file (T1552.001)"),
    ("/root/.bash_history", "shell history (T1552.003)"),
    ("/etc/passwd", "account database (T1003.008)"),
    ("/etc/shadow", "password hashes (T1003.008)"),
    ("/proc/self/environ", "process environment"),
    ("/var/run/secrets/kubernetes.io/serviceaccount/token", "service-account token (T1528, T1552.007)"),
    ("/root/.config/gcloud/application_default_credentials.json", "application access token (T1528)"),
    ("/root/.mozilla/firefox", "browser password store (T1555.003)"),
    ("/root/Library/Keychains", "keychain (T1555.001)"),
    ("/home", "other users' home directories (T1083)"),
    ("/var/app", "the mount point's own parent (T1083)"),
];

pub fn environment() -> Environment {
    let env_vars: Vec<EnvVar> = std::env::vars_os()
        .map(|(k, v)| EnvVar {
            name: k.to_string_lossy().into_owned(),
            value: v.to_string_lossy().into_owned(),
        })
        .collect();
    let secret_like_env_vars: Vec<String> = env_vars
        .iter()
        .filter(|v| {
            let n = v.name.to_ascii_uppercase();
            ["KEY", "TOKEN", "SECRET", "PASS", "CRED", "AUTH", "AWS_", "PRIVATE"].iter().any(|m| n.contains(m))
        })
        .map(|v| v.name.clone())
        .collect();

    let preopens: Vec<String> = wasip2::filesystem::preopens::get_directories()
        .into_iter()
        .map(|(_, p)| p)
        .collect();

    let root_listing = match fs::read_dir("/") {
        Ok(rd) => {
            let mut names: Vec<String> =
                rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
            names.sort();
            format!("ok: {} entries: {names:?}", names.len())
        }
        Err(e) => format!("refused: {e}"),
    };

    let credential_paths = CREDENTIAL_PATHS
        .iter()
        .map(|(path, what)| PathProbe {
            path: (*path).to_string(),
            looks_for: (*what).to_string(),
            result: match fs::metadata(path) {
                Ok(_) => "EXISTS: this path is visible inside the sandbox".to_string(),
                Err(e) => format!("refused: {e}"),
            },
        })
        .collect::<Vec<_>>();

    let write_probes = write_probes();
    let writable = write_probes.iter().any(|w| w.allowed);
    let visible = credential_paths.iter().filter(|p| p.result.starts_with("EXISTS")).count();

    let verdict = format!(
        "{}: {} environment variable(s), {} that look like credentials; {} preopen(s): {:?}; \
         {} of {} well-known credential paths visible; mount is {}.",
        if secret_like_env_vars.is_empty() && visible == 0 { "NOTHING TO STEAL" } else { "EXPOSED" },
        env_vars.len(),
        secret_like_env_vars.len(),
        preopens.len(),
        preopens,
        visible,
        credential_paths.len(),
        if writable { "WRITABLE (read-only is not enforced)" } else { "read-only (every write attempt was refused)" },
    );

    Environment {
        sandbox_root: CONFIG_ROOT,
        env_vars,
        secret_like_env_vars,
        args: std::env::args().collect(),
        cwd: match std::env::current_dir() {
            Ok(p) => p.display().to_string(),
            Err(e) => format!("refused: {e}"),
        },
        preopens,
        root_listing,
        credential_paths,
        write_probes,
        verdict,
    }
}

/// Try to write inside the mount. If a probe file does get created it is
/// removed again straight away; no existing file is ever modified.
fn write_probes() -> Vec<WriteProbe> {
    let mut out = Vec::new();

    let probe = format!("{CONFIG_ROOT}/.write-probe");
    out.push(match fs::OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(f) => {
            drop(f);
            let _ = fs::remove_file(&probe);
            WriteProbe {
                attempt: format!("create {probe}"),
                allowed: true,
                result: "ALLOWED: probe file created (and removed again)".into(),
            }
        }
        Err(e) => WriteProbe { attempt: format!("create {probe}"), allowed: false, result: format!("refused: {e}") },
    });

    let existing = format!("{CONFIG_ROOT}/app.conf");
    out.push(match fs::OpenOptions::new().append(true).open(&existing) {
        // Opened for append only; nothing is written to it.
        Ok(_) => WriteProbe {
            attempt: format!("open {existing} for append"),
            allowed: true,
            result: "ALLOWED: opened for writing (nothing was written)".into(),
        },
        Err(e) => WriteProbe {
            attempt: format!("open {existing} for append"),
            allowed: false,
            result: format!("refused: {e}"),
        },
    });

    let dir = format!("{CONFIG_ROOT}/.write-probe-dir");
    out.push(match fs::create_dir(&dir) {
        Ok(()) => {
            let _ = fs::remove_dir(&dir);
            WriteProbe {
                attempt: format!("mkdir {dir}"),
                allowed: true,
                result: "ALLOWED: directory created (and removed again)".into(),
            }
        }
        Err(e) => WriteProbe { attempt: format!("mkdir {dir}"), allowed: false, result: format!("refused: {e}") },
    });

    out
}
