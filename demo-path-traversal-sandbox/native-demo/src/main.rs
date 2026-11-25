//! Native baseline: the same config viewer, with no sandbox.
//!
//! This runs the viewer's path join (the line marked `// VULN:`, identical to
//! `cosmonic-app/viewer/src/viewer.rs`) as an ordinary process and shows the
//! traversal working. It touches nothing real: it builds a throwaway directory
//! tree under the system temp directory, plants a FAKE "private key" holding
//! inert text beside the config directory, reads it back through the bug, and
//! deletes the tree again.
//!
//!     <tmp>/path-traversal-native-demo-<pid>/
//!       var/app/config/app.conf        the one file the viewer is meant to serve
//!       var/app/config/latest -> ...   a symlink planted inside the config dir
//!       var/root/.ssh/id_rsa           the fake key (inert text, not a key)
//!
//! It never opens a path outside that tree: no real `~/.ssh`, no `/etc`.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

/// Inert stand-in for a credential. Not a key; not key-shaped.
const FAKE_KEY: &str = "FAKE-PRIVATE-KEY (inert demo text, not a credential)\n\
this file stands in for /root/.ssh/id_rsa in the native baseline\n";

/// Build the path the viewer will open for a user-supplied config name.
fn config_path(config_root: &Path, name: &str) -> PathBuf {
    let name = OsString::from(name);
    // VULN: (CWE-22) the user-supplied name is joined straight onto the config
    // directory. "../../root/.ssh/id_rsa" walks out of it, and an absolute name
    // makes `join` discard the base entirely.
    config_root.join(name)
}

/// Read a config file by name, exactly as the vulnerable service would.
fn view(config_root: &Path, name: &str) -> std::io::Result<Vec<u8>> {
    fs::read(config_path(config_root, name))
}

fn main() -> std::io::Result<()> {
    let tree = std::env::temp_dir().join(format!("path-traversal-native-demo-{}", std::process::id()));
    let config = tree.join("var/app/config");
    let key = tree.join("var/root/.ssh/id_rsa");
    fs::create_dir_all(&config)?;
    fs::create_dir_all(key.parent().expect("key has a parent"))?;
    fs::write(config.join("app.conf"), "[server]\nlisten = 0.0.0.0:8080\n")?;
    fs::write(&key, FAKE_KEY)?;
    #[cfg(unix)]
    std::os::unix::fs::symlink("../../root/.ssh/id_rsa", config.join("latest"))?;

    println!("native baseline: the config viewer with NO sandbox");
    println!("throwaway tree:  {}", tree.display());
    println!("config root:     {}", config.display());
    println!("fake key:        {} (inert text)\n", key.display());

    let absolute = key.display().to_string();
    let requests: Vec<(&str, String)> = vec![
        ("legitimate", "app.conf".into()),
        ("dot-dot traversal", "../../root/.ssh/id_rsa".into()),
        ("absolute path", absolute),
        ("symlink inside the config dir", "latest".into()),
        ("symlink, with a ./ prefix", "./latest".into()),
    ];

    let mut leaked = 0;
    for (label, name) in &requests {
        let opened = config_path(&config, name);
        match view(&config, name) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                let first = text.lines().next().unwrap_or("");
                let is_key = bytes == FAKE_KEY.as_bytes();
                if is_key {
                    leaked += 1;
                }
                println!("[{label}]");
                println!("  requested: {name}");
                println!("  opened:    {}", opened.display());
                println!(
                    "  result:    {} ({} bytes): {first}\n",
                    if is_key { "LEAKED the fake key" } else { "served" },
                    bytes.len()
                );
            }
            Err(e) => {
                println!("[{label}]\n  requested: {name}\n  opened:    {}\n  result:    error: {e}\n", opened.display());
            }
        }
    }

    // The environment a native process inherits. Counts only: no names, no values.
    let total = std::env::vars_os().count();
    let secretish = std::env::vars_os()
        .filter(|(k, _)| {
            let k = k.to_string_lossy().to_ascii_uppercase();
            ["KEY", "TOKEN", "SECRET", "PASS", "CRED", "AUTH"].iter().any(|m| k.contains(m))
        })
        .count();
    println!(
        "environment: this process inherited {total} variables, {secretish} with credential-looking names \
         (counted only; names and values are not printed)."
    );

    fs::remove_dir_all(&tree)?;
    println!("removed {}\n", tree.display());

    if leaked > 0 {
        println!(
            "VULNERABLE: {leaked} of {} requests read the fake key from outside the config directory.",
            requests.len() - 1
        );
        println!("Same viewer code as the sandboxed component; the only difference is what it was handed.");
    } else {
        println!("no request leaked the fake key on this platform");
    }
    Ok(())
}
