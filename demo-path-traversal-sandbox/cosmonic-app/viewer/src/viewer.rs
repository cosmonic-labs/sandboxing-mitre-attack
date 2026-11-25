//! The "config viewer": the vulnerable service this demo is about.
//!
//! It is a deliberately ordinary piece of code with a deliberately ordinary bug
//! (CWE-22, path traversal). It takes a file name from the request, joins it
//! onto the config directory and reads whatever that names. There is no
//! canonicalization, no `..` filter and no check that the result is still under
//! the config directory.
//!
//! It is NOT patched here. The mitigation is the sandbox: the component's only
//! filesystem authority is the single preopened directory `/var/app/config`,
//! so the joined path is resolved by the runtime against that one directory
//! and nothing else exists to be named.

use std::ffi::OsString;
use std::path::PathBuf;

/// The one directory this component is granted (a read-only volume mount).
pub const CONFIG_ROOT: &str = "/var/app/config";

/// Build the path the viewer will open for a user-supplied config name.
pub fn config_path(name: &[u8]) -> PathBuf {
    // The name arrives as raw bytes; WASI paths are byte strings, like Unix.
    let name = os_string(name);
    // VULN: (CWE-22) the user-supplied name is joined straight onto the config
    // directory. "../../root/.ssh/id_rsa" walks out of it, and an absolute name
    // such as "/root/.ssh/id_rsa" makes `join` discard the base entirely.
    PathBuf::from(CONFIG_ROOT).join(name)
}

/// Read a config file by name, exactly as the vulnerable service would.
pub fn view(name: &[u8]) -> std::io::Result<Vec<u8>> {
    std::fs::read(config_path(name))
}

#[cfg(target_os = "wasi")]
fn os_string(bytes: &[u8]) -> OsString {
    // SAFETY: on WASI, as on Unix, an `OsString` is an arbitrary byte string
    // with no encoding invariant, so any bytes are a valid value. (The safe
    // `std::os::wasi::ffi::OsStringExt::from_vec` is still unstable on wasip2.)
    unsafe { OsString::from_encoded_bytes_unchecked(bytes.to_vec()) }
}

#[cfg(unix)]
fn os_string(bytes: &[u8]) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(bytes.to_vec())
}

#[cfg(not(any(unix, target_os = "wasi")))]
fn os_string(bytes: &[u8]) -> OsString {
    OsString::from(String::from_utf8_lossy(bytes).into_owned())
}
