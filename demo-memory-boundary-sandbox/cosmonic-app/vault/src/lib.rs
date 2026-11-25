//! Memory-boundary sandbox demo — the VAULT component (Cosmonic Desktop).
//!
//! One job, exported over one custom interface: hold a secret in this
//! component's own linear memory and return it from `reveal()`.
//!
//! The secret is FAKE and inert — a labelled placeholder, not a credential. It
//! exists so the page can show that a sibling component (`parser`, which
//! handles the untrusted bytes) has no way to name this component's memory:
//! `parser`'s world has no imports, and each component gets its own linear
//! memory.
//!
//! This component has no grants: no volume, `allowedHosts: []`, and no HTTP
//! surface. Nothing outside the host can reach it; only `web` can, through the
//! runtime link.

wit_bindgen::generate!({
    world: "vault",
    path: "../wit",
    type_section_suffix: "memory-demo-vault",
    generate_all,
});

use exports::cosmonic::memory_demo::secrets::Guest;

/// The inert placeholder the vault holds. Not a real credential.
const SECRET: &str = "DEMO-ONLY-NOT-A-REAL-SECRET::vault-7f3a91c4";

struct Component;

export!(Component);

impl Guest for Component {
    fn reveal() -> String {
        SECRET.to_string()
    }
}
