//! PyO3 binding for rine's MLS core — the Rust half of PyPI `rine-mls`.
//!
//! The surface is deliberately the same shape as the napi binding's, method for
//! method, so `rine-core` and the Python SDK are two thin transports over one
//! implementation rather than two implementations that happen to agree today.
//! Only the spellings differ, and only where Python expects them to: snake_case
//! attributes, a constructor instead of a factory, keyword options instead of an
//! options object, an exception class per failure instead of an `Error.code`.
//!
//! What this layer adds over [`rine_mls_core`], and nothing else:
//!
//! - **typed, catchable errors** — an exception class per failure under one
//!   `RineMlsError` base, each carrying the same `RINE_MLS_*` wire code the
//!   JavaScript side sees (see [`error`]);
//! - **a panic firewall** — no Rust unwind reaches CPython, and a handle that
//!   panicked is retired rather than reused;
//! - **explicit byte ownership** — arguments are copied in, results are copied
//!   out as `bytes`, and no pointer into either heap outlives a call.
//!
//! Everything above the bytes stays in the transport: base64url, the HTTP calls,
//! the signed rine envelope. Everything below stays in the core: MLS itself, the
//! ciphersuites, the local state store, the KeyPackage and epoch-retention
//! policy, and the `0x04` `mls-v1` version tag — which lives in the core
//! precisely so this binding and the napi one cannot frame the same message two
//! different ways. The reasoning behind any of it belongs in the core's docs;
//! what is written here is what a Python caller has to know.
//!
//! Two exported surfaces are not MLS: [`mod@mlkem`] is raw ML-KEM-768 for the 1:1
//! `hpke-hybrid-v2` DM envelope, so the Python SDK's groups and its direct
//! messages run on one post-quantum implementation instead of two, and
//! [`mod@mldsa`] derives ML-DSA-65 public keys from seeds. Both also derive keys
//! from a seed for the org-root tree.
//!
//! All calls are synchronous and hold the GIL. mls-rs' storage traits are
//! synchronous and every operation is local CPU and local disk; an async wrapper
//! belongs in the Python SDK, over a thread executor, not here.
//!
//! **Threading.** The GIL means one handle is never mutated by two threads at
//! once, so sharing a handle between threads is safe if unexciting. Two
//! *clients* over the same store directory are a different matter: see the
//! warning on [`MlsClient`].

// The other ABI seam, held to the same rule as the napi one, and `deny` for the
// same forced reason plus one of its own: the build stamp below is a
// `#[no_mangle]` static, which the `unsafe_code` lint covers and which `forbid`
// leaves no way to exempt. See the note in `rine-mls-node`'s lib.rs.
#![deny(unsafe_code)]

mod allowed;
mod client;
mod epoch_reader;
mod error;
mod escrow;
mod group;
mod group_escrow;
mod group_update;
mod key_package_discard;
mod key_package_key;
mod mldsa;
mod mlkem;
mod options;
mod refusal;
mod types;

use pyo3::prelude::*;
use rine_mls_core::RineCipherSuite;

pub use allowed::AllowedIdentities;
pub use client::MlsClient;
pub use epoch_reader::EpochReader;
pub use escrow::{EscrowBacklog, EscrowExport, EscrowGap, EscrowGapReason, EscrowTake};
pub use group::MlsGroup;
pub use types::{AppMessage, CommitBundle, MemberIdentity, OpenedMessage};

/// Which release this extension module was compiled from, as a plain string in
/// the binary. The six published wheels are cross-compiled and only one of them
/// can be imported on the host that publishes them, so this is what
/// `scripts/verify-mls-artifacts.sh` reads out of each wheel's extension module
/// to refuse one left over from an earlier build. Exported so the linker keeps
/// it: it has no caller, and that is the point.
// The one exemption to the crate's `deny(unsafe_code)`, scoped to this item.
// A `#[no_mangle]` static is what the lint covers; the alternative is no build
// stamp, and `verify-mls-artifacts.sh` reads this string out of every shipped
// artifact to refuse a stale one.
#[allow(unsafe_code)]
#[no_mangle]
pub static RINE_MLS_BUILD_STAMP: &str = concat!("RINEMLS-BUILD/", env!("CARGO_PKG_VERSION"));

#[pymodule]
fn rine_mls(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MlsClient>()?;
    m.add_class::<MlsGroup>()?;
    m.add_class::<CommitBundle>()?;
    m.add_class::<AppMessage>()?;
    m.add_class::<MemberIdentity>()?;
    m.add_class::<EscrowExport>()?;
    m.add_class::<EscrowGapReason>()?;
    m.add_class::<EscrowGap>()?;
    m.add_class::<EscrowTake>()?;
    m.add_class::<EscrowBacklog>()?;
    m.add_class::<OpenedMessage>()?;
    m.add_class::<AllowedIdentities>()?;
    m.add_class::<EpochReader>()?;
    // Every constant is read off the core rather than restated, so the two
    // bindings cannot disagree about a protocol value or a policy number.
    // X-Wing is the only suite rine speaks; any other id is refused at client
    // construction.
    m.add("CIPHER_SUITE_XWING", RineCipherSuite::XWing.id())?;
    // The suite a NEW rine group is created with. Read this rather than
    // choosing a constant above.
    m.add("CIPHER_SUITE_DEFAULT", RineCipherSuite::DEFAULT.id())?;
    m.add("APP_MESSAGE_TAG", rine_mls_core::APP_MESSAGE_TAG)?;
    m.add("KEY_PACKAGE_TARGET", rine_mls_core::KEY_PACKAGE_TARGET)?;
    m.add(
        "KEY_PACKAGE_LOW_WATER",
        rine_mls_core::KEY_PACKAGE_LOW_WATER,
    )?;
    m.add(
        "KEY_PACKAGE_MAX_BATCH",
        rine_mls_core::KEY_PACKAGE_MAX_BATCH,
    )?;
    m.add(
        "SELF_READ_MAX_ENTRIES",
        rine_mls_core::SELF_READ_MAX_ENTRIES,
    )?;
    m.add("SELF_READ_MAX_BYTES", rine_mls_core::SELF_READ_MAX_BYTES)?;
    // Prior epochs kept when `epoch_retention_limit` is left unset, and the
    // server-side retention it is derived from.
    m.add(
        "EPOCH_RETENTION_DEFAULT",
        rine_mls_core::EPOCH_RETENTION_DEFAULT,
    )?;
    m.add(
        "MESSAGE_RETENTION_DAYS",
        rine_mls_core::MESSAGE_RETENTION_DAYS,
    )?;
    key_package_key::register(m)?;
    mlkem::register(m)?;
    mldsa::register(m)?;
    error::register(m)
}
