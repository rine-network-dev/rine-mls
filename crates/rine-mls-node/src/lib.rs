//! napi-rs binding for rine's MLS core — the Rust half of npm `@rine-network/mls`.
//!
//! The surface is deliberately the same shape as the PyO3 binding's, method for
//! method, so `rine-core` and the Python SDK are two thin transports over one
//! implementation rather than two implementations that happen to agree today.
//!
//! What this layer adds over [`rine_mls_core`], and nothing else:
//!
//! - **typed, catchable errors** — every failure is a JS `Error` whose `code` is
//!   a stable `RINE_MLS_*` string (see [`error`]);
//! - **a panic firewall** — no Rust unwind reaches V8, and a handle that
//!   panicked is retired rather than reused;
//! - **explicit byte ownership** — arguments are copied in, results are moved
//!   out, and no pointer into either heap outlives a call.
//!
//! Everything above the bytes stays in the transport: base64url, the HTTP calls,
//! the signed rine envelope. Everything below stays in the core: MLS itself, the
//! ciphersuites, the local state store, the KeyPackage and epoch-retention
//! policy, and the `0x04` `mls-v1` version tag — which lives in the core
//! precisely so this binding and the Python one cannot frame the same message
//! two different ways. The reasoning behind any of it belongs in the core's
//! docs; what is written here is what a JavaScript caller has to know.
//!
//! All calls are synchronous. mls-rs' storage traits are synchronous and every
//! operation here is local CPU and local disk, so a thread hop would buy
//! latency, not throughput. If PQ key generation ever shows up in a Node event
//! loop profile, the fix is `AsyncTask` on the minting calls, not a redesign.
//!
//! **Threading.** A handle belongs to the thread that created it. Posting one
//! to a worker does not fail loudly — structured clone drops the prototype and
//! the native state, so the worker receives an inert plain object — which means
//! MLS state cannot travel between threads even by accident. A worker that needs
//! MLS opens its own client. Two clients over the *same* store directory are the
//! case worth reading about: see the warning on [`MlsClient`].

mod client;
mod error;
mod group;
mod options;
#[cfg(feature = "panic-probe")]
mod probe;
mod types;

use napi_derive::napi;
use rine_mls_core::RineCipherSuite;

pub use client::MlsClient;
pub use group::MlsGroup;
pub use options::MlsClientOptions;
pub use types::{AppMessage, CommitBundle};

/// The suite ids the server stores in `mls_cipher_suite`, read off the core
/// rather than restated, so the two can never disagree.
#[napi]
pub const CIPHER_SUITE_CLASSICAL: u16 = RineCipherSuite::Classical.id();

#[napi]
pub const CIPHER_SUITE_XWING: u16 = RineCipherSuite::XWing.id();

/// The suite a NEW rine group is created with. Read this rather than choosing
/// one of the two constants above: the default is decided once, in the core, so
/// the TypeScript and Python stacks cannot drift into creating groups of
/// different suites.
#[napi]
pub const CIPHER_SUITE_DEFAULT: u16 = RineCipherSuite::DEFAULT.id();

/// The `0x04` leading byte of an `mls-v1` `encrypted_payload`.
#[napi]
pub const APP_MESSAGE_TAG: u8 = rine_mls_core::APP_MESSAGE_TAG;

/// Published-KeyPackage inventory an agent is topped back up to.
#[napi]
pub const KEY_PACKAGE_TARGET: u32 = rine_mls_core::KEY_PACKAGE_TARGET as u32;

/// Inventory at or above which replenishment is a no-op.
#[napi]
pub const KEY_PACKAGE_LOW_WATER: u32 = rine_mls_core::KEY_PACKAGE_LOW_WATER as u32;

/// Largest batch one publish call may mint, so a top-up stays inside a single
/// request body.
#[napi]
pub const KEY_PACKAGE_MAX_BATCH: u32 = rine_mls_core::KEY_PACKAGE_MAX_BATCH as u32;

/// How many of its own sends a group keeps readable back.
#[napi]
pub const SELF_READ_MAX_ENTRIES: u32 = rine_mls_core::SELF_READ_MAX_ENTRIES as u32;

/// Plaintext budget of that same cache, in bytes.
#[napi]
pub const SELF_READ_MAX_BYTES: u32 = rine_mls_core::SELF_READ_MAX_BYTES as u32;
