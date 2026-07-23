//! rine's MLS group contract, over [mls-rs](https://github.com/awslabs/mls-rs).
//!
//! This crate owns exactly the RFC 9420 subset rine's group flow uses:
//!
//! - create a group, every commit carrying the ratchet tree extension
//! - join by Welcome, or self-join by external commit from a GroupInfo that
//!   carries `external_pub` + `ratchet_tree`
//! - Add and Remove as inline proposals on a commit
//! - PrivateMessage application messages wrapping a signed rine envelope
//! - strict `current + 1` epoch ordering, matching the server's epoch CAS
//! - file-backed local state, which is never sent to the server
//! - the KeyPackage pool an agent publishes, and its low-water replenishment
//! - the self-read cache, because MLS forward secrecy stops a sender decrypting
//!   its own message
//!
//! Not used, and deliberately absent: PSK, ReInit, resumption, Update on the
//! default path, x509 credentials, and required-capabilities customization.
//!
//! One surface here is not MLS at all: [`mlkem`] exposes raw ML-KEM-768 for the
//! 1:1 `hpke-hybrid-v1` DM envelope. It lives in this crate so rine has one
//! post-quantum implementation to audit and update, not one for groups and a
//! second for direct messages.
//!
//! Base64 belongs to the transport, not here: this crate speaks bytes. The one
//! framing it does own is the `0x04` `mls-v1` application-message version tag
//! ([`APP_MESSAGE_TAG`]), because both FFI bindings must agree on it byte for byte.
//!
//! Portability: no native-only dependency lives outside the crypto provider
//! seam, so the crate stays buildable for `wasm32` and every platform in the
//! release matrix.

mod client;
mod crypto;
mod epoch;
mod error;
mod ffi;
mod frame;
mod group;
mod identity;
pub mod mlkem;
mod policy;
mod store;
mod suite;
mod wire;
pub mod xwing;

pub use client::{RineMlsClient, RineMlsConfig, RineMlsOptions};
pub use crypto::{
    RineCipherSuiteProvider, RineCryptoError, RineCryptoProvider, RineKemError, XWING_KEM_ID,
};
pub use epoch::wire_epoch;
pub use error::{MlsBlobKind, Result, RineMlsError, RineMlsErrorCode};
pub use ffi::{Guarded, PanicGuard};
pub use frame::APP_MESSAGE_TAG;
pub use group::{AppMessage, CommitBundle, RineMlsGroup};
pub use identity::AgentSigningKey;
pub use policy::{
    key_package_shortfall, EpochRetention, KEY_PACKAGE_LOW_WATER, KEY_PACKAGE_MAX_BATCH,
    KEY_PACKAGE_TARGET,
};
pub use store::{
    FileGroupStateStorage, FileKeyPackageStorage, MlsStoreRoot, SelfReadCache, StoreError,
    SELF_READ_MAX_BYTES, SELF_READ_MAX_ENTRIES,
};
pub use suite::RineCipherSuite;
