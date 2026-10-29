//! Helpers shared by the RFC 9420 vector tests: locating the vector files, and
//! building an `EpochReader` over the rine suite provider for a vector's
//! secrets. Suite 0x0003 and rine's 0xF057 share their AEAD, KDF, hash and
//! signature, and message protection never touches the KEM, so the RFC suite 3
//! vectors run on the rine provider with a suite 3 group context.

use mls_rs::group::{EpochReader, GroupContext};
use mls_rs::{CipherSuite, ProtocolVersion};
use mls_rs_core::crypto::{CipherSuiteProvider, CryptoProvider};
use rine_mls_core::RineCryptoProvider;
use serde_json::Value;

use super::fixture;

/// The `cases` of one RFC 9420 vector file, or `None` (with a note) when the
/// monorepo's `scripts/` directory is absent.
pub fn load_cases(file: &str) -> Option<Vec<Value>> {
    let vectors = fixture::load_json(&format!("scripts/vectors/mls-rfc9420/{file}"))?;

    Some(vectors["cases"].as_array().expect("cases").clone())
}

pub fn hex_field(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(value[field].as_str().expect("hex field")).expect("hex field")
}

pub fn provider() -> impl CipherSuiteProvider + Clone {
    RineCryptoProvider
        .cipher_suite_provider(CipherSuite::new(0xF057))
        .expect("rine suite")
}

/// A suite 3 group context with the given identifiers and hashes.
pub fn context(
    group_id: Vec<u8>,
    epoch: u64,
    tree_hash: Vec<u8>,
    transcript_hash: Vec<u8>,
) -> GroupContext {
    GroupContext {
        protocol_version: ProtocolVersion::MLS_10,
        cipher_suite: CipherSuite::new(3),
        group_id,
        epoch,
        tree_hash,
        confirmed_transcript_hash: transcript_hash.into(),
        extensions: Default::default(),
    }
}

/// A reader over `leaf_count` leaves that all record `signature_pub`.
pub fn reader(
    context: GroupContext,
    leaf_count: u32,
    sender_data_secret: &[u8],
    encryption_secret: &[u8],
    signature_pub: &[u8],
) -> EpochReader<impl CipherSuiteProvider + Clone> {
    let keys = (0..leaf_count).map(|leaf| (leaf, signature_pub.to_vec()));
    EpochReader::new(
        provider(),
        context,
        leaf_count,
        sender_data_secret,
        encryption_secret,
        keys,
    )
}
