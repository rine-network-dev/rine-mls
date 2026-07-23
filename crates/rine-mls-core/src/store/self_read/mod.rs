//! How a sender reads back a group message it sent.
//!
//! MLS forward secrecy consumes the sender's ratchet step at encryption time,
//! so a member cannot decrypt its own application message — mls-rs refuses it
//! by name (`CantProcessMessageFromSelf`). No API can change that, so a sender
//! that has to show its own message in a thread has to have kept the plaintext
//! at the one moment it held it: the encrypt call.
//!
//! This cache is that keeping, and it lives in the core rather than in each
//! binding for a specific reason: the key must be the **framed payload bytes**
//! returned by the encrypt call. That is the one representation TypeScript and
//! Python hold identically — a cache keyed on the base64url string on one side
//! and on raw bytes on the other is two caches that agree until the day they do
//! not.
//!
//! Bounded by design. It holds plaintext, so it is not an archive: the newest
//! [`SELF_READ_MAX_ENTRIES`] messages, and never more than
//! [`SELF_READ_MAX_BYTES`] of plaintext, per group. Beyond that the oldest
//! entries go and a sender reading that far back gets a typed
//! `SelfMessageNotCached` rather than silence.

mod codec;

use std::path::{Path, PathBuf};

use codec::{decode, digest, encode, evict, Entry};

use super::{read_optional, write_private, MlsStoreRoot, Result, StoreError};

/// Newest messages a group's self-read cache holds. Matches the LRU depth the
/// TypeScript stack's `self-read-cache.json` shipped with.
pub const SELF_READ_MAX_ENTRIES: usize = 256;

/// Plaintext budget per group, on top of the entry count: a handful of large
/// envelopes must not turn the cache into megabytes of retained plaintext.
pub const SELF_READ_MAX_BYTES: usize = 1024 * 1024;

/// One agent's self-read caches, one file per group, alongside that group's
/// MLS state.
#[derive(Debug, Clone)]
pub struct SelfReadCache {
    root: MlsStoreRoot,
}

impl SelfReadCache {
    pub(crate) fn new(root: MlsStoreRoot) -> Self {
        Self { root }
    }

    fn path(&self, group_id: &[u8]) -> PathBuf {
        self.root.group_dir(group_id).join("self_read.bin")
    }

    /// Record the plaintext of a message this member just encrypted, keyed by
    /// the framed payload the transport is about to send.
    pub(crate) fn record(&self, group_id: &[u8], payload: &[u8], envelope: &[u8]) -> Result<()> {
        let path = self.path(group_id);
        let key = digest(payload);

        let mut entries = load(&path)?;
        entries.retain(|entry| entry.key != key);
        entries.push(Entry {
            key,
            envelope: envelope.to_vec(),
        });
        evict(&mut entries);

        write_private(&path, &encode(&entries))
    }

    /// The plaintext of a message this member sent, if the cache still holds it.
    pub(crate) fn lookup(&self, group_id: &[u8], payload: &[u8]) -> Result<Option<Vec<u8>>> {
        let key = digest(payload);

        Ok(load(&self.path(group_id))?
            .into_iter()
            .find(|entry| entry.key == key)
            .map(|entry| entry.envelope))
    }
}

/// An absent cache file is an empty cache — a group that has never had a send
/// from this member has nothing to read back. A file that is present but does
/// not parse is not empty, it is damaged, and says so.
fn load(path: &Path) -> Result<Vec<Entry>> {
    let Some(bytes) = read_optional(path)? else {
        return Ok(Vec::new());
    };

    decode(&bytes).ok_or_else(|| StoreError::Corrupt {
        path: path.to_path_buf(),
    })
}
