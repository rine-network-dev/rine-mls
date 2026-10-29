//! The `EpochReadSecrets` v1 plaintext: the bytes an escrow seals.
//!
//! ```text
//! u8      version            = 0x01
//! u16be   cipher_suite       = 0xF057
//! u32be   leaf_count         leaves in the ratchet tree at this epoch
//! [32]    sender_data_secret
//! [32]    encryption_secret  the secret-tree root
//! u32be   context_len
//! [context_len] group_context   RFC 9420 TLS encoding, public
//! u32be   n                  non-empty leaves
//! n * { u32be leaf_index, [32] leaf signature public key }   public
//! ```
//!
//! The two secrets decrypt every PrivateMessage of the epoch and nothing else;
//! the two public tails are what a reader needs to check the MLS framing
//! signatures. No other key of the epoch is part of it.

use mls_rs::group::{EpochReadSecrets, GroupContext};
use mls_rs_codec::{MlsDecode, MlsEncode};
use zeroize::Zeroizing;

use crate::error::{EscrowFault, Result, RineMlsError};
use crate::suite::RineCipherSuite;

const VERSION: u8 = 0x01;
const SECRET_LEN: usize = 32;
/// An Ed25519 public key, the only signature key the suite's credentials carry.
const KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
const U32_LEN: usize = 4;
/// `version`, `cipher_suite`, `leaf_count`, the two secrets and `context_len`.
const HEADER_LEN: usize = 1 + 2 + U32_LEN + 2 * SECRET_LEN + U32_LEN;

/// The client refuses to export a group context over this size.
pub const MAX_CONTEXT_LEN: usize = 1024;

/// Twice the server's `MAX_GROUP_MEMBERS` (500): stale leaves outlive seats, so
/// the tree can hold more occupied leaves than the group has members.
pub const MAX_LEAVES: usize = 1000;

/// The most leaves, empty ones included, a ratchet tree of `MAX_LEAVES`
/// occupied leaves can span: the next power of two above them, doubled for a
/// tree that has not yet been truncated. A reader sizes its secret tree from the
/// declared count, so an unbounded one is an allocation the sealed blob chooses.
pub const MAX_LEAF_COUNT: u32 = 2 * MAX_LEAVES.next_power_of_two() as u32;

/// A parsed plaintext, with its group context decoded.
pub(super) struct EscrowPlaintext {
    pub leaf_count: u32,
    pub sender_data_secret: Zeroizing<Vec<u8>>,
    pub encryption_secret: Zeroizing<Vec<u8>>,
    pub group_context: GroupContext,
    pub leaf_signature_keys: Vec<(u32, Vec<u8>)>,
}

/// Encode the exported secrets of one epoch.
pub(super) fn encode(
    suite: RineCipherSuite,
    secrets: &EpochReadSecrets,
) -> std::result::Result<Zeroizing<Vec<u8>>, EscrowFault> {
    let context = secrets
        .group_context()
        .mls_encode_to_vec()
        .map_err(|_| EscrowFault::UndecodableContext)?;
    let leaves: Vec<_> = secrets.leaf_signature_keys().collect();

    if context.len() > MAX_CONTEXT_LEN {
        return Err(EscrowFault::ContextTooLarge {
            len: context.len(),
            max: MAX_CONTEXT_LEN,
        });
    }

    if leaves.len() > MAX_LEAVES {
        return Err(EscrowFault::TooManyLeaves {
            count: leaves.len(),
            max: MAX_LEAVES,
        });
    }

    expect_len(secrets.sender_data_secret().len(), SECRET_LEN)?;
    expect_len(secrets.encryption_secret().len(), SECRET_LEN)?;
    for (_, key) in &leaves {
        expect_len(key.len(), KEY_LEN)?;
    }

    let mut out = Zeroizing::new(Vec::with_capacity(
        HEADER_LEN + context.len() + U32_LEN + (U32_LEN + KEY_LEN) * leaves.len(),
    ));

    out.push(VERSION);
    out.extend_from_slice(&suite.id().to_be_bytes());
    out.extend_from_slice(&secrets.leaf_count().to_be_bytes());
    out.extend_from_slice(secrets.sender_data_secret());
    out.extend_from_slice(secrets.encryption_secret());
    out.extend_from_slice(&(context.len() as u32).to_be_bytes());
    out.extend_from_slice(&context);
    out.extend_from_slice(&(leaves.len() as u32).to_be_bytes());

    for (leaf_index, key) in leaves {
        out.extend_from_slice(&leaf_index.to_be_bytes());
        out.extend_from_slice(key);
    }

    Ok(out)
}

fn expect_len(len: usize, expected: usize) -> std::result::Result<(), EscrowFault> {
    if len == expected {
        Ok(())
    } else {
        Err(EscrowFault::BadFieldLength { len, expected })
    }
}

pub(super) fn parse(suite: RineCipherSuite, bytes: &[u8]) -> Result<EscrowPlaintext> {
    let mut cursor = Cursor(bytes);

    let version = cursor.u8()?;
    if version != VERSION {
        return Err(EscrowFault::UnsupportedVersion(version).into());
    }

    let got = cursor.u16()?;
    if got != suite.id() {
        return Err(RineMlsError::UnsupportedCipherSuite { id: got });
    }

    let leaf_count = cursor.u32()?;
    if !leaf_count.is_power_of_two() || leaf_count > MAX_LEAF_COUNT {
        return Err(EscrowFault::InvalidLeafCount { leaf_count }.into());
    }
    let sender_data_secret = Zeroizing::new(cursor.take(SECRET_LEN)?.to_vec());
    let encryption_secret = Zeroizing::new(cursor.take(SECRET_LEN)?.to_vec());

    let context_len = cursor.u32()? as usize;
    if context_len > MAX_CONTEXT_LEN {
        return Err(EscrowFault::ContextTooLarge {
            len: context_len,
            max: MAX_CONTEXT_LEN,
        }
        .into());
    }

    let mut context = cursor.take(context_len)?;
    let group_context =
        GroupContext::mls_decode(&mut context).map_err(|_| EscrowFault::UndecodableContext)?;
    if !context.is_empty() {
        return Err(EscrowFault::UndecodableContext.into());
    }
    if group_context.cipher_suite != suite.mls_rs() {
        return Err(
            EscrowFault::ContextSuiteMismatch(group_context.cipher_suite.raw_value()).into(),
        );
    }

    let count = cursor.u32()? as usize;
    if count > MAX_LEAVES {
        return Err(EscrowFault::TooManyLeaves {
            count,
            max: MAX_LEAVES,
        }
        .into());
    }

    let mut leaf_signature_keys: Vec<(u32, Vec<u8>)> = Vec::with_capacity(count);
    for _ in 0..count {
        let leaf_index = cursor.u32()?;
        let key = cursor.take(KEY_LEN)?.to_vec();

        if leaf_index >= leaf_count || leaf_signature_keys.iter().any(|(i, _)| *i == leaf_index) {
            return Err(EscrowFault::InvalidLeaf {
                leaf_index,
                leaf_count,
            }
            .into());
        }

        leaf_signature_keys.push((leaf_index, key));
    }

    if !cursor.0.is_empty() {
        return Err(EscrowFault::TrailingBytes.into());
    }

    Ok(EscrowPlaintext {
        leaf_count,
        sender_data_secret,
        encryption_secret,
        group_context,
        leaf_signature_keys,
    })
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(len).ok_or(EscrowFault::Truncated)?;
        self.0 = tail;

        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
}
