//! Helpers shared by the escrow-reader tests: hand-decoding and rewriting an
//! `EpochReadSecrets` v1 plaintext from the layout in the interface note (an
//! independent decoder that never touches the crate's own parser), plus the
//! small group-driving conveniences those tests share.

use rine_mls_core::{EpochReader, EscrowExport, EscrowFault, RineMlsError, RineMlsGroup};

/// The offset of the leaf signature key table: the 71-byte fixed part, the
/// 4-byte context length, the context, and the 4-byte leaf count.
fn leaf_table_offset(plaintext: &[u8]) -> usize {
    let context_len = u32::from_be_bytes(plaintext[71..75].try_into().expect("4 bytes")) as usize;
    79 + context_len
}

/// The number of non-empty leaves the plaintext names.
fn leaf_count(plaintext: &[u8]) -> usize {
    let offset = leaf_table_offset(plaintext);
    u32::from_be_bytes(plaintext[offset - 4..offset].try_into().expect("4 bytes")) as usize
}

/// The byte offset of `leaf_index`'s entry in the table.
fn entry_offset(plaintext: &[u8], leaf_index: u32) -> usize {
    let mut offset = leaf_table_offset(plaintext);

    for _ in 0..leaf_count(plaintext) {
        let index = u32::from_be_bytes(plaintext[offset..offset + 4].try_into().expect("4 bytes"));
        if index == leaf_index {
            return offset;
        }
        offset += 36;
    }

    panic!("leaf {leaf_index} is not in the plaintext's table");
}

/// The 32-byte sender-data secret, right after the version, suite and leaf count.
pub fn sender_data_secret(plaintext: &[u8]) -> [u8; 32] {
    plaintext[7..39].try_into().expect("32 bytes")
}

/// The 32-byte signature key the plaintext records for `leaf_index`.
pub fn leaf_key(plaintext: &[u8], leaf_index: u32) -> [u8; 32] {
    let offset = entry_offset(plaintext, leaf_index);
    plaintext[offset + 4..offset + 36]
        .try_into()
        .expect("32 bytes")
}

/// Overwrite the signature key the plaintext records for `leaf_index`.
pub fn set_leaf_key(plaintext: &mut [u8], leaf_index: u32, key: &[u8; 32]) {
    let offset = entry_offset(plaintext, leaf_index);
    plaintext[offset + 4..offset + 36].copy_from_slice(key);
}

/// Swap the signature keys of two leaves.
pub fn swap_leaf_keys(plaintext: &mut [u8], a: u32, b: u32) {
    let (key_a, key_b) = (leaf_key(plaintext, a), leaf_key(plaintext, b));
    set_leaf_key(plaintext, a, &key_b);
    set_leaf_key(plaintext, b, &key_a);
}

/// Every export the group has installed since the last take.
pub fn take(group: &mut RineMlsGroup) -> Vec<EscrowExport> {
    let take = group.take_escrow_exports().expect("take");
    assert!(take.gaps.is_empty(), "unexpected gaps: {:?}", take.gaps);

    take.exports
}

/// The export for one epoch.
pub fn export(exports: &[EscrowExport], epoch: u64) -> &EscrowExport {
    exports
        .iter()
        .find(|e| e.epoch == epoch)
        .expect("epoch export")
}

/// A reader built from one epoch's plaintext.
pub fn reader(group_id: &[u8], epoch: u64, plaintext: &[u8]) -> EpochReader {
    EpochReader::from_escrow(group_id, epoch, plaintext).expect("reader")
}

/// Encrypt one envelope, returning `(payload, envelope)`.
pub fn send(group: &mut RineMlsGroup, text: &str) -> (Vec<u8>, Vec<u8>) {
    let envelope = text.as_bytes().to_vec();
    let payload = group
        .encrypt_application_message(&envelope)
        .expect("encrypt");

    (payload, envelope)
}

/// One application message a test sent and the facts a reader must report.
#[derive(Clone)]
pub struct Sent {
    pub sender: String,
    pub leaf: u32,
    pub generation: u32,
    pub envelope: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Three messages from each sender, returned in the shuffled order a reader
/// must open them in: generation 2 before 0 before 1 within each sender, the
/// senders interleaved.
pub fn out_of_order(senders: Vec<(&str, &mut RineMlsGroup)>) -> Vec<Sent> {
    let mut sent = Vec::new();
    for (name, group) in senders {
        let leaf = group.current_member_index().expect("index");
        for generation in 0..3u32 {
            let (payload, envelope) = send(group, &format!("{name} {generation}"));
            sent.push(Sent {
                sender: name.to_string(),
                leaf,
                generation,
                envelope,
                payload,
            });
        }
    }

    let order = [
        ("carol", 2),
        ("alice", 2),
        ("bob", 2),
        ("bob", 0),
        ("carol", 0),
        ("alice", 0),
        ("alice", 1),
        ("bob", 1),
        ("carol", 1),
    ];

    order
        .into_iter()
        .map(|(name, generation)| {
            sent.iter()
                .find(|m| m.sender == name && m.generation == generation)
                .cloned()
                .expect("sent message")
        })
        .collect()
}

/// Assert that building a reader from `plaintext` fails with `expected`.
fn refused(group_id: &[u8], epoch: u64, plaintext: &[u8], expected: fn(&RineMlsError) -> bool) {
    let error = match EpochReader::from_escrow(group_id, epoch, plaintext) {
        Ok(_) => panic!("expected the escrow to be refused"),
        Err(error) => error,
    };
    assert!(expected(&error), "unexpected error: {error}");
}

/// Every malformed-escrow case the reader must refuse by name: a slot for
/// another epoch or group, a version byte that is not 0x01, a leaf count that is
/// not a bounded power of two, a ciphersuite that is not rine's, a group context
/// naming another suite than the plaintext's, a plaintext cut short, and one
/// with a byte appended.
pub fn assert_malformed_refused(group_id: &[u8], epoch: u64, plaintext: &[u8]) {
    refused(group_id, epoch + 1, plaintext, |e| {
        matches!(e, RineMlsError::InvalidEscrow(EscrowFault::SlotMismatch))
    });
    refused(&[0xAA; 16], epoch, plaintext, |e| {
        matches!(e, RineMlsError::InvalidEscrow(EscrowFault::SlotMismatch))
    });

    let mut version = plaintext.to_vec();
    version[0] = 0x02;
    refused(group_id, epoch, &version, |e| {
        matches!(
            e,
            RineMlsError::InvalidEscrow(EscrowFault::UnsupportedVersion(2))
        )
    });

    for leaf_count in [0u32, 3, 4096, u32::MAX] {
        let mut sized = plaintext.to_vec();
        sized[3..7].copy_from_slice(&leaf_count.to_be_bytes());
        refused(group_id, epoch, &sized, |e| {
            matches!(
                e,
                RineMlsError::InvalidEscrow(EscrowFault::InvalidLeafCount { .. })
            )
        });
    }

    let mut suite = plaintext.to_vec();
    suite[1..3].copy_from_slice(&1u16.to_be_bytes());
    refused(group_id, epoch, &suite, |e| {
        matches!(e, RineMlsError::UnsupportedCipherSuite { id: 1 })
    });

    // The context starts after the 4-byte length at 71; its first two bytes are
    // the protocol version and the next two the context's own cipher suite.
    let mut context_suite = plaintext.to_vec();
    context_suite[77..79].copy_from_slice(&3u16.to_be_bytes());
    refused(group_id, epoch, &context_suite, |e| {
        matches!(
            e,
            RineMlsError::InvalidEscrow(EscrowFault::ContextSuiteMismatch(3))
        )
    });

    refused(group_id, epoch, &plaintext[..plaintext.len() - 1], |e| {
        matches!(e, RineMlsError::InvalidEscrow(EscrowFault::Truncated))
    });

    let mut extra = plaintext.to_vec();
    extra.push(0);
    refused(group_id, epoch, &extra, |e| {
        matches!(e, RineMlsError::InvalidEscrow(EscrowFault::TrailingBytes))
    });
}
