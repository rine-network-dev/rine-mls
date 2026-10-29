//! The largest escrow a group can produce, and the server bound that must hold it.

mod common;

use common::scale::key_packages;
use common::TestAgent;
use rine_mls_core::{RineCipherSuite, MAX_CONTEXT_LEN, MAX_LEAVES};

const SUITE: RineCipherSuite = RineCipherSuite::DEFAULT;

/// Members admitted per commit: the server's cap on Welcomes in one commit.
const BATCH: usize = 32;

/// `version`, `cipher_suite`, `leaf_count`, the two secrets, `context_len`, `n`.
const FIXED_LEN: usize = 1 + 2 + 4 + 32 + 32 + 4 + 4;

/// `{ u32be leaf_index, [32] key }`.
const LEAF_ENTRY_LEN: usize = 4 + 32;

/// `hpke-hybrid-v2`: version byte, X25519 key, ML-KEM-768 ciphertext, GCM tag.
const SEAL_OVERHEAD: usize = 1 + 32 + 1088 + 16;

/// The server's `MAX_SEALED_BYTES` (`src/rine/api/mls_escrow_schemas.py`).
const SERVER_MAX_SEALED_BYTES: usize = 40960;

/// A group id length that puts a fresh group's context at exactly
/// `MAX_CONTEXT_LEN`: the context is the id plus fixed-size fields, and the id
/// length prefix is two bytes from 64 up. The probe reads the newest epoch, whose
/// context carries a transcript hash (epoch 0's is empty).
fn max_context_group_id_len() -> usize {
    const PROBE: usize = 100;
    let alice = TestAgent::new(1, SUITE);
    let (mut group, _) = alice.client.create_group(&[0xD0; PROBE]).expect("create");
    let export = group
        .take_escrow_exports()
        .expect("take")
        .exports
        .pop()
        .expect("an export");
    let context = export.plaintext.len() - FIXED_LEN - LEAF_ENTRY_LEN;

    PROBE + (MAX_CONTEXT_LEN - context)
}

#[test]
fn test_escrow_size_when_the_tree_is_full_and_the_context_maximal_the_sealed_blob_fits_the_server_bound(
) {
    let alice = TestAgent::new(1, SUITE);
    let id = vec![0xD1; max_context_group_id_len()];
    let (mut group, _) = alice.client.create_group(&id).expect("create");

    let mut leaves = 1usize;
    while leaves < MAX_LEAVES {
        let batch = BATCH.min(MAX_LEAVES - leaves);
        group
            .add_members(&key_packages(1000 + leaves as u32, batch, SUITE))
            .expect("add members");
        leaves += batch;
    }

    let take = group.take_escrow_exports().expect("take");
    assert!(
        take.gaps.iter().all(|g| g.epoch < group.epoch()),
        "the full epoch is not a gap"
    );
    let export = take.exports.last().expect("the full epoch is exported");
    assert_eq!(export.epoch, group.epoch());

    let expected = FIXED_LEN + MAX_CONTEXT_LEN + LEAF_ENTRY_LEN * MAX_LEAVES;
    assert_eq!(export.plaintext.len(), expected);
    assert_eq!(
        expected + SEAL_OVERHEAD,
        38240,
        "the worst case sealed blob"
    );
    assert!(expected + SEAL_OVERHEAD <= SERVER_MAX_SEALED_BYTES);
}
