//! The RFC 9420 secret-tree vectors, run through the vendored `EpochReader`.
//! The vectors carry keys and nonces but no ciphertexts, so each message is
//! sealed under the vector's key and nonce with a junk signature. The reader
//! can only return `Rejected` (AEAD opened, signature refused) if the key and
//! nonce it derived from the tree root, jumping from generation 0 to 15, are
//! the vector's.

mod common;

use common::rfc9420::{context, hex_field, load_cases, provider, reader};
use common::rfc9420_seal::{expand_with_label, seal_application};
use mls_rs::group::{EpochReadError, MAX_READER_SKIP};
use mls_rs::MlsMessage;

/// The back-history window upstream mls-rs keeps per leaf ratchet (RFC 9420 leaves it
/// to the implementation).
const MAX_RATCHET_BACK_HISTORY: u32 = 1024;
const GROUP_ID: [u8; 16] = [0x07; 16];
const EPOCH: u64 = 1;

#[test]
fn test_expand_with_label_when_given_the_vector_sample_derives_the_sender_data_key() {
    let Some(cases) = load_cases("secret-tree.json") else {
        return;
    };
    let provider = provider();

    for case in &cases {
        let sender_data = &case["sender_data"];
        let secret = hex_field(sender_data, "sender_data_secret");
        let ciphertext = hex_field(sender_data, "ciphertext");
        let sample = &ciphertext[..ciphertext.len().min(32)];

        assert_eq!(
            expand_with_label(&provider, &secret, "key", sample, 32),
            hex_field(sender_data, "key")
        );
        assert_eq!(
            expand_with_label(&provider, &secret, "nonce", sample, 12),
            hex_field(sender_data, "nonce")
        );
    }
}

#[test]
fn test_application_keys_when_sealed_with_the_vector_keys_open_up_to_the_signature_check() {
    let Some(cases) = load_cases("secret-tree.json") else {
        return;
    };
    let provider = provider();

    for case in &cases {
        let leaves = case["leaves"].as_array().expect("leaves");
        let sender_data_secret = hex_field(&case["sender_data"], "sender_data_secret");
        let context = context(GROUP_ID.to_vec(), EPOCH, vec![0; 32], vec![0; 32]);
        let mut reader = reader(
            context,
            leaves.len() as u32,
            &sender_data_secret,
            &hex_field(case, "encryption_secret"),
            &[0; 32],
        );

        for (leaf, generations) in leaves.iter().enumerate() {
            for entry in generations.as_array().expect("generations") {
                let generation = entry["generation"].as_u64().expect("generation") as u32;
                let sealed = seal_application(
                    &provider,
                    &GROUP_ID,
                    EPOCH,
                    &sender_data_secret,
                    leaf as u32,
                    generation,
                    &hex_field(entry, "application_key"),
                    &hex_field(entry, "application_nonce"),
                );
                let message = MlsMessage::from_bytes(&sealed).expect("parse the message");

                let error = reader
                    .open(&message)
                    .expect_err("the junk signature is refused");
                assert!(
                    matches!(error, EpochReadError::Rejected { sender, generation: g } if sender == leaf as u32 && g == generation),
                    "leaf {leaf} generation {generation}: {error:?}"
                );
            }
        }
    }
}

#[test]
fn test_reader_when_the_generation_is_at_the_reach_steps_and_one_past_it_is_refused() {
    let Some(cases) = load_cases("secret-tree.json") else {
        return;
    };
    let case = &cases[0];
    let provider = provider();
    let sender_data_secret = hex_field(&case["sender_data"], "sender_data_secret");
    let reach = MAX_RATCHET_BACK_HISTORY + MAX_READER_SKIP;

    let open_at = |generation: u32| {
        let context = context(GROUP_ID.to_vec(), EPOCH, vec![0; 32], vec![0; 32]);
        let mut reader = reader(
            context,
            case["leaves"].as_array().expect("leaves").len() as u32,
            &sender_data_secret,
            &hex_field(case, "encryption_secret"),
            &[0; 32],
        );
        let sealed = seal_application(
            &provider,
            &GROUP_ID,
            EPOCH,
            &sender_data_secret,
            0,
            generation,
            &[0; 32],
            &[0; 12],
        );

        reader
            .open(&MlsMessage::from_bytes(&sealed).expect("parse the message"))
            .expect_err("the junk key never opens")
    };

    assert!(
        matches!(open_at(reach + 1), EpochReadError::GenerationTooFar { generation } if generation == reach + 1),
        "one step past the reach is refused by name",
    );
    assert!(
        !matches!(open_at(reach), EpochReadError::GenerationTooFar { .. }),
        "the reach itself is walked, and only the junk key fails it",
    );
}
