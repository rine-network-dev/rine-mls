//! The RFC 9420 message-protection vectors, run through the vendored
//! `EpochReader`: the reader opens the vector's application message, checks its
//! framing signature, and refuses with the right error when the key, the epoch
//! or the message type is wrong.

mod common;

use common::rfc9420::{context, hex_field, load_cases, reader};
use mls_rs::error::MlsError;
use mls_rs::group::EpochReadError;
use mls_rs::MlsMessage;
use serde_json::Value;

/// The vectors are generated for a two-member group.
const LEAVES: u32 = 2;

/// Opens a named field of the case in a fresh reader (the ratchets are per
/// reader). The vector does not say which leaf signs, so every leaf records
/// the key.
fn open_reader(
    case: &Value,
    epoch_offset: u64,
    signature_pub: &[u8],
) -> impl FnMut(&str) -> Result<Vec<u8>, EpochReadError> {
    let context = context(
        hex_field(case, "group_id"),
        case["epoch"].as_u64().expect("epoch") + epoch_offset,
        hex_field(case, "tree_hash"),
        hex_field(case, "confirmed_transcript_hash"),
    );
    let mut reader = reader(
        context,
        LEAVES,
        &hex_field(case, "sender_data_secret"),
        &hex_field(case, "encryption_secret"),
        signature_pub,
    );
    let case = case.clone();

    move |field| {
        let message = MlsMessage::from_bytes(&hex_field(&case, field)).expect("parse the message");
        reader.open(&message).map(|opened| opened.application_data)
    }
}

#[test]
fn test_application_priv_when_signature_key_is_right_opens_to_the_vector_text() {
    let Some(cases) = load_cases("message-protection.json") else {
        return;
    };

    for case in &cases {
        let mut open = open_reader(case, 0, &hex_field(case, "signature_pub"));
        assert_eq!(
            open("application_priv").expect("opens"),
            hex_field(case, "application")
        );
    }
}

#[test]
fn test_handshake_priv_when_signature_key_is_right_is_refused_as_not_application() {
    let Some(cases) = load_cases("message-protection.json") else {
        return;
    };

    for case in &cases {
        for field in ["proposal_priv", "commit_priv"] {
            let mut open = open_reader(case, 0, &hex_field(case, "signature_pub"));
            let error = open(field).expect_err("a handshake message is not an application message");
            assert!(
                matches!(error, EpochReadError::Mls(MlsError::UnexpectedMessageType)),
                "{field}: {error:?}"
            );
        }
    }
}

#[test]
fn test_application_priv_when_signature_key_is_wrong_is_rejected() {
    let Some(cases) = load_cases("message-protection.json") else {
        return;
    };

    for case in &cases {
        let mut wrong = hex_field(case, "signature_pub");
        wrong[0] ^= 1;
        let mut open = open_reader(case, 0, &wrong);
        let error = open("application_priv").expect_err("a wrong key is refused");
        assert!(
            matches!(error, EpochReadError::Rejected { .. }),
            "{error:?}"
        );
    }
}

#[test]
fn test_application_priv_when_reader_epoch_is_wrong_is_refused() {
    let Some(cases) = load_cases("message-protection.json") else {
        return;
    };

    for case in &cases {
        let mut open = open_reader(case, 1, &hex_field(case, "signature_pub"));
        let error = open("application_priv").expect_err("a wrong epoch is refused");
        assert!(matches!(error, EpochReadError::Mls(_)), "{error:?}");
    }
}
