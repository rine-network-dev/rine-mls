//! The rules rine runs for commit options leave the framing of messages as it
//! was: commits travel as public messages and application messages are padded
//! the way the stock rules pad them. The lengths below were recorded by running
//! the same exchange against the release before rine had rules of its own.

mod common;

use common::{group_id, TestAgent};
use mls_rs::{MlsMessage, WireFormat};
use rine_mls_core::RineCipherSuite;

const SUITE: RineCipherSuite = RineCipherSuite::DEFAULT;

#[test]
fn test_encryption_options_when_rine_rules_run_then_framing_matches_the_stock_rules() {
    let alice = TestAgent::new(1, SUITE);
    let bob = TestAgent::new(2, SUITE);
    let (mut group, bundle) = alice
        .client
        .create_group_with_members(
            &group_id(1),
            &[bob.client.generate_key_package().expect("key package")],
        )
        .expect("create with bob");

    assert_eq!(
        MlsMessage::from_bytes(&bundle.commit)
            .expect("a commit")
            .wire_format(),
        WireFormat::PublicMessage,
    );
    for (envelope_len, payload_len) in [(1, 175), (100, 271), (1000, 1359)] {
        let payload = group
            .encrypt_application_message(&vec![7; envelope_len])
            .expect("encrypt");
        assert_eq!(
            payload.len(),
            payload_len,
            "payload for {envelope_len} bytes"
        );
    }
}
