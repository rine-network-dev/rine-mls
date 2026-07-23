use mls_rs::{MlsMessage, WireFormat};

use crate::error::{MlsBlobKind, Result, RineMlsError};
use crate::suite::RineCipherSuite;

/// Decode an MLS wire blob and assert two things about it: that it is the
/// artifact this call path expects, and that it belongs to the ciphersuite this
/// call path is operating in. A mis-routed or foreign-suite blob then fails
/// loudly at the boundary instead of surfacing as a confusing protocol error
/// several frames later.
///
/// The rine transport carries these blobs as base64 (control plane) or
/// base64url with a `0x04` version tag (application messages); both encodings
/// are peeled off by the caller, this layer only sees raw MLS bytes.
pub(crate) fn decode(
    bytes: &[u8],
    expected: MlsBlobKind,
    suite: RineCipherSuite,
) -> Result<MlsMessage> {
    let message = MlsMessage::from_bytes(bytes)?;
    let got = message.wire_format();

    let accepted = match expected {
        MlsBlobKind::KeyPackage => got == WireFormat::KeyPackage,
        MlsBlobKind::Welcome => got == WireFormat::Welcome,
        MlsBlobKind::GroupInfo => got == WireFormat::GroupInfo,
        // Member commits are PrivateMessage or PublicMessage; an external
        // commit is always PublicMessage (the sender is not yet a member).
        MlsBlobKind::Commit => {
            matches!(got, WireFormat::PublicMessage | WireFormat::PrivateMessage)
        }
        MlsBlobKind::ApplicationMessage => got == WireFormat::PrivateMessage,
    };

    if !accepted {
        return Err(RineMlsError::UnexpectedBlob { expected, got });
    }

    // Only KeyPackage, Welcome and GroupInfo name a ciphersuite on the wire; a
    // commit or an application message carries the group's suite implicitly and
    // fails to decrypt if it is wrong, which is the check itself.
    if let Some(got) = message.cipher_suite() {
        if got.raw_value() != suite.id() {
            return Err(RineMlsError::CipherSuiteMismatch {
                expected: suite.id(),
                got: got.raw_value(),
            });
        }
    }

    Ok(message)
}

/// Decode a KeyPackage claimed for `key_packages[index]` of an Add commit.
///
/// Every way of failing to *read* the blob collapses into one error, because
/// they all have the same remedy. rine publishes KeyPackages MLSMessage-framed;
/// the pre-cutover TypeScript stack published a bare RFC 9420 KeyPackage, which
/// this core cannot parse and deliberately does not accept. An
/// adder that meets one is not looking at a transport problem and must not walk
/// the peer's pool looking for a readable entry — every entry in a pre-cutover
/// pool is equally unreadable, so the retry only ends in an exhausted pool. The
/// peer has to drain and republish, and `index` says which member it is.
///
/// A blob of the right shape but the wrong ciphersuite is a different failure
/// with a different remedy, and keeps its own error.
pub(crate) fn decode_key_package(
    bytes: &[u8],
    index: usize,
    suite: RineCipherSuite,
) -> Result<MlsMessage> {
    match decode(bytes, MlsBlobKind::KeyPackage, suite) {
        Err(RineMlsError::Mls(_) | RineMlsError::UnexpectedBlob { .. }) => {
            Err(RineMlsError::UnreadableKeyPackage { index })
        }
        other => other,
    }
}
