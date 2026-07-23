//! rine's `mls-v1` application-message framing.
//!
//! An `encryption_version: "mls-v1"` payload is a one-byte version tag followed
//! by the MLS PrivateMessage, so a receiver dispatches on the byte without
//! decoding the ciphertext. The tag lives here — in the one core both the napi
//! and the PyO3 binding call — so the TypeScript and Python stacks cannot drift
//! into two framings of the same wire format.
//!
//! Base64url stays in the transport: every host language already has it, and
//! it is the transport's business how bytes become a JSON string.

use crate::error::{Result, RineMlsError};

/// Leading byte of an `mls-v1` `encrypted_payload`, called `VERSION_MLS` in
/// rine's client stacks.
pub const APP_MESSAGE_TAG: u8 = 0x04;

/// `0x04 || PrivateMessage` — the bytes the transport base64url-encodes.
pub(crate) fn tag(ciphertext: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(1 + ciphertext.len());
    framed.push(APP_MESSAGE_TAG);
    framed.extend_from_slice(ciphertext);
    framed
}

/// Strip the version tag, refusing anything that is not an `mls-v1` payload.
pub(crate) fn untag(framed: &[u8]) -> Result<&[u8]> {
    match framed.split_first() {
        None => Err(RineMlsError::EmptyFrame),
        Some((&APP_MESSAGE_TAG, rest)) => Ok(rest),
        Some((&got, _)) => Err(RineMlsError::UnexpectedVersionTag {
            expected: APP_MESSAGE_TAG,
            got,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_untag_when_the_frame_carries_the_mls_tag_returns_the_ciphertext() {
        assert_eq!(untag(&tag(b"ciphertext")).unwrap(), b"ciphertext");
    }

    #[test]
    fn test_untag_when_the_frame_is_empty_is_refused() {
        assert!(matches!(untag(&[]).unwrap_err(), RineMlsError::EmptyFrame));
    }

    #[test]
    fn test_untag_when_the_tag_is_another_encryption_version_is_refused() {
        // 0x03 is the hpke-hybrid-v1 DM tag: a 1:1 envelope mis-routed onto the
        // group path must fail here, not several frames deeper.
        let err = untag(&[0x03, 0xAA]).unwrap_err();
        assert!(matches!(
            err,
            RineMlsError::UnexpectedVersionTag {
                expected: APP_MESSAGE_TAG,
                got: 0x03
            }
        ));
    }
}
