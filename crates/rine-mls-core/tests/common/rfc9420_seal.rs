//! Builds RFC 9420 PrivateMessages (sections 6.3 and 9.1) from a known message
//! key and nonce, so the secret-tree vectors, which carry keys but no
//! ciphertexts, can be run through a reader. The signature inside is junk.

use mls_rs_core::crypto::CipherSuiteProvider;

const MLS_10: u16 = 1;
const WIRE_FORMAT_PRIVATE_MESSAGE: u16 = 2;
const CONTENT_TYPE_APPLICATION: u8 = 1;
const SIGNATURE_LEN: usize = 64;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// The MLS variable-length vector prefix, for lengths below 16384.
fn vlbytes(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len();
    let mut out = match len {
        0..=63 => vec![len as u8],
        64..=16383 => (0x4000 | len as u16).to_be_bytes().to_vec(),
        _ => panic!("a test vector value is never this long"),
    };
    out.extend_from_slice(bytes);
    out
}

/// RFC 9420 section 8: `HKDF-Expand(secret, KDFLabel, len)`.
pub fn expand_with_label(
    provider: &impl CipherSuiteProvider,
    secret: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let mut info = (len as u16).to_be_bytes().to_vec();
    info.extend(vlbytes(format!("MLS 1.0 {label}").as_bytes()));
    info.extend(vlbytes(context));

    provider
        .kdf_expand(secret, &info, len)
        .expect("expand")
        .to_vec()
}

/// An application PrivateMessage from `leaf` at `generation`, sealed under the
/// given content key and nonce, with a zero reuse guard and a junk signature.
#[allow(clippy::too_many_arguments)]
pub fn seal_application(
    provider: &impl CipherSuiteProvider,
    group_id: &[u8],
    epoch: u64,
    sender_data_secret: &[u8],
    leaf: u32,
    generation: u32,
    key: &[u8],
    nonce: &[u8],
) -> Vec<u8> {
    let mut content = vlbytes(b"vector text");
    content.extend(vlbytes(&[0x5a; SIGNATURE_LEN]));

    let mut aad = vlbytes(group_id);
    aad.extend(epoch.to_be_bytes());
    aad.push(CONTENT_TYPE_APPLICATION);
    aad.extend(vlbytes(&[]));
    let ciphertext = provider
        .aead_seal(key, &content, Some(&aad), nonce)
        .expect("seal content");

    let sample = &ciphertext[..ciphertext.len().min(KEY_LEN)];
    let sender_key = expand_with_label(provider, sender_data_secret, "key", sample, KEY_LEN);
    let sender_nonce = expand_with_label(provider, sender_data_secret, "nonce", sample, NONCE_LEN);

    let mut sender_data = leaf.to_be_bytes().to_vec();
    sender_data.extend(generation.to_be_bytes());
    sender_data.extend([0u8; 4]);

    let mut sender_aad = vlbytes(group_id);
    sender_aad.extend(epoch.to_be_bytes());
    sender_aad.push(CONTENT_TYPE_APPLICATION);
    let encrypted_sender_data = provider
        .aead_seal(&sender_key, &sender_data, Some(&sender_aad), &sender_nonce)
        .expect("seal sender data");

    let mut message = MLS_10.to_be_bytes().to_vec();
    message.extend(WIRE_FORMAT_PRIVATE_MESSAGE.to_be_bytes());
    message.extend(vlbytes(group_id));
    message.extend(epoch.to_be_bytes());
    message.push(CONTENT_TYPE_APPLICATION);
    message.extend(vlbytes(&[]));
    message.extend(vlbytes(&encrypted_sender_data));
    message.extend(vlbytes(&ciphertext));
    message
}
