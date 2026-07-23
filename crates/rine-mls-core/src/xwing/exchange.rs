//! The X-Wing exchange itself: the combiner, and the encapsulate/decapsulate
//! pair built on it.

use libcrux_ml_kem::mlkem768;
use zeroize::Zeroizing;

use super::{
    expand, split_encapsulation_key, Result, XWingError, CIPHERTEXT_SIZE, DECAPSULATION_KEY_SIZE,
    ENCAPSULATION_SEED_SIZE, LABEL, ML_KEM_CIPHERTEXT_SIZE, SHARED_SECRET_SIZE, X25519_SIZE,
};

/// `SHA3-256(ss_M || ss_X || ct_X || pk_X || label)`.
///
/// `ct_M` is deliberately absent: X-Wing leans on ML-KEM-768 already binding
/// its own ciphertext into `ss_M`, which is what makes the hybrid safe without
/// re-hashing the 1 kB ciphertext. Do not "fix" this by adding `ct_M` — it
/// would change every shared secret and break interoperability.
fn combiner(
    ss_m: &[u8; SHARED_SECRET_SIZE],
    ss_x: &[u8; X25519_SIZE],
    ct_x: &[u8; X25519_SIZE],
    pk_x: &[u8; X25519_SIZE],
) -> Zeroizing<[u8; SHARED_SECRET_SIZE]> {
    let mut input = Zeroizing::new([0u8; 4 * X25519_SIZE + LABEL.len()]);
    let mut at = 0;

    for part in [&ss_m[..], &ss_x[..], &ct_x[..], &pk_x[..], &LABEL[..]] {
        input[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }

    Zeroizing::new(libcrux_sha3::sha256(input.as_slice()))
}

/// Encapsulate to `pk` using `eseed` as the entire randomness input.
pub fn encapsulate(
    pk: &[u8],
    eseed: &[u8; ENCAPSULATION_SEED_SIZE],
) -> Result<(Zeroizing<[u8; SHARED_SECRET_SIZE]>, [u8; CIPHERTEXT_SIZE])> {
    let (pk_m, pk_x) = split_encapsulation_key(pk)?;
    let pk_m = mlkem768::MlKem768PublicKey::from(&pk_m);

    let mut ml_kem_randomness = Zeroizing::new([0u8; 32]);
    ml_kem_randomness.copy_from_slice(&eseed[..32]);
    let mut ek_x = Zeroizing::new([0u8; X25519_SIZE]);
    ek_x.copy_from_slice(&eseed[32..]);

    let (ct_m, ss_m) = mlkem768::encapsulate(&pk_m, *ml_kem_randomness);
    let ss_m = Zeroizing::new(ss_m);

    let ct_x = x25519_dalek::x25519(*ek_x, x25519_dalek::X25519_BASEPOINT_BYTES);
    let ss_x = Zeroizing::new(x25519_dalek::x25519(*ek_x, pk_x));

    let mut ct = [0u8; CIPHERTEXT_SIZE];
    ct[..ML_KEM_CIPHERTEXT_SIZE].copy_from_slice(ct_m.as_slice());
    ct[ML_KEM_CIPHERTEXT_SIZE..].copy_from_slice(&ct_x);

    Ok((combiner(&ss_m, &ss_x, &ct_x, &pk_x), ct))
}

/// Decapsulate `ct` with the decapsulation seed `sk`.
///
/// `pk_X` for the combiner is re-derived from the seed rather than taken from
/// any caller-supplied public key: a mismatched public key then produces a
/// different shared secret and fails authentication, instead of being trusted.
pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Result<Zeroizing<[u8; SHARED_SECRET_SIZE]>> {
    let sk: &[u8; DECAPSULATION_KEY_SIZE] = sk
        .try_into()
        .map_err(|_| XWingError::DecapsulationKeyLength(sk.len()))?;
    let ct: &[u8; CIPHERTEXT_SIZE] = ct
        .try_into()
        .map_err(|_| XWingError::CiphertextLength(ct.len()))?;

    let expanded = expand(sk);

    let mut ct_m = [0u8; ML_KEM_CIPHERTEXT_SIZE];
    ct_m.copy_from_slice(&ct[..ML_KEM_CIPHERTEXT_SIZE]);
    let mut ct_x = [0u8; X25519_SIZE];
    ct_x.copy_from_slice(&ct[ML_KEM_CIPHERTEXT_SIZE..]);

    let ss_m = Zeroizing::new(mlkem768::decapsulate(
        &expanded.sk_m,
        &mlkem768::MlKem768Ciphertext::from(&ct_m),
    ));
    let ss_x = Zeroizing::new(x25519_dalek::x25519(*expanded.sk_x, ct_x));

    Ok(combiner(&ss_m, &ss_x, &ct_x, &expanded.pk_x))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_when_read_as_bytes_is_the_six_byte_domain_separator() {
        assert_eq!(LABEL, &[0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
    }

    #[test]
    fn test_combiner_input_when_assembled_is_secrets_first_and_label_last() {
        let ss_m = [1u8; 32];
        let ss_x = [2u8; 32];
        let ct_x = [3u8; 32];
        let pk_x = [4u8; 32];

        let expected = [&ss_m[..], &ss_x, &ct_x, &pk_x, LABEL].concat();

        assert_eq!(
            combiner(&ss_m, &ss_x, &ct_x, &pk_x).as_slice(),
            &libcrux_sha3::sha256(&expected),
        );
    }

    #[test]
    fn test_encapsulate_when_key_is_wrong_length_is_refused() {
        assert_eq!(
            encapsulate(&[0u8; 32], &[0u8; ENCAPSULATION_SEED_SIZE]).unwrap_err(),
            XWingError::EncapsulationKeyLength(32),
        );
    }

    #[test]
    fn test_decapsulate_when_ciphertext_is_wrong_length_is_refused() {
        assert_eq!(
            decapsulate(&[0u8; 16], &[0u8; DECAPSULATION_KEY_SIZE]).unwrap_err(),
            XWingError::CiphertextLength(16),
        );
    }
}
