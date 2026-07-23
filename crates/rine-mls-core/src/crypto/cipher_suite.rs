//! Every method here forwards to a primitive assembled in the parent module and
//! computes nothing itself — the file is a line-by-line check of that claim.

use mls_rs_core::crypto::{
    CipherSuite, CipherSuiteProvider, HpkeCiphertext, HpkePsk, HpkePublicKey, HpkeSecretKey,
    SignaturePublicKey, SignatureSecretKey,
};
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_hpke::context::{ContextR, ContextS};
use mls_rs_crypto_rustcrypto::{aead::Aead, kdf::Kdf};
use mls_rs_crypto_traits::{AeadType, KdfType};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use super::error::RineCryptoError;
use super::RineCipherSuiteProvider;

impl CipherSuiteProvider for RineCipherSuiteProvider {
    type Error = RineCryptoError;
    type HpkeContextR = ContextR<Kdf, Aead>;
    type HpkeContextS = ContextS<Kdf, Aead>;

    fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.hash(data))
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.mac(key, data)?)
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead
            .seal(key, data, aad, nonce)
            .map_err(|e| RineCryptoError::Aead(e.into_any_error()))
    }

    fn aead_open(
        &self,
        key: &[u8],
        cipher_text: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.aead
            .open(key, cipher_text, aad, nonce)
            .map_err(|e| RineCryptoError::Aead(e.into_any_error()))
            .map(Zeroizing::new)
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .extract(salt, ikm)
            .map_err(|e| RineCryptoError::Kdf(e.into_any_error()))
            .map(Zeroizing::new)
    }

    fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf
            .expand(prk, info, len)
            .map_err(|e| RineCryptoError::Kdf(e.into_any_error()))
            .map(Zeroizing::new)
    }

    fn kdf_extract_size(&self) -> usize {
        self.kdf.extract_size()
    }

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        Ok(self.hpke.seal(remote_key, info, None, aad, pt)?)
    }

    fn hpke_seal_psk(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
        psk: HpkePsk<'_>,
    ) -> Result<HpkeCiphertext, Self::Error> {
        Ok(self.hpke.seal(remote_key, info, Some(psk), aad, pt)?)
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self
            .hpke
            .open(ciphertext, local_secret, local_public, info, None, aad)?)
    }

    fn hpke_open_psk(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        psk: HpkePsk<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self
            .hpke
            .open(ciphertext, local_secret, local_public, info, Some(psk), aad)?)
    }

    fn hpke_setup_r(
        &self,
        enc: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        Ok(self
            .hpke
            .setup_receiver(enc, local_secret, local_public, info, None)?)
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        Ok(self.hpke.setup_sender(remote_key, info, None)?)
    }

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        Ok(self.hpke.derive(ikm)?)
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        Ok(self.hpke.generate()?)
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(self.hpke.public_key_validate(key)?)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        OsRng.try_fill_bytes(out).map_err(RineCryptoError::Rand)
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.signer.sign(secret_key, data)?)
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(self.signer.verify(public_key, signature, data)?)
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        Ok(self.signer.signature_key_generate()?)
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        Ok(self.signer.signature_key_derive_public(secret_key)?)
    }
}
