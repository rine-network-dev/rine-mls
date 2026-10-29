// rine patch, described in PATCH.md: not part of upstream mls-rs 0.55.2.

use alloc::vec::Vec;

use mls_rs_core::crypto::{CipherSuiteProvider, SignaturePublicKey};

use super::{
    ciphertext_processor::CiphertextProcessor,
    epoch::{EpochSecrets, PriorEpoch},
    framing::Content,
    message_verifier::{verify_auth_content_signature, SignaturePublicKeysContainer},
    secret_tree::{KeyType, SecretTree},
    GroupContext,
};
use crate::{client::MlsError, tree_kem::node::LeafIndex, MlsMessage};

#[cfg(feature = "psk")]
use crate::psk::PreSharedKey;

/// Why [`EpochReader::open`] returned no message.
#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum EpochReadError {
    /// The AEAD opened, but the framing signature does not verify under the key
    /// the epoch records for the leaf the sender data names. Every member
    /// refuses such a message, so it is not the sender's text.
    #[cfg_attr(
        feature = "std",
        error("framing signature of leaf {sender} generation {generation} does not verify")
    )]
    Rejected { sender: u32, generation: u32 },
    /// The sender data names a generation more than
    /// [`super::MAX_READER_SKIP`] steps past the sender's ratchet. A member chose that
    /// number, and honouring it would cost the reader that many key
    /// derivations, so it is refused before any is spent.
    #[cfg_attr(
        feature = "std",
        error("generation {generation} is too far ahead of the sender's ratchet")
    )]
    GenerationTooFar { generation: u32 },
    #[cfg_attr(feature = "std", error(transparent))]
    Mls(MlsError),
}

impl From<MlsError> for EpochReadError {
    fn from(error: MlsError) -> Self {
        Self::Mls(error)
    }
}

/// An application message opened by an [`EpochReader`], signature checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedMessage {
    pub sender: u32,
    pub generation: u32,
    /// The signature public key the epoch records for `sender`, the one the framing signature
    /// verified under. A consumer that binds the sender to an agent compares this key.
    pub signer_public_key: Vec<u8>,
    pub authenticated_data: Vec<u8>,
    pub application_data: Vec<u8>,
}

/// Opens the PrivateMessages of one epoch from its [`EpochReadSecrets`], as a
/// member that was never part of the group: it holds the sender-data secret and
/// the secret-tree root, nothing else.
///
/// It is the member decrypt path, not a copy of it: the same
/// `CiphertextProcessor::open` and the same framing-signature verification a
/// member runs on a prior epoch, over a [`PriorEpoch`] built from the secrets.
///
/// [`EpochReadSecrets`]: super::EpochReadSecrets
pub struct EpochReader<P: CipherSuiteProvider> {
    epoch: PriorEpoch,
    cipher_suite_provider: P,
}

impl<P: CipherSuiteProvider + Clone> EpochReader<P> {
    /// `leaf_signature_keys` are `(leaf index, signature public key)` of the
    /// non-empty leaves. The reader's own leaf index is `u32::MAX`: `open`
    /// refuses a message whose sender is the provider's own index, and no real
    /// leaf has that one.
    pub fn new(
        cipher_suite_provider: P,
        group_context: GroupContext,
        leaf_count: u32,
        sender_data_secret: &[u8],
        encryption_secret: &[u8],
        leaf_signature_keys: impl IntoIterator<Item = (u32, Vec<u8>)>,
    ) -> Self {
        let mut signature_public_keys = Vec::new();
        signature_public_keys.resize(leaf_count as usize, None);

        for (leaf_index, key) in leaf_signature_keys {
            if let Some(slot) = signature_public_keys.get_mut(leaf_index as usize) {
                *slot = Some(SignaturePublicKey::from(key));
            }
        }

        let secrets = EpochSecrets {
            #[cfg(feature = "psk")]
            resumption_secret: PreSharedKey::new(Vec::new()),
            sender_data_secret: sender_data_secret.to_vec().into(),
            secret_tree: SecretTree::new(leaf_count, encryption_secret.to_vec().into()),
        };

        Self {
            epoch: PriorEpoch {
                context: group_context,
                self_index: LeafIndex::unchecked(u32::MAX),
                secrets,
                signature_public_keys,
                #[cfg(feature = "prior_epoch_membership_key")]
                membership_key: Default::default(),
            },
            cipher_suite_provider,
        }
    }

    /// Opens an application message of this epoch.
    ///
    /// A generation more than 1024 ahead of the sender's ratchet is reached by
    /// stepping the ratchet forward first, which is what a member does one
    /// message at a time, up to [`super::MAX_READER_SKIP`] more steps
    /// ([`EpochReadError::GenerationTooFar`] beyond that). The steps are not
    /// kept, so after a jump the messages of one sender that fall behind the
    /// 1024 window cannot be opened: feed each sender's messages in ascending
    /// generation order.
    ///
    /// Like a member, the reader consumes the generation's key before it checks
    /// the framing signature, so a forged message burns that generation: the
    /// sender's genuine message at the same generation then fails to open.
    #[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
    pub async fn open(&mut self, message: &MlsMessage) -> Result<OpenedMessage, EpochReadError> {
        let ciphertext = message
            .clone()
            .into_ciphertext()
            .ok_or(MlsError::UnexpectedMessageType)?;

        if ciphertext.group_id != self.epoch.context.group_id {
            return Err(MlsError::GroupIdMismatch.into());
        }

        if ciphertext.epoch != self.epoch.context.epoch {
            return Err(MlsError::InvalidEpoch.into());
        }

        if ciphertext.content_type != super::ContentType::Application {
            return Err(MlsError::UnexpectedMessageType.into());
        }

        let sender_data =
            CiphertextProcessor::new(&mut self.epoch, self.cipher_suite_provider.clone())
                .open_sender_data(&ciphertext)
                .await?;

        let sender = *sender_data.sender;
        let generation = sender_data.generation;

        if sender as usize >= self.epoch.signature_public_keys.len() {
            return Err(MlsError::LeafNotFound(sender).into());
        }

        self.epoch
            .secrets
            .secret_tree
            .skip_forward(
                &self.cipher_suite_provider,
                sender_data.sender.into(),
                KeyType::Application,
                generation,
            )
            .await
            .map_err(|error| match error {
                MlsError::InvalidFutureGeneration(generation) => {
                    EpochReadError::GenerationTooFar { generation }
                }
                other => EpochReadError::Mls(other),
            })?;

        let content = CiphertextProcessor::new(&mut self.epoch, self.cipher_suite_provider.clone())
            .open(&ciphertext)
            .await?;

        verify_auth_content_signature(
            &self.cipher_suite_provider,
            SignaturePublicKeysContainer::List(&self.epoch.signature_public_keys),
            &self.epoch.context,
            &content,
            #[cfg(feature = "by_ref_proposal")]
            &[],
        )
        .await
        .map_err(|error| match error {
            MlsError::InvalidSignature | MlsError::LeafNotFound(_) => {
                EpochReadError::Rejected { sender, generation }
            }
            other => EpochReadError::Mls(other),
        })?;

        let signer_public_key = self
            .epoch
            .signature_public_keys
            .get(sender as usize)
            .and_then(Option::as_ref)
            .ok_or(MlsError::LeafNotFound(sender))?
            .to_vec();

        match content.content.content {
            Content::Application(data) => Ok(OpenedMessage {
                sender,
                generation,
                signer_public_key,
                authenticated_data: content.content.authenticated_data,
                application_data: data.to_vec(),
            }),
            _ => Err(MlsError::UnexpectedMessageType.into()),
        }
    }
}
