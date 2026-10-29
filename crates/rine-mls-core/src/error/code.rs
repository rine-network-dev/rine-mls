use super::RineMlsError;

/// The stable, machine-readable classification of a [`RineMlsError`].
///
/// This is the vocabulary the FFI bindings translate into host-language error
/// types — a JS `Error.code` and a Python exception subclass — so a TypeScript
/// or Python caller branches on a value, never on message text. Defining it
/// once here is what keeps the two bindings saying the same thing about the
/// same failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RineMlsErrorCode {
    /// RFC 9420 processing failed inside MLS.
    Protocol,
    /// The allowed set refused a leaf in the input; the handle names the agent
    /// ([`crate::PanicGuard::refused_peer`]).
    PeerNotAdmitted,
    /// The local state store could not be read or written.
    Store,
    /// Strict `current + 1` commit ordering refused a commit.
    EpochConflict,
    EpochOverflow,
    /// A blob of the wrong MLS artifact type arrived on this path.
    UnexpectedBlob,
    /// MLS processed the message, but it was not the kind this path expects.
    UnexpectedMessage,
    /// An Add commit produced no Welcome for a member it added.
    MissingWelcome,
    /// A KeyPackage this core cannot read — the pre-cutover framing, above all.
    UnreadableKeyPackage,
    /// A blob minted for a ciphersuite other than the one in play.
    CipherSuiteMismatch,
    /// The caller was removed from this group and it can no longer be used.
    GroupInactive,
    /// A message this member sent, whose plaintext the self-read cache no
    /// longer holds.
    SelfMessageNotCached,
    /// A KeyPackage publish batch larger than one request may carry.
    KeyPackageBatchTooLarge,
    /// An epoch-retention setting that would keep no prior epoch at all.
    InvalidEpochRetention,
    InvalidSigningSeed,
    /// A client opened for an agent with an empty id.
    EmptyAgentId,
    UnsupportedCipherSuite,
    /// The `mls-v1` payload did not carry the `0x04` version tag.
    UnexpectedVersionTag,
    EmptyFrame,
    /// A ratchet-tree leaf whose credential is not `basic`, met while
    /// enumerating the tree.
    UnreadableCredential,
    /// A Rust panic was caught at the FFI boundary, by
    /// [`crate::PanicGuard`], instead of unwinding into the host runtime.
    Panic,
    /// A previous call on this handle panicked, so its MLS state may be
    /// inconsistent and the handle refuses further use.
    Poisoned,
    /// A raw ML-KEM-768 key or ciphertext was refused on the DM-envelope
    /// primitive surface ([`crate::mlkem`]).
    MlKem,
    /// An ML-DSA-65 key-generation seed of the wrong length
    /// ([`crate::mldsa`]).
    MlDsa,
    /// A per-epoch read escrow that cannot be encoded or does not read back.
    InvalidEscrow,
    /// An AEAD-valid message whose MLS framing signature does not verify.
    MemberRejected,
    /// A message naming a generation beyond the reader's reach.
    GenerationTooFar,
    /// A resync from a GroupInfo with no leaf carrying the agent's credential.
    NoSeatToReplace,
    /// A resync from a GroupInfo with several such leaves.
    AmbiguousSeat,
    /// A resync from a GroupInfo that carries no ratchet tree.
    GroupInfoWithoutTree,
    /// The allowed set already holds the pair at another generation.
    AllowedGenerationConflict,
    /// A self-update to the key the leaf already carries.
    LeafAlreadyCurrent,
    /// A self-update from a seat whose signer is not its leaf's key.
    SignerLeafMismatch,
    /// An external commit that replaces its leaf with a different key.
    ResyncChangesKey,
    /// A commit is already pending on the handle.
    CommitPending,
    /// There is no pending commit to apply.
    NoPendingCommit,
    /// A commit that carries no GroupInfo for the epoch it creates.
    MissingGroupInfo,
}

impl RineMlsErrorCode {
    /// The wire spelling used as a JS `Error.code` and as the Python
    /// exception's `code` attribute.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protocol => "RINE_MLS_PROTOCOL",
            Self::PeerNotAdmitted => "RINE_MLS_PEER_NOT_ADMITTED",
            Self::Store => "RINE_MLS_STORE",
            Self::EpochConflict => "RINE_MLS_EPOCH_CONFLICT",
            Self::EpochOverflow => "RINE_MLS_EPOCH_OVERFLOW",
            Self::UnexpectedBlob => "RINE_MLS_UNEXPECTED_BLOB",
            Self::UnexpectedMessage => "RINE_MLS_UNEXPECTED_MESSAGE",
            Self::MissingWelcome => "RINE_MLS_MISSING_WELCOME",
            Self::UnreadableKeyPackage => "RINE_MLS_UNREADABLE_KEY_PACKAGE",
            Self::CipherSuiteMismatch => "RINE_MLS_CIPHER_SUITE_MISMATCH",
            Self::GroupInactive => "RINE_MLS_GROUP_INACTIVE",
            Self::SelfMessageNotCached => "RINE_MLS_SELF_MESSAGE_NOT_CACHED",
            Self::KeyPackageBatchTooLarge => "RINE_MLS_KEY_PACKAGE_BATCH_TOO_LARGE",
            Self::InvalidEpochRetention => "RINE_MLS_INVALID_EPOCH_RETENTION",
            Self::InvalidSigningSeed => "RINE_MLS_INVALID_SIGNING_SEED",
            Self::EmptyAgentId => "RINE_MLS_EMPTY_AGENT_ID",
            Self::UnsupportedCipherSuite => "RINE_MLS_UNSUPPORTED_CIPHER_SUITE",
            Self::UnexpectedVersionTag => "RINE_MLS_UNEXPECTED_VERSION_TAG",
            Self::EmptyFrame => "RINE_MLS_EMPTY_FRAME",
            Self::UnreadableCredential => "RINE_MLS_UNREADABLE_CREDENTIAL",
            Self::Panic => "RINE_MLS_PANIC",
            Self::Poisoned => "RINE_MLS_POISONED",
            Self::MlKem => "RINE_MLS_ML_KEM",
            Self::MlDsa => "RINE_MLS_ML_DSA",
            Self::InvalidEscrow => "RINE_MLS_INVALID_ESCROW",
            Self::MemberRejected => "RINE_MLS_MEMBER_REJECTED",
            Self::GenerationTooFar => "RINE_MLS_GENERATION_TOO_FAR",
            Self::NoSeatToReplace => "RINE_MLS_NO_SEAT_TO_REPLACE",
            Self::AmbiguousSeat => "RINE_MLS_AMBIGUOUS_SEAT",
            Self::GroupInfoWithoutTree => "RINE_MLS_GROUP_INFO_WITHOUT_TREE",
            Self::AllowedGenerationConflict => "RINE_MLS_ALLOWED_GENERATION_CONFLICT",
            Self::LeafAlreadyCurrent => "RINE_MLS_LEAF_ALREADY_CURRENT",
            Self::SignerLeafMismatch => "RINE_MLS_SIGNER_LEAF_MISMATCH",
            Self::ResyncChangesKey => "RINE_MLS_RESYNC_CHANGES_KEY",
            Self::CommitPending => "RINE_MLS_COMMIT_PENDING",
            Self::NoPendingCommit => "RINE_MLS_NO_PENDING_COMMIT",
            Self::MissingGroupInfo => "RINE_MLS_MISSING_GROUP_INFO",
        }
    }
}

impl RineMlsError {
    pub const fn code(&self) -> RineMlsErrorCode {
        match self {
            Self::Mls(_) => RineMlsErrorCode::Protocol,
            Self::PeerNotAdmitted { .. } => RineMlsErrorCode::PeerNotAdmitted,
            Self::Store(_) => RineMlsErrorCode::Store,
            Self::EpochConflict { .. } => RineMlsErrorCode::EpochConflict,
            Self::EpochOverflow { .. } => RineMlsErrorCode::EpochOverflow,
            Self::UnexpectedBlob { .. } => RineMlsErrorCode::UnexpectedBlob,
            Self::UnexpectedMessageContent { .. } => RineMlsErrorCode::UnexpectedMessage,
            Self::MissingWelcome { .. } => RineMlsErrorCode::MissingWelcome,
            Self::UnreadableKeyPackage { .. } => RineMlsErrorCode::UnreadableKeyPackage,
            Self::CipherSuiteMismatch { .. } => RineMlsErrorCode::CipherSuiteMismatch,
            Self::GroupInactive { .. } => RineMlsErrorCode::GroupInactive,
            Self::SelfMessageNotCached => RineMlsErrorCode::SelfMessageNotCached,
            Self::KeyPackageBatchTooLarge { .. } => RineMlsErrorCode::KeyPackageBatchTooLarge,
            Self::InvalidEpochRetention => RineMlsErrorCode::InvalidEpochRetention,
            Self::InvalidSigningSeed { .. } => RineMlsErrorCode::InvalidSigningSeed,
            Self::EmptyAgentId => RineMlsErrorCode::EmptyAgentId,
            Self::UnsupportedCipherSuite { .. } => RineMlsErrorCode::UnsupportedCipherSuite,
            Self::UnexpectedVersionTag { .. } => RineMlsErrorCode::UnexpectedVersionTag,
            Self::EmptyFrame => RineMlsErrorCode::EmptyFrame,
            Self::UnreadableCredential { .. } => RineMlsErrorCode::UnreadableCredential,
            Self::MlKem(_) => RineMlsErrorCode::MlKem,
            Self::MlDsa(_) => RineMlsErrorCode::MlDsa,
            Self::InvalidEscrow(_) => RineMlsErrorCode::InvalidEscrow,
            Self::MemberRejected { .. } => RineMlsErrorCode::MemberRejected,
            Self::GenerationTooFar { .. } => RineMlsErrorCode::GenerationTooFar,
            Self::NoSeatToReplace => RineMlsErrorCode::NoSeatToReplace,
            Self::AmbiguousSeat { .. } => RineMlsErrorCode::AmbiguousSeat,
            Self::GroupInfoWithoutTree => RineMlsErrorCode::GroupInfoWithoutTree,
            Self::LeafUpdate(fault) => fault.code(),
        }
    }
}
