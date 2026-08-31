//! Typed failures at every seam. The machine-readable classification the
//! FFI bindings branch on is [`mod@code`].

mod code;

pub use code::RineMlsErrorCode;

use core::fmt;

use mls_rs::WireFormat;

use crate::store::StoreError;

/// The kind of MLS artifact a rine call was handed. Used to report a
/// wire-format mismatch without stringly-typed error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsBlobKind {
    KeyPackage,
    Welcome,
    Commit,
    GroupInfo,
    ApplicationMessage,
}

impl fmt::Display for MlsBlobKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::KeyPackage => "KeyPackage",
            Self::Welcome => "Welcome",
            Self::Commit => "Commit",
            Self::GroupInfo => "GroupInfo",
            Self::ApplicationMessage => "ApplicationMessage",
        };
        f.write_str(name)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RineMlsError {
    #[error(transparent)]
    Mls(#[from] mls_rs::error::MlsError),

    #[error(transparent)]
    Store(#[from] StoreError),

    /// Strict RFC 9420 `current + 1` commit ordering, mirroring the rine
    /// server's epoch CAS: a commit built at any epoch other than the group's
    /// current one is refused instead of silently forking local state.
    #[error("epoch conflict: group is at epoch {current}, commit was built at epoch {commit}")]
    EpochConflict { current: u64, commit: u64 },

    #[error("epoch counter overflow at {current}")]
    EpochOverflow { current: u64 },

    #[error("expected a {expected} blob, got wire format {got:?}")]
    UnexpectedBlob {
        expected: MlsBlobKind,
        got: WireFormat,
    },

    /// `process_incoming_message` returned something other than the caller's
    /// expectation (e.g. a commit arrived on the application-message path).
    #[error("expected a {expected} message on this path")]
    UnexpectedMessageContent { expected: MlsBlobKind },

    #[error("an Add commit produced no Welcome for the member added at index {index}")]
    MissingWelcome { index: usize },

    /// A claimed KeyPackage this core cannot read. Its own remedy, not a retry:
    /// see [`crate::RineMlsClient::create_group_with_members`].
    #[error(
        "the KeyPackage claimed for member {index} is not one this core can read; \
         a KeyPackage pool published before rine's MLS cutover has to be drained \
         and republished before that member can be added"
    )]
    UnreadableKeyPackage { index: usize },

    /// A blob minted for one ciphersuite arrived on a path operating in
    /// another — a classical KeyPackage offered to a post-quantum group, or a
    /// Welcome for a group whose suite is not the one this client was opened
    /// with. Both ids are the wire values the rine server stores as
    /// `mls_cipher_suite`.
    #[error("expected ciphersuite 0x{expected:04X}, got 0x{got:04X}")]
    CipherSuiteMismatch { expected: u16, got: u16 },

    /// The group was left behind by a Remove commit that evicted this member.
    /// It can no longer commit or send; it is kept only so the caller can see
    /// what happened and retire its local state.
    #[error("this member was removed from the group at epoch {epoch}")]
    GroupInactive { epoch: u64 },

    /// This member sent the message, so MLS cannot decrypt it (forward secrecy
    /// consumed the sender's ratchet step at encryption time) and the local
    /// self-read cache no longer holds the plaintext either.
    #[error(
        "this group message was sent by this member; MLS forward secrecy makes it \
         undecryptable, and its plaintext is no longer in the local self-read cache"
    )]
    SelfMessageNotCached,

    /// More KeyPackages were asked for in one publish than a single request may
    /// carry. See [`crate::KEY_PACKAGE_MAX_BATCH`].
    #[error("a KeyPackage publish batch is capped at {max} packages, {requested} were requested")]
    KeyPackageBatchTooLarge { requested: usize, max: usize },

    /// An epoch-retention setting of zero: see
    /// [`crate::EpochRetention::from_limit`].
    #[error(
        "epoch retention must keep at least one prior epoch, or be left unset for all of them"
    )]
    InvalidEpochRetention,

    #[error("Ed25519 signing seed must be 32 bytes, got {len}")]
    InvalidSigningSeed { len: usize },

    /// A ciphersuite id that is neither of rine's two. Raised by callers that
    /// take the suite as the wire integer the server stores (`mls_cipher_suite`)
    /// rather than as [`crate::RineCipherSuite`] — the FFI bindings, above all.
    #[error("unsupported MLS ciphersuite 0x{id:04X}")]
    UnsupportedCipherSuite { id: u16 },

    #[error("mls-v1 application message must start with the 0x{expected:02X} version tag, got 0x{got:02X}")]
    UnexpectedVersionTag { expected: u8, got: u8 },

    #[error("mls-v1 application message is empty")]
    EmptyFrame,

    /// A ratchet-tree leaf whose credential is not `basic`, met while
    /// enumerating the tree ([`crate::RineMlsGroup::member_identities`]).
    ///
    /// rine mints only basic credentials, so this cannot arise from a group
    /// rine built. It is raised rather than skipped because the enumeration
    /// feeds an orphan computation that *removes* members: a leaf silently
    /// dropped from the roster is a leaf no set difference can ever name.
    #[error("ratchet-tree leaf {index} carries a non-basic credential")]
    UnreadableCredential { index: u32 },

    /// A raw ML-KEM-768 key or ciphertext the DM envelope path refused. Not an
    /// MLS failure — it reaches this enum so the crate's one error taxonomy
    /// covers everything the FFI bindings can raise.
    #[error(transparent)]
    MlKem(#[from] crate::mlkem::MlKemError),
}

pub type Result<T> = core::result::Result<T, RineMlsError>;
