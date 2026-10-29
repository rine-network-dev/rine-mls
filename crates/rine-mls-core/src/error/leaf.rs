//! Failures of moving a member's own leaf to a new key, and of the checks that
//! keep every member's answer to "may this leaf replace that one" the same.

use super::{AgentLabel, RineMlsErrorCode};

#[derive(Debug, thiserror::Error)]
pub enum LeafUpdateFault {
    /// The allowed set already holds this `(agent id, leaf key)` pair at
    /// another generation. A generation is signed into the agent's
    /// certificate, so two answers for one pair mean a caller bug, and the set
    /// keeps the first.
    #[error(
        "agent {} is already in the allowed set with this leaf key at a different generation",
        AgentLabel(agent_id)
    )]
    AllowedGenerationConflict { agent_id: Vec<u8> },

    /// A self-update to the key the member's leaf already carries.
    #[error("this member's leaf already carries the key derived from that seed")]
    LeafAlreadyCurrent,

    /// This handle signs with a different key than its own leaf carries (it was
    /// installed from an older KeyPackage while the client holds a newer
    /// seed). The commit's framing signature would not verify against the
    /// leaf, so every receiver would refuse it.
    #[error("this member signs with a different key than its leaf carries; it cannot update its own leaf")]
    SignerLeafMismatch,

    /// An external commit that replaces a leaf with a different key. A resync
    /// keeps the key it replaces; moving to a new key is the self-update.
    #[error(
        "an external commit by agent {} replaces its leaf with a different key",
        AgentLabel(agent_id)
    )]
    ResyncChangesKey { agent_id: Vec<u8> },

    /// A commit is already pending on this handle: apply it or clear it before
    /// building another.
    #[error("a commit is pending on this group handle; apply or clear it first")]
    CommitPending,

    #[error("this group handle has no pending commit")]
    NoPendingCommit,

    /// A commit built with external-commit GroupInfo disabled. The client's
    /// rules always enable it, so this is a programming error.
    #[error("the commit produced no GroupInfo for the epoch it creates")]
    MissingGroupInfo,
}

impl LeafUpdateFault {
    pub const fn code(&self) -> RineMlsErrorCode {
        match self {
            Self::AllowedGenerationConflict { .. } => RineMlsErrorCode::AllowedGenerationConflict,
            Self::LeafAlreadyCurrent => RineMlsErrorCode::LeafAlreadyCurrent,
            Self::SignerLeafMismatch => RineMlsErrorCode::SignerLeafMismatch,
            Self::ResyncChangesKey { .. } => RineMlsErrorCode::ResyncChangesKey,
            Self::CommitPending => RineMlsErrorCode::CommitPending,
            Self::NoPendingCommit => RineMlsErrorCode::NoPendingCommit,
            Self::MissingGroupInfo => RineMlsErrorCode::MissingGroupInfo,
        }
    }
}
