//! Why a per-epoch read escrow could not be encoded or read back.

/// What is wrong with an `EpochReadSecrets` v1 plaintext, or with the epoch it
/// was exported from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EscrowFault {
    #[error("escrow plaintext version 0x{0:02X} is not 0x01")]
    UnsupportedVersion(u8),

    #[error("escrow plaintext ends before its fixed fields and tails do")]
    Truncated,

    #[error("escrow plaintext carries bytes after its last field")]
    TrailingBytes,

    #[error("the epoch's group context is {len} bytes, over the {max} byte escrow limit")]
    ContextTooLarge { len: usize, max: usize },

    #[error("the escrowed group context does not decode as an RFC 9420 GroupContext")]
    UndecodableContext,

    #[error(
        "the escrowed group context is for cipher suite 0x{0:04X}, not the 0xF057 the plaintext declares"
    )]
    ContextSuiteMismatch(u16),

    #[error("an escrowed secret or key is {len} bytes, not {expected}")]
    BadFieldLength { len: usize, expected: usize },

    #[error("the escrow names {count} leaves, over the {max} leaf escrow limit")]
    TooManyLeaves { count: usize, max: usize },

    #[error("the escrow declares a {leaf_count} leaf tree, which is not a power of two up to the leaf limit")]
    InvalidLeafCount { leaf_count: u32 },

    #[error("escrow leaf {leaf_index} is repeated, or lies outside the {leaf_count} leaf tree")]
    InvalidLeaf { leaf_index: u32, leaf_count: u32 },

    #[error(
        "the escrowed group context is for another group or epoch than the slot it was read for"
    )]
    SlotMismatch,
}
