use mls_rs::CipherSuite;

/// The MLS ciphersuites rine speaks.
///
/// The suite id travels on the wire (the rine server persists it verbatim as
/// `mls_cipher_suite`), so it is a protocol constant, not a tuning knob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RineCipherSuite {
    /// RFC 9420 `0x0001` — `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
    /// The RFC-mandatory classical suite; rine's non-PQ fallback.
    Classical,

    /// rine's post-quantum suite: X-Wing (X25519 + ML-KEM-768) key exchange,
    /// ChaCha20-Poly1305, SHA-256 and Ed25519.
    ///
    /// It sits at `0xF057`, inside the private-use ciphersuite range RFC 9420
    /// reserves for exactly this. It is deliberately **not** `0x004D`, the
    /// code point the withdrawn X-Wing MLS draft used: that value went back to
    /// the standards range when the draft lapsed and can be assigned to a
    /// different suite, at which point two implementations would disagree about
    /// what a group's own ciphersuite means. A private-use point cannot be
    /// taken away from us. When the IETF's post-quantum MLS work lands a real
    /// code point, moving to it is a deliberate, one-time migration.
    XWing,
}

impl RineCipherSuite {
    /// Every suite rine supports, in the order they are advertised.
    pub const ALL: [Self; 2] = [Self::Classical, Self::XWing];

    /// The suite a NEW rine group is created with. Post-quantum is the default,
    /// not an opt-in: a group created today is read by whoever holds its
    /// ciphertext for as long as that ciphertext exists, so the classical suite
    /// is the fallback rather than the starting point.
    ///
    /// It lives here because both bindings and both SDK stacks have to agree on
    /// it. A default chosen separately in TypeScript and in Python is a default
    /// that eventually differs, and the two halves of a group would then
    /// disagree about their own ciphersuite.
    pub const DEFAULT: Self = Self::XWing;

    /// The wire id sent to the rine server as `cipher_suite`.
    pub const fn id(self) -> u16 {
        match self {
            Self::Classical => 0x0001,
            Self::XWing => 0xF057,
        }
    }

    pub const fn is_post_quantum(self) -> bool {
        match self {
            Self::Classical => false,
            Self::XWing => true,
        }
    }

    pub(crate) const fn mls_rs(self) -> CipherSuite {
        CipherSuite::new(self.id())
    }

    /// The RFC 9420 suite each rine suite borrows its AEAD, KDF, hash and
    /// signature scheme from. Only the KEM differs between the two, so the
    /// classical suite names itself and the post-quantum one names `0x0003`,
    /// which is where ChaCha20-Poly1305 with SHA-256 and Ed25519 is already
    /// defined. Nothing but primitive selection reads this.
    pub(crate) const fn primitives(self) -> CipherSuite {
        match self {
            Self::Classical => CipherSuite::CURVE25519_AES128,
            Self::XWing => CipherSuite::CURVE25519_CHACHA,
        }
    }
}

impl TryFrom<u16> for RineCipherSuite {
    type Error = u16;

    fn try_from(id: u16) -> Result<Self, Self::Error> {
        match id {
            0x0001 => Ok(Self::Classical),
            0xF057 => Ok(Self::XWing),
            other => Err(other),
        }
    }
}
