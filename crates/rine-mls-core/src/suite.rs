use mls_rs::CipherSuite;

/// The one MLS ciphersuite rine speaks.
///
/// The suite id travels on the wire (the rine server persists it verbatim as
/// `mls_cipher_suite`), so it is a protocol constant, not a tuning knob. RFC
/// 9420's classical suite `0x0001` is not a variant: the system is
/// post-quantum only, so the id cannot be converted into a suite
/// ([`TryFrom<u16>`] refuses it) and no client can be opened for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RineCipherSuite {
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
    /// Every suite rine supports, in the order they are advertised. One today;
    /// the suite-parametrised tests iterate it, so a suite added here is held to
    /// every property they pin without editing them.
    pub const ALL: [Self; 1] = [Self::XWing];

    /// The suite a NEW rine group is created with.
    ///
    /// It lives here because both bindings and both SDK stacks have to agree on
    /// it. A default chosen separately in TypeScript and in Python is a default
    /// that eventually differs, and the two halves of a group would then
    /// disagree about their own ciphersuite.
    pub const DEFAULT: Self = Self::XWing;

    /// The wire id sent to the rine server as `cipher_suite`.
    pub const fn id(self) -> u16 {
        match self {
            Self::XWing => 0xF057,
        }
    }

    pub(crate) const fn mls_rs(self) -> CipherSuite {
        CipherSuite::new(self.id())
    }

    /// The RFC 9420 suite rine's suite borrows its AEAD, KDF, hash and
    /// signature scheme from: `0x0003`, where ChaCha20-Poly1305 with SHA-256 and
    /// Ed25519 is already defined. Nothing but primitive selection reads this.
    pub(crate) const fn primitives(self) -> CipherSuite {
        match self {
            Self::XWing => CipherSuite::CURVE25519_CHACHA,
        }
    }
}

impl TryFrom<u16> for RineCipherSuite {
    type Error = u16;

    fn try_from(id: u16) -> Result<Self, Self::Error> {
        match id {
            0xF057 => Ok(Self::XWing),
            other => Err(other),
        }
    }
}
