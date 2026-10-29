//! How a Rust failure reaches Python.
//!
//! The same two rules the napi binding follows, expressed the way Python
//! expects them:
//!
//! 1. **Every failure is typed.** Each [`RineMlsErrorCode`] gets its own
//!    exception class under a common `RineMlsError` base, so callers write
//!    `except EpochConflictError` rather than matching on message text. Each
//!    class also carries the shared wire code as a `code` attribute, so code
//!    that would rather branch on a value than on a class can, and so the
//!    Python and JavaScript sides name the same failure identically.
//! 2. **No panic crosses the boundary.** Every call runs behind the core's
//!    [`PanicGuard`], which converts a panic into `MlsPanicError` and retires
//!    the handle. (PyO3 has its own panic net; it raises an opaque
//!    `PanicException` and leaves the handle usable, which is exactly the two
//!    things we do not want.)
//!
//! Both halves of that live in `rine-mls-core`, tested there; what is left here
//! is only the last step — a code becoming a Python exception.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use rine_mls_core::{
    Guarded, PanicGuard, Result as CoreResult, RineMlsError as CoreError, RineMlsErrorCode,
};

create_exception!(
    rine_mls,
    RineMlsError,
    PyException,
    "Base class for every failure raised by rine's MLS core."
);

/// The base class an exception is declared under: the one written after a
/// colon in `rine_exceptions!`, else the common `RineMlsError`.
macro_rules! parent_class {
    () => {
        RineMlsError
    };
    ($parent:ident) => {
        $parent
    };
}

macro_rules! rine_exceptions {
    ($($variant:ident => $exc:ident $(: $parent:ident)?),+ $(,)?) => {
        $(create_exception!(rine_mls, $exc, parent_class!($($parent)?));)+

        fn typed(code: RineMlsErrorCode, message: String) -> PyErr {
            let err = match code {
                $(RineMlsErrorCode::$variant => PyErr::new::<$exc, _>(message),)+
                // RineMlsErrorCode is non_exhaustive: a code added upstream
                // without a class here still arrives as a rine MLS error rather
                // than as something a caller's `except` block would miss.
                _ => PyErr::new::<RineMlsError, _>(message),
            };

            with_code(err, code)
        }

        pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
            m.add("RineMlsError", m.py().get_type::<RineMlsError>())?;
            $(
                let class = m.py().get_type::<$exc>();
                class.setattr("code", RineMlsErrorCode::$variant.as_str())?;
                m.add(stringify!($exc), class)?;
            )+
            Ok(())
        }
    };
}

rine_exceptions! {
    Protocol => MlsProtocolError,
    // A subclass of `MlsProtocolError`: a caller that already catches the
    // protocol class keeps catching the refusal it used to arrive as.
    PeerNotAdmitted => PeerNotAdmittedError: MlsProtocolError,
    Store => MlsStoreError,
    EpochConflict => EpochConflictError,
    EpochOverflow => EpochOverflowError,
    UnexpectedBlob => UnexpectedBlobError,
    UnexpectedMessage => UnexpectedMessageError,
    MissingWelcome => MissingWelcomeError,
    UnreadableKeyPackage => UnreadableKeyPackageError,
    CipherSuiteMismatch => CipherSuiteMismatchError,
    GroupInactive => GroupInactiveError,
    SelfMessageNotCached => SelfMessageNotCachedError,
    KeyPackageBatchTooLarge => KeyPackageBatchTooLargeError,
    InvalidEpochRetention => InvalidEpochRetentionError,
    InvalidSigningSeed => InvalidSigningSeedError,
    UnsupportedCipherSuite => UnsupportedCipherSuiteError,
    UnexpectedVersionTag => UnexpectedVersionTagError,
    EmptyFrame => EmptyFrameError,
    UnreadableCredential => UnreadableCredentialError,
    Panic => MlsPanicError,
    Poisoned => MlsPoisonedError,
    MlKem => MlKemError,
    MlDsa => MlDsaError,
    EmptyAgentId => EmptyAgentIdError,
    InvalidEscrow => InvalidEscrowError,
    MemberRejected => MemberRejectedError,
    GenerationTooFar => GenerationTooFarError,
    NoSeatToReplace => NoSeatToReplaceError,
    AmbiguousSeat => AmbiguousSeatError,
    GroupInfoWithoutTree => GroupInfoWithoutTreeError,
    AllowedGenerationConflict => AllowedGenerationConflictError,
    LeafAlreadyCurrent => LeafAlreadyCurrentError,
    SignerLeafMismatch => SignerLeafMismatchError,
    // A subclass of `MlsProtocolError`: a resync that changes the key used to
    // arrive as a protocol refusal, and a caller catching that keeps catching it.
    ResyncChangesKey => ResyncChangesKeyError: MlsProtocolError,
    CommitPending => CommitPendingError,
    NoPendingCommit => NoPendingCommitError,
    MissingGroupInfo => MissingGroupInfoError,
}

/// Put the wire code on the raised instance, not only on its class.
///
/// The classes above carry `code` so a caller can read it without an exception
/// in hand. This is the other half: a caller that caught the *base* class — the
/// path a code added to the core but not yet mapped here takes — still learns
/// which failure it was. A JavaScript caller's `Error.code` is always populated,
/// so a Python caller's must be too, or the two bindings stop naming the same
/// failure the same way at exactly the moment it matters.
fn with_code(err: PyErr, code: RineMlsErrorCode) -> PyErr {
    Python::attach(|py| {
        if let Err(e) = err.value(py).setattr("code", code.as_str()) {
            return e;
        }
        err
    })
}

/// Run one core operation on behalf of a Python caller.
pub fn guard<T>(poison: &mut PanicGuard, op: impl FnOnce() -> CoreResult<T>) -> PyResult<T> {
    match poison.run(op) {
        Guarded::Ok(value) => Ok(value),
        Guarded::Err { code, message } => Err(typed(code, message)),
    }
}

/// Convert a core error raised outside [`guard`] (bundle conversion, mostly).
pub fn from_core(e: CoreError) -> PyErr {
    typed(e.code(), e.to_string())
}
