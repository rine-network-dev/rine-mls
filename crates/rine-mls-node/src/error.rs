//! How a Rust failure reaches JavaScript.
//!
//! Two rules, and W3 inherits both:
//!
//! 1. **Every failure is typed.** `napi::Error` is generic over its status, and
//!    napi-rs passes that status straight into `napi_create_error` as the JS
//!    error's `code`. So a rine failure arrives as a real `Error` whose `code`
//!    is one of [`RineMlsErrorCode`]'s stable strings — a value to branch on,
//!    not a message to parse. The message stays human-readable and carries the
//!    detail (which epoch, which artifact); it is never the contract.
//! 2. **No panic crosses the boundary.** Unwinding out of an `extern "C"` frame
//!    is undefined behaviour, and a Rust panic that reached V8 would take the
//!    whole Node process down. Every call runs behind the core's
//!    [`PanicGuard`], which converts a panic into a `RINE_MLS_PANIC` error and
//!    retires the handle.
//!
//! Both halves of that live in `rine-mls-core`, tested there; what is left here
//! is only the last step — a code becoming a JavaScript `Error`.

use rine_mls_core::{Guarded, PanicGuard, Result as CoreResult, RineMlsError, RineMlsErrorCode};

/// Newtype so `napi::Error`'s status is rine's code vocabulary. napi-rs only
/// asks for `AsRef<str>`.
#[derive(Debug, Clone, Copy)]
pub struct MlsErrorCode(RineMlsErrorCode);

impl AsRef<str> for MlsErrorCode {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

/// The error type every binding method returns.
///
/// Written out as `Result<T, MlsError>` at each call site rather than hidden
/// behind an alias: napi-rs recognises a fallible method by the literal
/// `Result` path segment, and an alias makes it treat the whole `Result` as the
/// value to hand JavaScript.
pub type MlsError = napi::Error<MlsErrorCode>;

/// The orphan rule forbids `impl From<RineMlsError> for napi::Error<_>`, so the
/// conversion is a plain function used as `.map_err(from_core)`.
pub fn from_core(e: RineMlsError) -> MlsError {
    napi::Error::new(MlsErrorCode(e.code()), e)
}

/// Run one core operation on behalf of a JS caller.
pub fn guard<T>(
    poison: &mut PanicGuard,
    op: impl FnOnce() -> CoreResult<T>,
) -> Result<T, MlsError> {
    match poison.run(op) {
        Guarded::Ok(value) => Ok(value),
        Guarded::Err { code, message } => Err(napi::Error::new(MlsErrorCode(code), message)),
    }
}
