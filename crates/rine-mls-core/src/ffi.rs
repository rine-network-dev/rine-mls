//! The panic firewall every FFI binding runs its calls behind.
//!
//! Unwinding out of an `extern "C"` frame is undefined behaviour, and a Rust
//! panic that reached V8 or CPython would take the whole host process down. So
//! no binding calls this crate directly: each one calls through [`PanicGuard`],
//! which turns a panic into an ordinary typed failure and **retires the
//! handle**. State half-mutated by an unwind is not state to keep using, so
//! every later call on that handle fails with
//! [`RineMlsErrorCode::Poisoned`] rather than working from a torn ratchet.
//!
//! The mechanism lives here, not in the bindings, for two reasons: it is the
//! same mechanism on both sides, and here it can actually be tested — a binding
//! crate is a `cdylib` with no host runtime to link a test harness against.
//! What stays in each binding is only the last step: turning a
//! [`RineMlsErrorCode`] into a JavaScript `Error.code` or a Python exception
//! class.
//!
//! One build-level caveat the bindings inherit: `catch_unwind` only catches
//! when the profile unwinds. A `panic = "abort"` release profile would silence
//! this firewall without any compile error, so no rine profile may set it.

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::error::{Result, RineMlsErrorCode};

/// What a guarded call produced, stated in the vocabulary an FFI binding needs:
/// a value, or a code plus a human-readable message.
#[derive(Debug)]
pub enum Guarded<T> {
    Ok(T),
    Err {
        code: RineMlsErrorCode,
        message: String,
    },
}

/// One handle's panic state. `Default` is "healthy".
#[derive(Debug, Default)]
pub struct PanicGuard {
    tripped: bool,
}

impl PanicGuard {
    /// Run one core operation on behalf of a host-language caller.
    ///
    /// `AssertUnwindSafe` is deliberate, and the poison flag is what pays for
    /// it: the state may well be inconsistent after a panic, which is exactly
    /// why the handle is retired instead of trusted.
    pub fn run<T>(&mut self, op: impl FnOnce() -> Result<T>) -> Guarded<T> {
        if self.tripped {
            return Guarded::Err {
                code: RineMlsErrorCode::Poisoned,
                message: "MLS handle was retired after an internal panic; \
                          open it again from stored state"
                    .to_owned(),
            };
        }

        match catch_unwind(AssertUnwindSafe(op)) {
            Ok(Ok(value)) => Guarded::Ok(value),
            Ok(Err(e)) => Guarded::Err {
                code: e.code(),
                message: e.to_string(),
            },
            Err(payload) => {
                self.tripped = true;
                Guarded::Err {
                    code: RineMlsErrorCode::Panic,
                    message: format!("internal MLS panic: {}", describe(payload.as_ref())),
                }
            }
        }
    }
}

fn describe(payload: &(dyn Any + Send)) -> &str {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return s;
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.as_str();
    }
    "panic payload was not a string"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RineMlsError;

    fn failed<T>(guarded: Guarded<T>) -> (RineMlsErrorCode, String) {
        match guarded {
            Guarded::Err { code, message } => (code, message),
            Guarded::Ok(_) => panic!("expected a failure"),
        }
    }

    #[test]
    fn test_run_when_the_operation_succeeds_returns_the_value() {
        let mut guard = PanicGuard::default();
        assert!(matches!(guard.run(|| Ok(7)), Guarded::Ok(7)));
    }

    #[test]
    fn test_run_when_the_operation_fails_normally_leaves_the_handle_usable() {
        let mut guard = PanicGuard::default();

        let (code, message) = failed(guard.run(|| {
            Err::<(), _>(RineMlsError::EpochConflict {
                current: 7,
                commit: 6,
            })
        }));
        assert_eq!(code, RineMlsErrorCode::EpochConflict);
        assert!(message.contains("epoch 7"));

        assert!(matches!(guard.run(|| Ok(1)), Guarded::Ok(1)));
    }

    #[test]
    fn test_run_when_the_operation_panics_reports_it_without_unwinding() {
        let mut guard = PanicGuard::default();

        let (code, message) = failed(guard.run(|| -> Result<()> { panic!("torn ratchet") }));
        assert_eq!(code, RineMlsErrorCode::Panic);
        assert!(message.contains("torn ratchet"));
    }

    #[test]
    fn test_run_when_a_previous_call_panicked_refuses_to_run_at_all() {
        let mut guard = PanicGuard::default();
        let _ = guard.run(|| -> Result<()> { panic!("torn ratchet") });

        let mut ran = false;
        let (code, _) = failed(guard.run(|| {
            ran = true;
            Ok(())
        }));
        assert_eq!(code, RineMlsErrorCode::Poisoned);
        assert!(!ran, "a poisoned handle must not touch MLS state again");
    }

    #[test]
    fn test_run_when_the_panic_payload_is_not_a_string_still_reports_a_panic() {
        let mut guard = PanicGuard::default();

        let (code, message) = failed(guard.run(|| -> Result<()> {
            std::panic::panic_any(42u8);
        }));
        assert_eq!(code, RineMlsErrorCode::Panic);
        assert!(message.contains("not a string"));
    }
}
