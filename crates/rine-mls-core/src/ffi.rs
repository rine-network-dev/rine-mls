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
///
/// It also remembers which agent the last call's allowed-set refusal named, so
/// both bindings expose the same read-only getter and [`Guarded`] stays a plain
/// value-or-code result.
#[derive(Debug, Default)]
pub struct PanicGuard {
    tripped: bool,
    refused_peer: Option<Vec<u8>>,
}

impl PanicGuard {
    /// Run one core operation on behalf of a host-language caller.
    ///
    /// `AssertUnwindSafe` is deliberate, and the poison flag is what pays for
    /// it: the state may well be inconsistent after a panic, which is exactly
    /// why the handle is retired instead of trusted.
    pub fn run<T>(&mut self, op: impl FnOnce() -> Result<T>) -> Guarded<T> {
        self.refused_peer = None;

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
            Ok(Err(e)) => {
                self.refused_peer = e.refused_peer().map(<[u8]>::to_vec);
                Guarded::Err {
                    code: e.code(),
                    message: e.to_string(),
                }
            }
            Err(payload) => {
                self.tripped = true;
                Guarded::Err {
                    code: RineMlsErrorCode::Panic,
                    message: format!("internal MLS panic: {}", describe(payload.as_ref())),
                }
            }
        }
    }

    /// The credential identity of the leaf the allowed set refused in the last
    /// call on this handle, or `None` after any other outcome. Reads recorded
    /// state; read it straight after the failing call.
    pub fn refused_peer(&self) -> Option<&[u8]> {
        self.refused_peer.as_deref()
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
