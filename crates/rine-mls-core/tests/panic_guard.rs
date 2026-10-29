//! The panic firewall every FFI binding runs its calls behind: a panic becomes
//! a typed failure and retires the handle, and a refused peer is remembered
//! for exactly the call that produced it.

use rine_mls_core::{Guarded, PanicGuard, Result, RineMlsError, RineMlsErrorCode};

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

const AGENT_C: &[u8] = b"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

fn refusal() -> Result<()> {
    Err(RineMlsError::PeerNotAdmitted {
        agent_id: AGENT_C.to_vec(),
    })
}

#[test]
fn test_run_when_a_peer_is_refused_records_it_and_the_next_ok_run_clears_it() {
    let mut guard = PanicGuard::default();

    let (code, message) = failed(guard.run(refusal));
    assert_eq!(code, RineMlsErrorCode::PeerNotAdmitted);
    assert!(message.contains("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"));
    assert_eq!(guard.refused_peer(), Some(AGENT_C));

    assert!(matches!(guard.run(|| Ok(1)), Guarded::Ok(1)));
    assert_eq!(guard.refused_peer(), None);
}

#[test]
fn test_run_when_a_different_error_follows_a_refusal_clears_the_recorded_peer() {
    let mut guard = PanicGuard::default();
    let _ = guard.run(refusal);

    let _ = guard.run(|| Err::<(), _>(RineMlsError::EmptyFrame));
    assert_eq!(guard.refused_peer(), None);
}

#[test]
fn test_run_when_the_handle_is_poisoned_clears_the_recorded_peer() {
    let mut guard = PanicGuard::default();
    let _ = guard.run(refusal);
    let _ = guard.run(|| -> Result<()> { panic!("torn ratchet") });
    assert_eq!(guard.refused_peer(), None);

    let _ = guard.run(refusal);
    assert_eq!(
        guard.refused_peer(),
        None,
        "a poisoned handle never runs the call"
    );
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
