//! The deployment knobs a client is opened with.

use napi_derive::napi;
use rine_mls_core::{EpochRetention, Result as CoreResult, RineMlsOptions};

/// Optional settings for `MlsClient.open`. Omitting the object, or leaving a
/// field undefined, is rine's shipped policy — a caller that wants the defaults
/// never restates a number.
#[napi(object)]
#[derive(Default)]
pub struct MlsClientOptions {
    /// How many prior epochs a group keeps secrets for.
    ///
    /// Undefined is rine's shipped window, `EPOCH_RETENTION_DEFAULT`: enough
    /// epochs to cover the server's 90-day message retention in the
    /// fastest-churning group rine serves. A smaller number trades backlog
    /// reach for a narrower forward-secrecy window — old epoch secrets stop
    /// sitting on disk sooner, and a member absent for more than that many
    /// commits can no longer read what it missed, permanently. `0` is refused
    /// (`RINE_MLS_INVALID_EPOCH_RETENTION`): it would not tighten anything, it
    /// would break the group.
    pub epoch_retention_limit: Option<u32>,
}

impl MlsClientOptions {
    pub(crate) fn to_core(&self) -> CoreResult<RineMlsOptions> {
        Ok(RineMlsOptions {
            epoch_retention: EpochRetention::from_limit(
                self.epoch_retention_limit.map(|n| n as usize),
            )?,
        })
    }
}
