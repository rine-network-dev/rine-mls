//! The per-epoch escrow accessors of a group handle, in their own `impl` block
//! so `group.rs` stays about the group itself.

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

use crate::error::{from_core, guard, MlsError};
use crate::group::MlsGroup;
use crate::types::{
    convert_backlog, convert_fingerprints, convert_take, EpochFingerprint, EscrowBacklog,
    EscrowTake,
};

#[napi]
impl MlsGroup {
    /// Every epoch this group installed since the last take, oldest first.
    ///
    /// Seal and persist each result — write it to disk — **before** calling
    /// `save()`. Taking empties the in-memory list, but the stored snapshot
    /// keeps the exports until the next `save()`, so a crash in between yields
    /// them again on the next load.
    ///
    /// An epoch that cannot be escrowed (a tree or group context over the escrow
    /// limits, or an export discarded because too many were waiting) comes back
    /// in `gaps` and never fails the take for the others. Record each gap beside
    /// the sealed files before saving: once saved, nothing else remembers it.
    #[napi]
    pub fn take_escrow_exports(&mut self) -> Result<EscrowTake, MlsError> {
        let inner = &mut self.inner;
        let take = guard(&mut self.poison, || inner.take_escrow_exports())?;

        convert_take(take).map_err(from_core)
    }

    /// The fork fingerprint of the group's current epoch — the `fp` an
    /// `EscrowExport` of this epoch carries — without taking anything. Two
    /// members on different forks of one epoch read different values.
    #[napi]
    pub fn epoch_fingerprint(&mut self) -> Result<Uint8Array, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.epoch_fingerprint()).map(|fp| Uint8Array::new(fp.to_vec()))
    }

    /// What the next `takeEscrowExports()` will return, without taking it: how
    /// many exports wait, and how many epochs were already discarded past the
    /// group's cap.
    #[napi]
    pub fn escrow_backlog(&self) -> EscrowBacklog {
        convert_backlog(self.inner.escrow_backlog())
    }

    /// The `(epoch, fp)` of every export a take would return now, oldest first,
    /// without taking anything. Record them before parking a snapshot that may
    /// later be unreadable, so the epochs given up are filed under their fork.
    #[napi]
    pub fn queued_escrow_fingerprints(&mut self) -> Result<Vec<EpochFingerprint>, MlsError> {
        let inner = &self.inner;
        let queued = guard(&mut self.poison, || inner.queued_escrow_fingerprints())?;

        convert_fingerprints(queued).map_err(from_core)
    }
}
