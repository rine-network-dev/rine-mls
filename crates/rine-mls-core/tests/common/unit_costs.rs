//! The per-operation costs of one real group, measured rather than fitted.
//!
//! Every daily-usage number rine can state is a multiple of one of these: what
//! a message weighs on the wire, what a membership change weighs, what an epoch
//! costs on disk, and how long each takes. They are gathered in one place so
//! the simulation composes measured unit costs instead of extrapolating a
//! curve — a composition can be checked against the group it came from, a
//! curve fit cannot.

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use rine_mls_core::RineCipherSuite;

use super::scale::{commit, found, key_packages, Cohort};
use super::{dir_size, file_size, group_dir, group_id};

/// The rine envelope every data-plane number here is measured against: a signed
/// envelope carrying a short agent-to-agent message.
pub const ENVELOPE_BYTES: usize = 500;

/// Sends timed per group size. One send is microseconds and one sample of it is
/// noise; the mean over a handful is a number worth putting in a table.
const ROUNDS: usize = 32;

/// What one operation costs on a group of [`UnitCosts::size`] members. Byte
/// counts are base64 — the unit the wire actually carries — except the on-disk
/// ones, which are raw file bytes.
pub struct UnitCosts {
    pub size: usize,
    pub suite: RineCipherSuite,

    /// Founding, kept for context: the whole init POST at this size.
    pub founding_commit: usize,
    pub founding_welcome: usize,
    pub founding_total: usize,

    /// One `mls-v1` application message carrying an [`ENVELOPE_BYTES`]
    /// envelope, and what MLS added to it.
    pub app_payload: usize,
    pub app_overhead: usize,

    /// One Add commit and the single Welcome it produces.
    pub add_commit: usize,
    pub add_welcome: usize,
    pub add_group_info: usize,
    /// One Remove commit. A Remove admits nobody, so it carries no Welcome —
    /// [`Self::remove_welcomes`] is the proof, not an assumption.
    pub remove_commit: usize,
    pub remove_welcomes: usize,
    /// A path-only commit — a membership change with its proposal subtracted,
    /// which is what rine's ordinary churn reduces to. Measured as the third
    /// commit the founder mints, so its own direct path is already populated.
    ///
    /// It is deliberately not called a *settled* commit. A founding commit
    /// leaves every interior node above the leaves blank, and a path secret is
    /// encrypted to the resolution of each copath node, so a commit stays O(N)
    /// until every member has committed through its own path — which in rine's
    /// admin-commits-everything pattern never happens. `scale_settling.rs`
    /// measures how far that is from the O(log N) the design assumed.
    pub churn_commit: usize,

    /// Raw on-disk bytes: the current state, the whole group directory, one
    /// retained epoch, and the self-read cache after [`ROUNDS`] sends.
    pub state_bytes: u64,
    pub group_dir_bytes: u64,
    pub epoch_bytes: u64,
    pub epochs_kept: usize,
    pub self_read_bytes: u64,

    pub found_in: Duration,
    pub join_in: Duration,
    pub encrypt: Duration,
    pub decrypt: Duration,
    pub apply_add: Duration,
    pub apply_remove: Duration,
    pub apply_churn: Duration,
    pub save: Duration,
}

impl UnitCosts {
    /// Found a real group of `size` members and weigh and time every operation
    /// a day of ordinary use is made of. Expensive — a thousand-member founding
    /// is minutes of client CPU — so callers measure once and reuse.
    pub fn measure(size: usize, suite: RineCipherSuite, tag: u8, first: u32) -> Self {
        let mut cohort = found(size, 2, suite, tag, first);
        let dir = group_dir(cohort.agents[0].store_path(), &group_id(tag));

        let started = Instant::now();
        cohort.groups[0].save().expect("save founding state");
        let save = started.elapsed();
        let state_bytes = file_size(&dir.join("state.bin"));

        let (encrypt, decrypt, app_payload) = time_sends(&mut cohort);

        let joiner = key_packages(first + size as u32 + 1, 1, suite);
        let add = commit(&mut cohort, |group| group.add_member(&joiner[0]));
        let remove = commit(&mut cohort, |group| group.remove_member(2));
        let churn = commit(&mut cohort, |group| group.add_members(&[]));

        cohort.groups[0].save().expect("save after churn");
        let (epochs_total, epochs_kept) = epochs(&dir.join("epochs"));

        Self {
            size,
            suite,
            founding_commit: cohort.commit,
            founding_welcome: cohort.welcome,
            founding_total: cohort.commit + cohort.welcomes_total + cohort.group_info,
            app_payload,
            app_overhead: app_payload - ENVELOPE_BYTES,
            add_commit: add.commit,
            add_welcome: add.welcome,
            add_group_info: add.group_info,
            remove_commit: remove.commit,
            remove_welcomes: remove.welcomes,
            churn_commit: churn.commit,
            state_bytes,
            group_dir_bytes: dir_size(&dir),
            epoch_bytes: epochs_total / epochs_kept.max(1) as u64,
            epochs_kept,
            self_read_bytes: file_size(&dir.join("self_read.bin")),
            found_in: cohort.found_in,
            join_in: cohort.join_in,
            encrypt,
            decrypt,
            apply_add: add.apply,
            apply_remove: remove.apply,
            apply_churn: churn.apply,
            save,
        }
    }
}

/// Mean encrypt and decrypt time over [`ROUNDS`] sends, and the raw framed
/// payload one send produces. The encrypt side includes the self-read cache
/// write, because a rine send is not finished until the sender can read its own
/// message back.
fn time_sends(cohort: &mut Cohort) -> (Duration, Duration, usize) {
    let envelope = vec![0x5A; ENVELOPE_BYTES];
    let (sender, receivers) = cohort.split();
    let mut encrypt = Duration::ZERO;
    let mut decrypt = Duration::ZERO;
    let mut payload_len = 0;

    for _ in 0..ROUNDS {
        let started = Instant::now();
        let payload = sender
            .encrypt_application_message(&envelope)
            .expect("encrypt");
        encrypt += started.elapsed();
        payload_len = payload.len();

        let started = Instant::now();
        let seen = receivers[0]
            .decrypt_application_message(&payload)
            .expect("peer decrypts");
        decrypt += started.elapsed();
        assert_eq!(seen.envelope, envelope);
    }

    (
        encrypt / ROUNDS as u32,
        decrypt / ROUNDS as u32,
        payload_len,
    )
}

/// Total bytes and file count of the retained epoch secrets. Nothing is deleted
/// here until the group has spent a whole retention window
/// ([`rine_mls_core::EPOCH_RETENTION_DEFAULT`]), so at these sizes this
/// directory is the group's growth term.
fn epochs(dir: &Path) -> (u64, usize) {
    let count = fs::read_dir(dir)
        .map(|entries| entries.count())
        .unwrap_or(0);

    (dir_size(dir), count)
}
