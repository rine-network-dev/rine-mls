//! N-2 — what the retention window is worth, in epochs and in bytes.
//!
//! `EPOCH_RETENTION_DEFAULT` is ninety days of the fastest-churning group rine
//! serves. The ninety days comes from rine's message-retention policy and the
//! size ceiling is 500; the step between them — **how many epochs a day of
//! churn actually spends** — is the one that could have been wrong, so it is
//! measured here rather than reasoned.
//!
//! The cheap test carries the load-bearing claim — **one membership change is
//! one epoch, and a message is none** — because if a message ever advanced an
//! epoch the window would be a traffic budget rather than a churn budget, and
//! ninety days of it would be wrong by orders of magnitude. The `#[ignore]`d
//! ones found 500-member groups to price a day at each churn rate the
//! daily-usage model sweeps, and are the evidence behind the numbers in
//! `policy/retention.rs`'s docstring.
//!
//! ```text
//! cargo test --release -p rine-mls-core --test epoch_window -- --ignored --nocapture
//! ```

mod common;

use std::time::Instant;

use common::scale::{commit, found};
use common::{dir_size, for_each_suite, group_dir, group_id, TestAgent};
use rine_mls_core::{RineCipherSuite, EPOCH_RETENTION_DEFAULT, MESSAGE_RETENTION_DAYS};

/// The group-size ceiling. The window is sized for a group this big
/// because that is where an epoch costs the most and churn spends the most.
const CEILING: usize = 500;

/// Fractions of a group's membership that change in a day — the daily-usage
/// model's own sweep (`scale_daily.rs` `CHURN_RATES`).
const CHURN_RATES: [f64; 3] = [0.005, 0.02, 0.10];

/// Messages a day in a big group, the model's headline rate. Present so the
/// measurement answers "epochs per *day*" rather than "epochs per commit".
const MESSAGES_PER_DAY: usize = 200;

const ENVELOPE: &[u8] = b"a short agent-to-agent message, of the shape a rine envelope carries";

#[test]
fn test_epochs_when_a_day_is_driven_then_one_lands_per_commit_and_none_per_message() {
    for_each_suite(|suite| {
        let day = drive_a_day(suite, 0xB1, 4, 3, 12);

        assert_eq!(
            day.epochs, 3,
            "an epoch advances on a commit and only on a commit: 3 membership \
             changes and 12 messages left {} epoch records",
            day.epochs,
        );
        assert!(
            day.bytes > 0,
            "a retained epoch is a real file with a real cost",
        );
    });
}

/// ```text
/// cargo test --release -p rine-mls-core --test epoch_window -- --ignored --nocapture \
///     test_retention_window_when_priced_at_the_ceiling_covers_the_server_retention
/// ```
#[test]
#[ignore = "founds a 500-member group per suite to price one day of churn at the ceiling"]
fn test_retention_window_when_priced_at_the_ceiling_covers_the_server_retention() {
    for_each_suite(|suite| {
        for (n, churn) in CHURN_RATES.into_iter().enumerate() {
            let commits = (CEILING as f64 * churn).ceil() as usize;
            let day = drive_a_day(suite, 0xC0 + n as u8, CEILING, commits, MESSAGES_PER_DAY);

            let per_epoch = day.bytes / day.epochs.max(1) as u64;
            let window_days = EPOCH_RETENTION_DEFAULT as f64 / day.epochs as f64;

            eprintln!(
                "N-2 suite 0x{:04X}  N {CEILING}  churn {:5.1} %  \
                 {:3} commits/day  {:3} epochs/day  {:9} B/day  {:6} B/epoch  \
                 window {:6} epochs = {:7.1} days  full window {:7.1} MB  \
                 {:6.1} s",
                suite.id(),
                churn * 100.0,
                commits,
                day.epochs,
                day.bytes,
                per_epoch,
                EPOCH_RETENTION_DEFAULT,
                window_days,
                (EPOCH_RETENTION_DEFAULT as u64 * per_epoch) as f64 / 1_000_000.0,
                day.took,
            );

            assert_eq!(
                day.epochs,
                commits,
                "the window is sized in commits, so a day at {:.1} % churn in a \
                 group of {CEILING} must spend exactly {commits} epochs",
                churn * 100.0,
            );
            assert!(
                window_days >= MESSAGE_RETENTION_DAYS as f64,
                "the shipped window covers only {window_days:.1} days at {:.1} % \
                 churn, and the server serves messages for {MESSAGE_RETENTION_DAYS}",
                churn * 100.0,
            );
        }
    });
}

/// What one modelled day left on one member's disk.
struct Day {
    /// Epoch records added to the receiving member's store.
    epochs: usize,
    /// Bytes those records cost.
    bytes: u64,
    took: f64,
}

/// Drive one day of a group of `size`: `commits` membership changes and
/// `messages` sends, all applied and persisted by a live peer, and weigh what
/// the day added to that peer's epoch directory.
///
/// The peer, not the committer, because the peer is every member: an admin
/// mints the churn, everyone else downloads and persists it.
fn drive_a_day(
    suite: RineCipherSuite,
    tag: u8,
    size: usize,
    commits: usize,
    messages: usize,
) -> Day {
    let first = tag as u32 * 1000;
    let mut cohort = found(size, 2, suite, tag, first);
    let epochs_dir = group_dir(cohort.agents[1].store_path(), &group_id(tag)).join("epochs");

    cohort.groups[1].save().expect("peer persists its join");
    let before = (count(&epochs_dir), dir_size(&epochs_dir));
    let started = Instant::now();

    // Churn: a transient member joins, then leaves again, so the group is the
    // same size at the end of the day as at the start.
    let mut seated: Option<TestAgent> = None;
    for n in 0..commits {
        match seated.take() {
            Some(transient) => {
                let leaf = cohort.groups[0]
                    .member_index(&transient.identity)
                    .expect("the transient member's leaf");
                commit(&mut cohort, |group| group.remove_member(leaf));
            }
            None => {
                let transient = TestAgent::indexed(first + size as u32 + n as u32 + 1, suite);
                let package = transient
                    .client
                    .generate_key_package()
                    .expect("key package");
                commit(&mut cohort, |group| group.add_member(&package));
                seated = Some(transient);
            }
        }
        cohort.groups[1].save().expect("peer persists the commit");
    }

    for _ in 0..messages {
        let (sender, receivers) = cohort.split();
        let payload = sender
            .encrypt_application_message(ENVELOPE)
            .expect("encrypt");
        receivers[0]
            .decrypt_application_message(&payload)
            .expect("peer decrypts");
        receivers[0].save().expect("peer persists the read");
    }

    let took = started.elapsed().as_secs_f64();
    let after = (count(&epochs_dir), dir_size(&epochs_dir));

    Day {
        epochs: after.0 - before.0,
        bytes: after.1 - before.1,
        took,
    }
}

fn count(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
}

/// What a persist costs once the window is full — the price of trimming at all,
/// which every deployment now pays because there is no "keep everything"
/// setting to opt out into.
///
/// Reading a full window's directory is the whole of that price — MEASURED at
/// +1.4 ms on a 5.0 ms persist — and it is why the trim runs only on a write
/// that inserted an epoch: a message persist does not change the epoch set, so
/// listing it would be a directory scan bought for nothing, on the one path
/// that runs hundreds of times a day. What this test shows with the guard in
/// place is the *absence* of that cost.
#[test]
#[ignore = "plants a full retention window of epoch files to time a persist against it"]
fn test_persist_when_the_window_is_full_stays_cheap() {
    let suite = RineCipherSuite::Classical;
    let alice = TestAgent::new(1, suite);
    let id = group_id(0xB7);

    let (mut group, _) = alice.client.create_group(&id).expect("create");
    group.save().expect("persist");

    let epochs = group_dir(alice.store_path(), &id).join("epochs");
    let before = count(&epochs);
    let empty = mean_persist(&mut group);

    for id in 1_000..1_000 + EPOCH_RETENTION_DEFAULT as u64 - 1 {
        std::fs::write(epochs.join(format!("{id}.bin")), b"planted").expect("plant an epoch");
    }
    let full = mean_persist(&mut group);

    eprintln!(
        "N-2 persist  {before:5} epoch records {empty:7.3} ms   {:5} records {full:7.3} ms",
        count(&epochs),
    );
    assert_eq!(
        count(&epochs),
        EPOCH_RETENTION_DEFAULT,
        "a persist that inserted no epoch leaves the directory alone: {} planted \
         plus this group's own, none of them trimmed",
        EPOCH_RETENTION_DEFAULT - 1,
    );
}

/// Mean milliseconds of a message-path persist. One sample is dominated by the
/// first write's directory creation, which is not what is being compared.
fn mean_persist(group: &mut rine_mls_core::RineMlsGroup) -> f64 {
    const ROUNDS: u32 = 16;

    group.save().expect("warm up");

    let started = Instant::now();
    for _ in 0..ROUNDS {
        group.save().expect("persist");
    }

    started.elapsed().as_secs_f64() * 1000.0 / ROUNDS as f64
}
