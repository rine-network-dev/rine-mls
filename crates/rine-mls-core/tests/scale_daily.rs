//! Measurement C — a day in the life of an agent in twenty-eight groups.
//!
//! The profile is the plan's: one agent belonging to eight groups of a thousand
//! and twenty of a hundred, swept across three message rates and three churn
//! rates. Nine cells; the headline is 200 messages a day in a thousand-member
//! group at 2 % daily churn.
//!
//! **Which numbers are measured and which are composed.** Every unit cost —
//! what one message weighs, what one commit weighs, what each costs in wall
//! clock, what an epoch costs on disk — is measured here, now, on a real group
//! of the size in question ([`UnitCosts::measure`] founds it). The day is then
//! composed by multiplying those measured units by counts. Nothing is
//! extrapolated from a curve fit: a composition can be checked back against the
//! group it came from, which is exactly what the fitted model this work
//! replaces could not be.
//!
//! The model, stated so it can be argued with:
//!
//! - a group of `N` at churn `c` sees `ceil(N·c)` membership changes a day, each
//!   one its own commit, which every member downloads;
//! - the agent originates `1/N` of its groups' messages and receives the rest;
//! - every state-changing operation — a send, a receive, a commit — is followed
//!   by a persist, because a client that batches persistence loses the work on
//!   a crash;
//! - disk grows by one retained epoch record per commit, until the group has
//!   spent `EPOCH_RETENTION_DEFAULT` of them and the oldest starts falling off;
//!   the growth column below is therefore the rate, not a level that never
//!   stops.
//!
//! ⚠️ **The growth column understates the marginal cost. A per-commit figure
//! computed the other way — see below — is deliberately higher, and both are
//! correct.**
//! [`UnitCosts::epoch_bytes`] is the epochs directory divided by the number of
//! records in it, and one of those records is the founding epoch — a couple of
//! hundred bytes against a churn epoch's several thousand. Averaging it in pulls
//! the mean down, so this test prints a *smaller* number than the reported
//! figure, which divides the founding record back out before quoting a cost per
//! commit. The two disagree by a uniform factor at every churn rate and neither
//! is wrong: this is the harness mean, that is the marginal per-commit cost, and
//! the marginal one is what a group actually pays per membership change. Do not
//! "correct" either to match the other.
//!
//! ```text
//! cargo test --release -p rine-mls-core --test scale_daily -- --ignored --nocapture
//! ```

mod common;

use common::for_each_suite;
use common::unit_costs::UnitCosts;

/// The agent's group profile: (members per group, groups of that size).
const BIG: (usize, usize) = (1000, 8);
const SMALL: (usize, usize) = (100, 20);

/// Messages a day in a big group. The small groups carry a quarter of the rate,
/// which is the plan's 4:1 ratio.
const MESSAGE_RATES: [usize; 3] = [20, 200, 2000];
const SMALL_RATE_DIVISOR: f64 = 4.0;

/// Fraction of a group's membership that changes in a day.
const CHURN_RATES: [f64; 3] = [0.005, 0.02, 0.10];

/// The cell the plan asks to be called out.
const HEADLINE: (usize, f64) = (200, 0.02);

/// ```text
/// cargo test --release -p rine-mls-core --test scale_daily -- --ignored --nocapture \
///     test_daily_cost_of_eight_thousand_member_groups_and_twenty_hundreds
/// ```
#[test]
#[ignore = "founds a 1000-member and a 100-member group per suite to measure the unit costs"]
fn test_daily_cost_of_eight_thousand_member_groups_and_twenty_hundreds() {
    for_each_suite(|suite| {
        let big = UnitCosts::measure(BIG.0, suite, 0xF0, 0);
        let small = UnitCosts::measure(SMALL.0, suite, 0xF1, 0);
        report_units(&big, &small);

        for messages in MESSAGE_RATES {
            for churn in CHURN_RATES {
                let day = day_of(&big, BIG.1, messages as f64, churn).plus(day_of(
                    &small,
                    SMALL.1,
                    messages as f64 / SMALL_RATE_DIVISOR,
                    churn,
                ));

                let headline = messages == HEADLINE.0 && churn == HEADLINE.1;
                eprintln!(
                    "C1 suite 0x{:04X}  {messages:5} msg/day  churn {:5.1} %  \
                     in {:9.2} MB  out {:7.3} MB  cpu {:8.1} s  \
                     disk steady {:7.1} MB  growth(mean-epoch) +{:7.2} MB/day \
                     (+{:8.1} MB/month)  24 h catch-up {:9.2} MB in {:7.1} s{}",
                    suite.id(),
                    churn * 100.0,
                    mb(day.inbound),
                    mb(day.outbound),
                    day.cpu,
                    mb(day.steady),
                    mb(day.growth),
                    mb(day.growth * 30.0),
                    mb(day.inbound),
                    day.cpu,
                    if headline { "   <-- HEADLINE" } else { "" },
                );
            }
        }
    });
}

/// One day's traffic, time and disk for one slice of the profile.
struct Day {
    inbound: f64,
    outbound: f64,
    cpu: f64,
    steady: f64,
    growth: f64,
}

impl Day {
    fn plus(self, other: Self) -> Self {
        Self {
            inbound: self.inbound + other.inbound,
            outbound: self.outbound + other.outbound,
            cpu: self.cpu + other.cpu,
            steady: self.steady + other.steady,
            growth: self.growth + other.growth,
        }
    }
}

/// Compose one day across `groups` groups of the size `costs` was measured on.
fn day_of(costs: &UnitCosts, groups: usize, messages: f64, churn: f64) -> Day {
    let size = costs.size as f64;
    let commits = (size * churn).ceil();
    let sent = messages / size;
    let received = messages - sent;
    let groups = groups as f64;

    let persist = costs.save.as_secs_f64();
    let cpu = received * (costs.decrypt.as_secs_f64() + persist)
        + sent * (costs.encrypt.as_secs_f64() + persist)
        + commits * (costs.apply_churn.as_secs_f64() + persist);

    Day {
        inbound: groups
            * (received * costs.app_payload as f64 + commits * costs.churn_commit as f64),
        outbound: groups * sent * costs.app_payload as f64,
        cpu: groups * cpu,
        steady: groups * costs.group_dir_bytes as f64,
        growth: groups * commits * costs.epoch_bytes as f64,
    }
}

fn report_units(big: &UnitCosts, small: &UnitCosts) {
    for costs in [big, small] {
        eprintln!(
            "C0 suite 0x{:04X}  N {:4}  MEASURED units: message {} B  churn commit {} B  \
             Welcome {} B  group on disk {} B  epoch {} B  \
             decrypt {:.3} ms  encrypt {:.3} ms  apply {:.3} ms  save {:.3} ms",
            costs.suite.id(),
            costs.size,
            costs.app_payload,
            costs.churn_commit,
            costs.founding_welcome,
            costs.group_dir_bytes,
            costs.epoch_bytes,
            costs.decrypt.as_secs_f64() * 1000.0,
            costs.encrypt.as_secs_f64() * 1000.0,
            costs.apply_churn.as_secs_f64() * 1000.0,
            costs.save.as_secs_f64() * 1000.0,
        );
    }
    eprintln!(
        "C0 one-time: joining all {} groups costs {} B of Welcomes",
        BIG.1 + SMALL.1,
        BIG.1 * big.founding_welcome + SMALL.1 * small.founding_welcome,
    );
}

fn mb(bytes: f64) -> f64 {
    bytes / 1_000_000.0
}
