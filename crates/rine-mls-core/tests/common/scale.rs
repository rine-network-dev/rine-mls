//! Building the large groups the `#[ignore]`d scale measurements run on.
//!
//! Everything here exists because a thousand-member group is expensive in a way
//! a correctness test never is: a thousand agents is a thousand state
//! directories, and one founding commit at that size produces a thousand
//! Welcomes that each carry the whole ratchet tree. So members that only need
//! to exist as leaves are minted and dropped, and the ones that have to stay
//! alive are named — MLS will not decrypt a message for the member that sent
//! it, so every data-plane number needs at least a second live participant.

use std::time::{Duration, Instant};

use rine_mls_core::{CommitBundle, RineCipherSuite, RineMlsError, RineMlsGroup};

use super::{base64_len, group_id, TestAgent};

/// Mint one KeyPackage each for `count` distinct agents.
///
/// The agents are dropped on the way out. Founding needs only the public
/// KeyPackage of each member; keeping a thousand clients open so each one could
/// in principle process its own Welcome costs a thousand temp directories to
/// prove nothing these measurements are about.
pub fn key_packages(first: u32, count: usize, suite: RineCipherSuite) -> Vec<Vec<u8>> {
    (0..count)
        .map(|n| {
            TestAgent::indexed(first + n as u32, suite)
                .client
                .generate_key_package()
                .expect("key package")
        })
        .collect()
}

/// A founded group of `size` members, `agents.len()` of which are real clients
/// that processed their own Welcome and can commit, decrypt and be measured.
///
/// The founding bundle itself is not kept — at a thousand members it is
/// gigabytes of Welcomes — only what it weighed.
pub struct Cohort {
    pub size: usize,
    /// Live agents, founder first.
    pub agents: Vec<TestAgent>,
    /// One group handle per live agent, in the same order.
    pub groups: Vec<RineMlsGroup>,
    /// base64 bytes of the founding commit, of one Welcome and of the
    /// GroupInfo, plus the aggregate of every Welcome the founding produced.
    pub commit: usize,
    pub welcome: usize,
    pub group_info: usize,
    pub welcomes_total: usize,
    pub found_in: Duration,
    pub join_in: Duration,
}

impl Cohort {
    /// The founder's handle and every other live member's, borrowed at once —
    /// what a measurement needs to mint a commit on one member and time
    /// another applying it.
    pub fn split(&mut self) -> (&mut RineMlsGroup, &mut [RineMlsGroup]) {
        let (founder, rest) = self.groups.split_at_mut(1);

        (&mut founder[0], rest)
    }
}

/// Found a group of `size` members — the founder included — in one commit, and
/// walk `live - 1` of them through their Welcomes.
///
/// `tag` is the rine group UUID's fill byte and `first` the seed index the
/// agents start at; two groups alive in the same process must differ in both.
pub fn found(size: usize, live: usize, suite: RineCipherSuite, tag: u8, first: u32) -> Box<Cohort> {
    assert!(
        live >= 2 && size >= live,
        "a cohort needs a founder and at least one live peer, and cannot have more \
         live members than members"
    );

    let agents: Vec<TestAgent> = (0..live as u32)
        .map(|n| TestAgent::indexed(first + n, suite))
        .collect();

    let mut packages: Vec<Vec<u8>> = agents[1..]
        .iter()
        .map(|agent| agent.client.generate_key_package().expect("key package"))
        .collect();
    packages.extend(key_packages(first + live as u32, size - live, suite));

    let started = Instant::now();
    let (group, bundle) = agents[0]
        .client
        .create_group_with_members(&group_id(tag), &packages)
        .expect("founding commit");
    let found_in = started.elapsed();

    let started = Instant::now();
    let mut groups = vec![group];
    for (agent, welcome) in agents[1..].iter().zip(&bundle.welcomes) {
        groups.push(
            agent
                .client
                .join_from_welcome(welcome)
                .expect("member joins from its Welcome"),
        );
    }
    let join_in = started.elapsed() / (live as u32 - 1);

    Box::new(Cohort {
        size,
        agents,
        groups,
        commit: base64_len(bundle.commit.len()),
        welcome: base64_len(bundle.welcomes[0].len()),
        group_info: base64_len(bundle.group_info.len()),
        welcomes_total: bundle.welcomes.iter().map(|w| base64_len(w.len())).sum(),
        found_in,
        join_in,
    })
}

/// What one commit produced, in base64 bytes, and how long the live peer took
/// to apply it.
pub struct Commit {
    pub commit: usize,
    /// Zero when the commit admitted nobody.
    pub welcome: usize,
    pub welcomes: usize,
    pub group_info: usize,
    pub apply: Duration,
}

/// Mint one commit on the founder's handle, weigh it, and time the peer
/// applying it. Every steady-state commit measurement goes through here, so
/// "what it weighed" and "what it cost to apply" are always taken on the same
/// commit rather than on two runs that drifted apart.
pub fn commit<F>(cohort: &mut Cohort, mint: F) -> Commit
where
    F: FnOnce(&mut RineMlsGroup) -> Result<CommitBundle, RineMlsError>,
{
    let (committer, receivers) = cohort.split();
    let bundle = mint(committer).expect("commit");

    let started = Instant::now();
    receivers[0]
        .apply_commit(&bundle.commit)
        .expect("peer applies the commit");
    let apply = started.elapsed();

    Commit {
        commit: base64_len(bundle.commit.len()),
        welcome: bundle.welcomes.first().map_or(0, |w| base64_len(w.len())),
        welcomes: bundle.welcomes.len(),
        group_info: base64_len(bundle.group_info.len()),
        apply,
    }
}

/// Seconds as a float, for tables where a `Duration`'s own formatting would
/// switch units between rows and stop the column being comparable.
pub fn secs(duration: Duration) -> f64 {
    duration.as_secs_f64()
}

/// Milliseconds, for the per-operation columns.
pub fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}
