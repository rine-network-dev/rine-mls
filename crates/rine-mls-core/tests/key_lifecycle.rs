//! An agent's KeyPackage pool: inventory, low-water replenishment, the
//! client-side publish cap, and the release-time drain.

mod common;

use std::fs;

use common::{for_each_suite, group_id, TestAgent};
use rine_mls_core::{
    RineCipherSuite, RineMlsErrorCode, KEY_PACKAGE_LOW_WATER, KEY_PACKAGE_MAX_BATCH,
    KEY_PACKAGE_TARGET,
};

/// The server's `packages` array is capped at 100 entries, so a client cap
/// above that would be refused by the server before the body size ever
/// mattered. Checked at compile time because it can be.
const _: () = assert!(KEY_PACKAGE_MAX_BATCH <= 100);

/// Base64 of `n` bytes, which is the size the rine control plane actually
/// sends. No base64 dependency needed to know it.
fn base64_len(n: usize) -> usize {
    4 * n.div_ceil(3)
}

fn stored_files(agent: &TestAgent) -> usize {
    match fs::read_dir(agent.store_path().join("key_packages")) {
        Ok(entries) => entries.count(),
        Err(_) => 0,
    }
}

#[test]
fn test_key_package_when_minted_is_on_disk_before_it_could_be_published() {
    for_each_suite(|suite| {
        let agent = TestAgent::new(1, suite);

        let blob = agent.client.generate_key_package().expect("mint");

        assert!(!blob.is_empty());
        assert_eq!(
            stored_files(&agent),
            1,
            "the private half must already be stored when the public blob is \
             handed to the caller: a KeyPackage the server can hand out but we \
             cannot open yields a Welcome nobody can ever process",
        );
        assert_eq!(agent.client.key_package_count().expect("count"), 1);
    });
}

#[test]
fn test_key_package_count_when_the_pool_is_untouched_is_zero() {
    let agent = TestAgent::new(1, RineCipherSuite::DEFAULT);

    assert_eq!(agent.client.key_package_count().expect("count"), 0);
}

#[test]
fn test_generate_key_packages_when_asked_for_a_batch_mints_exactly_that_many() {
    let agent = TestAgent::new(1, RineCipherSuite::DEFAULT);

    let batch = agent.client.generate_key_packages(5).expect("mint batch");

    assert_eq!(batch.len(), 5);
    assert_eq!(agent.client.key_package_count().expect("count"), 5);
}

#[test]
fn test_generate_key_packages_when_the_batch_exceeds_the_cap_is_refused_outright() {
    let agent = TestAgent::new(1, RineCipherSuite::DEFAULT);

    let err = agent
        .client
        .generate_key_packages(KEY_PACKAGE_MAX_BATCH + 1)
        .expect_err("over the publish cap");

    assert_eq!(err.code(), RineMlsErrorCode::KeyPackageBatchTooLarge);
    assert_eq!(
        agent.client.key_package_count().expect("count"),
        0,
        "an over-cap request must mint nothing, not a truncated batch the \
         caller would mistake for the inventory it asked for",
    );
}

#[test]
fn test_publish_batch_at_the_cap_stays_inside_one_request_body() {
    // The server accepts a hundred packages per request and no proxy or
    // app-tier body limit exists to catch what that weighs on the PQ suite, so
    // the cap is the client's to hold. This pins what the cap actually costs.
    let agent = TestAgent::new(1, RineCipherSuite::XWing);

    let batch = agent
        .client
        .generate_key_packages(KEY_PACKAGE_MAX_BATCH)
        .expect("mint the largest batch allowed");

    let body: usize = batch.iter().map(|blob| base64_len(blob.len())).sum();

    assert!(
        body <= 128 * 1024,
        "a full-cap post-quantum publish is {body} base64 bytes; the cap exists \
         to keep this well under any plausible request-body ceiling",
    );
}

#[test]
fn test_replenish_key_packages_when_inventory_is_healthy_mints_nothing() {
    let agent = TestAgent::new(1, RineCipherSuite::DEFAULT);
    agent
        .client
        .generate_key_packages(KEY_PACKAGE_LOW_WATER)
        .expect("seed the pool");

    let batch = agent.client.replenish_key_packages().expect("replenish");

    assert!(batch.is_empty(), "at the low-water mark is not below it");
    assert_eq!(
        agent.client.key_package_count().expect("count"),
        KEY_PACKAGE_LOW_WATER
    );
}

#[test]
fn test_replenish_key_packages_when_inventory_is_low_refills_to_target() {
    let agent = TestAgent::new(1, RineCipherSuite::DEFAULT);
    agent
        .client
        .generate_key_packages(KEY_PACKAGE_LOW_WATER - 1)
        .expect("seed the pool");

    let batch = agent.client.replenish_key_packages().expect("replenish");

    assert_eq!(
        batch.len(),
        KEY_PACKAGE_TARGET - (KEY_PACKAGE_LOW_WATER - 1)
    );
    assert_eq!(
        agent.client.key_package_count().expect("count"),
        KEY_PACKAGE_TARGET
    );
}

#[test]
fn test_replenish_key_packages_when_the_pool_is_empty_mints_a_full_target() {
    let agent = TestAgent::new(1, RineCipherSuite::DEFAULT);

    let batch = agent.client.replenish_key_packages().expect("replenish");

    assert_eq!(batch.len(), KEY_PACKAGE_TARGET);
}

#[test]
fn test_replenish_key_packages_when_a_peer_consumed_one_tops_the_pool_back_up() {
    let suite = RineCipherSuite::DEFAULT;
    let alice = TestAgent::new(1, suite);
    let bob = TestAgent::new(2, suite);

    // Bob publishes a pool sitting exactly at the low-water mark; Alice adds
    // him, which consumes one of those packages for real.
    let pool = bob
        .client
        .generate_key_packages(KEY_PACKAGE_LOW_WATER)
        .expect("seed the pool");

    let (mut group, _) = alice.client.create_group(&group_id(0xE1)).expect("create");
    let add = group.add_member(&pool[0]).expect("add commit");
    bob.client
        .join_from_welcome(&add.welcomes[0])
        .expect("welcome join")
        .save()
        .expect("persist");

    assert_eq!(
        bob.client.key_package_count().expect("count"),
        KEY_PACKAGE_LOW_WATER - 1,
        "a processed Welcome consumes the package it joined with",
    );

    let batch = bob.client.replenish_key_packages().expect("replenish");

    assert_eq!(
        batch.len(),
        KEY_PACKAGE_TARGET - (KEY_PACKAGE_LOW_WATER - 1)
    );
    assert_eq!(
        bob.client.key_package_count().expect("count"),
        KEY_PACKAGE_TARGET,
        "an agent whose pool a peer drew from tops itself back up: only the \
         pool's owner can, and the adder that hits an empty pool cannot",
    );
}

#[test]
fn test_drain_and_republish_when_the_pool_is_pre_cutover_replaces_all_of_it() {
    for_each_suite(|suite| {
        let agent = TestAgent::new(1, suite);
        let stale = agent
            .client
            .generate_key_packages(4)
            .expect("a pre-cutover pool");

        let fresh = agent
            .client
            .drain_and_republish_key_packages()
            .expect("drain and republish");

        assert_eq!(fresh.len(), KEY_PACKAGE_TARGET);
        assert_eq!(
            agent.client.key_package_count().expect("count"),
            KEY_PACKAGE_TARGET,
            "the drained private halves must be gone, not merely outnumbered",
        );
        for old in &stale {
            assert!(
                !fresh.contains(old),
                "a republished pool shares nothing with the pool it replaced",
            );
        }
    });
}

#[test]
fn test_drain_and_republish_when_the_pool_is_empty_still_publishes_a_full_pool() {
    let agent = TestAgent::new(1, RineCipherSuite::DEFAULT);

    let fresh = agent
        .client
        .drain_and_republish_key_packages()
        .expect("drain and republish");

    assert_eq!(fresh.len(), KEY_PACKAGE_TARGET);
}
