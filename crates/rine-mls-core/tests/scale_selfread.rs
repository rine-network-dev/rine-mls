//! Open item 1 — what the self-read cache costs a sender.
//!
//! MLS forward secrecy consumes the sender's ratchet step at encryption time,
//! so a member cannot decrypt its own message; the cache is the plaintext kept
//! at the one moment the sender held it. `SelfReadCache::record` loads the
//! whole cache file, appends, evicts and rewrites it, so every send is a
//! read-modify-write of up to the cap. Bounded for disk, which is what the
//! design promised — but the I/O per send is the cap, not the message, and
//! that ratio is what decides whether it matters.
//!
//! Group size does not enter into it: the cache is per group and sized by the
//! messages this member sent, so these run on a minimal group.
//!
//! ```text
//! cargo test --release -p rine-mls-core --test scale_selfread -- --ignored --nocapture
//! ```

mod common;

use std::time::{Duration, Instant};

use common::scale::{found, millis};
use common::unit_costs::ENVELOPE_BYTES;
use common::{file_size, for_each_suite, group_dir, group_id};
use rine_mls_core::{RineCipherSuite, SELF_READ_MAX_BYTES, SELF_READ_MAX_ENTRIES};

/// Write amplification of the self-read cache, at the two saturations it has:
/// the entry cap, which small envelopes hit first, and the byte cap, which
/// large ones hit first.
///
/// Every send is a read-modify-write of the whole cache file, so a saturated
/// cache makes each send cost twice the cap in file I/O whatever the message
/// weighed. That is bounded — which is what the design promised — but it is not
/// free, and the ratio to the message itself is the number that decides whether
/// it matters.
///
/// ```text
/// cargo test --release -p rine-mls-core --test scale_selfread -- --ignored --nocapture
/// ```
#[test]
#[ignore = "300 sends per saturation mode per suite"]
fn test_self_read_cache_write_amplification_when_the_cache_is_saturated() {
    for_each_suite(|suite| {
        // 500-byte envelopes saturate on the entry cap (256 x 500 B is well
        // under the byte cap); 8 kB ones saturate on the byte cap first.
        saturate(suite, ENVELOPE_BYTES, SELF_READ_MAX_ENTRIES + 44, "entries");
        saturate(suite, 8192, SELF_READ_MAX_BYTES / 8192 + 44, "bytes");
    });
}

/// Send `sends` messages of `envelope_bytes` into a minimal group, then time
/// what one further send costs once the cache is full.
fn saturate(suite: RineCipherSuite, envelope_bytes: usize, sends: usize, mode: &str) {
    let mut cohort = found(3, 2, suite, 0xC1, 0);
    let cache = group_dir(cohort.agents[0].store_path(), &group_id(0xC1)).join("self_read.bin");
    let envelope = vec![0x5A; envelope_bytes];
    let sender = &mut cohort.groups[0];

    let started = Instant::now();
    sender
        .encrypt_application_message(&envelope)
        .expect("first send");
    let cold = started.elapsed();

    for _ in 1..sends {
        sender.encrypt_application_message(&envelope).expect("send");
    }
    let saturated_bytes = file_size(&cache);

    let mut hot = Duration::ZERO;
    for _ in 0..32 {
        let started = Instant::now();
        sender
            .encrypt_application_message(&envelope)
            .expect("send at a full cache");
        hot += started.elapsed();
    }
    let hot = hot / 32;

    eprintln!(
        "B4 suite 0x{:04X}  self-read saturated by {mode}  envelope {envelope_bytes:5} B  \
         after {sends:4} sends: cache {saturated_bytes:8} B  \
         read+write per send {:8} B ({:5.1}x the envelope)  \
         send cold {:7.3} ms -> full {:7.3} ms",
        suite.id(),
        saturated_bytes * 2,
        (saturated_bytes * 2) as f64 / envelope_bytes as f64,
        millis(cold),
        millis(hot),
    );
}
