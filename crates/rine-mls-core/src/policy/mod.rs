//! One owner for rine's MLS lifecycle policy: how far back a group keeps epoch
//! secrets ([`mod@retention`]), and how many KeyPackages an agent keeps
//! published ([`mod@key_packages`]).
//!
//! These numbers decide what a returning agent can still read and whether a
//! peer can still add it to a group. Stating each of them once, here, is what
//! keeps the TypeScript and Python stacks from drifting into two policies for
//! one protocol — both bindings read these values rather than restating them.

mod key_packages;
mod retention;

pub use key_packages::{
    key_package_shortfall, KEY_PACKAGE_LOW_WATER, KEY_PACKAGE_MAX_BATCH, KEY_PACKAGE_TARGET,
};
pub use retention::{EpochRetention, EPOCH_RETENTION_DEFAULT, MESSAGE_RETENTION_DAYS};
