//! The KeyPackage pool an agent keeps published, and how it is topped up.

/// Inventory an agent's published KeyPackage pool is topped back up to.
///
/// The same value the TypeScript stack replenishes to, deliberately: an
/// inventory policy that differs by language is an agent that is addable from
/// one surface and not from another.
pub const KEY_PACKAGE_TARGET: usize = 10;

/// Inventory at or above which replenishment is a no-op.
pub const KEY_PACKAGE_LOW_WATER: usize = 3;

/// The largest batch of KeyPackages one publish call may mint.
///
/// A KeyPackage on the post-quantum suite is roughly 3.5 kB once base64'd, and
/// the server accepts up to 100 of them in a single `packages` array — a
/// ~357 kB request body, with no request-body ceiling configured anywhere in
/// rine's proxy or app tier to catch it. The cap therefore has to be applied by
/// the client, and it is applied here: 32 packages is about 114 kB, three times
/// [`KEY_PACKAGE_TARGET`] so a full drain-and-republish is still one request,
/// and far below the server's own 200-package inventory cap.
pub const KEY_PACKAGE_MAX_BATCH: usize = 32;

/// How many KeyPackages to mint given the inventory an agent still holds.
///
/// Low-water, not top-of-every-call: an agent at or above
/// [`KEY_PACKAGE_LOW_WATER`] mints nothing, and one below it goes back to
/// [`KEY_PACKAGE_TARGET`] in a single batch.
pub const fn key_package_shortfall(available: usize) -> usize {
    if available >= KEY_PACKAGE_LOW_WATER {
        return 0;
    }

    KEY_PACKAGE_TARGET.saturating_sub(available)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_package_shortfall_when_inventory_is_healthy_mints_nothing() {
        assert_eq!(key_package_shortfall(KEY_PACKAGE_LOW_WATER), 0);
        assert_eq!(key_package_shortfall(KEY_PACKAGE_TARGET), 0);
    }

    #[test]
    fn test_key_package_shortfall_when_inventory_is_low_refills_to_target() {
        assert_eq!(key_package_shortfall(KEY_PACKAGE_LOW_WATER - 1), 8);
        assert_eq!(key_package_shortfall(0), KEY_PACKAGE_TARGET);
    }

    #[test]
    fn test_key_package_shortfall_never_exceeds_the_publish_batch_cap() {
        assert!(key_package_shortfall(0) <= KEY_PACKAGE_MAX_BATCH);
    }
}
