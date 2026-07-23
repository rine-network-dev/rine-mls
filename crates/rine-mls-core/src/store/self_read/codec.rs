//! The cache file's own serialization, and the bound that keeps it small.

use super::{SELF_READ_MAX_BYTES, SELF_READ_MAX_ENTRIES};

/// Leading byte of the cache file. rine's own serialization, versioned so a
/// later format is a recognisable file rather than a corrupt one.
const FORMAT_VERSION: u8 = 1;

pub(super) const KEY_LEN: usize = 32;

pub(super) struct Entry {
    pub(super) key: [u8; KEY_LEN],
    pub(super) envelope: Vec<u8>,
}

pub(super) fn digest(payload: &[u8]) -> [u8; KEY_LEN] {
    libcrux_sha3::sha256(payload)
}

/// Drop oldest-first until the cache is inside both bounds, always keeping the
/// entry just written: a single envelope larger than the whole byte budget
/// still reads back once rather than vanishing on arrival.
pub(super) fn evict(entries: &mut Vec<Entry>) {
    let mut total: usize = entries.iter().map(|entry| entry.envelope.len()).sum();

    while entries.len() > 1
        && (entries.len() > SELF_READ_MAX_ENTRIES || total > SELF_READ_MAX_BYTES)
    {
        total -= entries.remove(0).envelope.len();
    }
}

pub(super) fn encode(entries: &[Entry]) -> Vec<u8> {
    let mut out = vec![FORMAT_VERSION];

    for entry in entries {
        out.extend_from_slice(&entry.key);
        out.extend_from_slice(&(entry.envelope.len() as u64).to_be_bytes());
        out.extend_from_slice(&entry.envelope);
    }

    out
}

pub(super) fn decode(bytes: &[u8]) -> Option<Vec<Entry>> {
    let (&version, mut rest) = bytes.split_first()?;
    if version != FORMAT_VERSION {
        return None;
    }

    let mut entries = Vec::new();

    while !rest.is_empty() {
        let (key, tail) = rest.split_at_checked(KEY_LEN)?;
        let (len, tail) = tail.split_at_checked(8)?;
        let len = usize::try_from(u64::from_be_bytes(len.try_into().ok()?)).ok()?;
        let (envelope, tail) = tail.split_at_checked(len)?;

        entries.push(Entry {
            key: key.try_into().ok()?,
            envelope: envelope.to_vec(),
        });
        rest = tail;
    }

    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seed: u8, size: usize) -> Entry {
        Entry {
            key: [seed; KEY_LEN],
            envelope: vec![seed; size],
        }
    }

    #[test]
    fn test_encode_when_round_tripped_preserves_every_entry_in_order() {
        let entries = vec![entry(1, 0), entry(2, 5), entry(3, 300)];

        let decoded = decode(&encode(&entries)).expect("decode");

        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[2].key, [3; KEY_LEN]);
        assert_eq!(decoded[2].envelope.len(), 300);
    }

    #[test]
    fn test_decode_when_the_file_is_truncated_reports_corruption() {
        let bytes = encode(&[entry(1, 10)]);

        assert!(decode(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn test_decode_when_the_format_version_is_unknown_is_refused() {
        assert!(decode(&[FORMAT_VERSION + 1]).is_none());
    }

    #[test]
    fn test_evict_when_over_the_entry_cap_drops_the_oldest() {
        let mut entries: Vec<Entry> = (0..SELF_READ_MAX_ENTRIES + 2)
            .map(|i| entry(i as u8, 1))
            .collect();

        evict(&mut entries);

        assert_eq!(entries.len(), SELF_READ_MAX_ENTRIES);
        assert_eq!(entries[0].envelope, vec![2u8]);
    }

    #[test]
    fn test_evict_when_over_the_byte_budget_drops_the_oldest() {
        let mut entries = vec![entry(1, SELF_READ_MAX_BYTES), entry(2, 16)];

        evict(&mut entries);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, [2; KEY_LEN]);
    }

    #[test]
    fn test_evict_when_one_entry_exceeds_the_budget_still_keeps_it() {
        let mut entries = vec![entry(9, SELF_READ_MAX_BYTES * 2)];

        evict(&mut entries);

        assert_eq!(entries.len(), 1);
    }
}
