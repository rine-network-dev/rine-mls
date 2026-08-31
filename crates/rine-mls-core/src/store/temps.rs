//! The temp file every state write goes through: named so no two writers can
//! pick the same one, and reclaimed when the writer that opened it dies.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Distinguishes concurrent writes inside one process. A counter rather than
/// entropy: two writers only have to differ, and a number is readable in a
/// directory listing when a crash leaves one behind.
static WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

/// How long a temp file must have sat untouched before a later save reclaims
/// it. One write opens, fills, fsyncs and renames inside a single call, so a
/// temp this old belongs to a writer that died between the open and the
/// rename — and by then the pid in its name may have been reused, which is why
/// the rule is age rather than liveness. The margin is what makes age safe: a
/// temp file is never what a reader opens, so the worst a wrongly swept one can
/// do is fail that single save loudly at its rename.
const STALE_TEMP_AGE: Duration = Duration::from_secs(60 * 60);

/// A temp path no other writer can also pick.
///
/// A name derived from the destination alone is shared by every writer of that
/// file: two processes saving the same group would open the *same* temp path,
/// truncate it under each other, interleave their writes and both rename it
/// into place — leaving a splice of two states, which no reader can recover
/// from. The pid separates processes, [`WRITE_SEQ`] separates writers within
/// one.
///
/// The suffix is appended rather than replacing the extension, so the name ends
/// in `.tmp` and never in `.bin`: the epoch and KeyPackage listings select
/// entries by that extension, and a temp file that looked like a `.bin` would
/// be counted as an epoch that has no readable state.
pub(super) fn temp_path(path: &Path) -> PathBuf {
    let seq = WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.{seq}.tmp", std::process::id()));

    path.with_file_name(name)
}

/// Delete temps for `path` that were left behind by writers which died before
/// their rename.
///
/// A temp holds the whole serialized state — retired epoch secrets included —
/// at 0600, and the `.bin` listings skip it, so nothing else would ever remove
/// it. Only temps of this same destination are considered, so saving
/// `epochs/1.bin` cannot touch the in-flight temp of `epochs/10.bin`.
///
/// Matching is on the `<destination>.<pid>.<seq>.tmp` shape [`temp_path`]
/// builds. 0.1.0 named its temp by replacing the destination's extension —
/// `epochs/1.bin` was written through `epochs/1.tmp` — so a temp abandoned by a
/// 0.1.0 writer carries no destination prefix, does not match, and stays on
/// disk with its secrets until it is removed by hand.
///
/// Best-effort by design: it runs after the rename that already made the new
/// state durable, so a directory that cannot be listed or an entry that cannot
/// be removed is not a reason to report a save that succeeded as failed.
pub(super) fn sweep_stale_temps(path: &Path) {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    let mut prefix = name.to_os_string();
    prefix.push(".");

    for entry in entries.flatten() {
        let candidate = entry.file_name();
        let bytes = candidate.as_encoded_bytes();
        if !bytes.starts_with(prefix.as_encoded_bytes()) || !bytes.ends_with(b".tmp") {
            continue;
        }

        let abandoned = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .is_ok_and(|written| written.elapsed().is_ok_and(|age| age >= STALE_TEMP_AGE));

        if abandoned {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::FileTimes;
    use std::time::SystemTime;

    use super::super::files::write_private;
    use super::*;

    /// A temp file of the shape [`temp_path`] builds, backdated by `age` so the
    /// sweep sees the writer that opened it as gone.
    fn temp(dir: &Path, name: &str, age: Duration) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, b"serialized group state, epoch secrets and all").expect("temp");
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open temp")
            .set_times(FileTimes::new().set_modified(SystemTime::now() - age))
            .expect("backdate temp");

        path
    }

    #[test]
    fn test_save_when_a_writer_died_before_its_rename_reclaims_the_temp() {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = dir.path().join("state.bin");
        let orphan = temp(
            dir.path(),
            "state.bin.4242.0.tmp",
            STALE_TEMP_AGE + Duration::from_secs(60),
        );

        write_private(&state, b"the state this save wrote").expect("write");

        assert!(
            !orphan.exists(),
            "a temp left by a dead writer keeps a full copy of the group's secrets on disk",
        );
        assert_eq!(
            fs::read(&state).expect("read"),
            b"the state this save wrote",
        );
    }

    #[test]
    fn test_save_when_another_writer_is_mid_save_leaves_its_temp_alone() {
        let dir = tempfile::tempdir().expect("temp dir");
        let epoch = dir.path().join("1.bin");
        let in_flight = temp(dir.path(), "1.bin.4242.7.tmp", Duration::ZERO);
        let other_epoch = temp(
            dir.path(),
            "10.bin.4242.0.tmp",
            STALE_TEMP_AGE + Duration::from_secs(60),
        );

        write_private(&epoch, b"epoch 1").expect("write");

        assert!(
            in_flight.exists(),
            "removing a live writer's temp fails its rename — the failure unique temp \
             names exist to prevent",
        );
        assert!(
            other_epoch.exists(),
            "a save sweeps only the temps of the file it is writing",
        );
        assert_eq!(fs::read(&epoch).expect("read"), b"epoch 1");
    }
}
