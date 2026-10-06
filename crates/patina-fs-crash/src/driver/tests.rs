//! Tests for filesystem driver operations and dirty-page tracking.

use super::DIRTY_PAGE;
use crate::CrashFs;
use crate::tests::{lossy, write};
use patina_dst_abi::{FsAllocateMode, FsClock, FsEntryKind, OpenFlags, SeekWhence};
use patina_dst_driver_api::FsDriver;

#[test]
fn positional_write_is_crash_losable_exactly_like_a_cursor_write() {
    // A page-oriented database writes every page through pwrite (write_at),
    // so a positional write MUST be as crash-losable as a cursor write --
    // otherwise the crash campaign would silently miss its real durability
    // boundary. CrashFs overrides write_at so an append-mode descriptor
    // cannot redirect the explicit offset; the write is still journaled
    // through the same live-vs-durable model. This is the
    // load-bearing guarantee for the whole positional-I/O rung.
    const OFFSET: u64 = 1024;

    // Unsynced positional write is dropped: after a durable zero baseline,
    // a pwrite that is never fsynced reverts on crash.
    let mut fs = CrashFs::default();
    let fd = fs
        .open(FsClock::EPOCH, "/db", OpenFlags::create_truncate_write())
        .unwrap();
    fs.set_len(FsClock::EPOCH, fd, 4096).unwrap();
    fs.sync(fd).unwrap(); // durable baseline: 4096 zero bytes
    fs.sync_directory("/").unwrap(); // durable namespace entry
    fs.write_at(FsClock::EPOCH, fd, OFFSET, b"positional")
        .unwrap();
    fs.crash().unwrap();
    let after = fs.contents("/db").unwrap();
    assert!(
        !after
            .windows(b"positional".len())
            .any(|w| w == b"positional"),
        "an unsynced positional write survived a crash"
    );

    // A positional write that IS fsynced survives byte-for-byte.
    let mut fs = CrashFs::default();
    let fd = fs
        .open(FsClock::EPOCH, "/db", OpenFlags::create_truncate_write())
        .unwrap();
    fs.set_len(FsClock::EPOCH, fd, 4096).unwrap();
    fs.write_at(FsClock::EPOCH, fd, OFFSET, b"positional")
        .unwrap();
    fs.sync(fd).unwrap();
    fs.sync_directory("/").unwrap();
    fs.crash().unwrap();
    let after = fs.contents("/db").unwrap();
    let start = OFFSET as usize;
    assert_eq!(
        &after[start..start + b"positional".len()],
        b"positional",
        "a synced positional write did not survive a crash"
    );

    // A positional read reaches the written bytes WITHOUT disturbing the
    // shared cursor -- the property that makes positional I/O sound under
    // concurrency (no crash involved).
    let mut fs = CrashFs::default();
    let read_write = OpenFlags {
        read: true,
        write: true,
        create: true,
        truncate: true,
        append: false,
        exclusive: false,
        path_only: false,
        mode: patina_dst_abi::DEFAULT_FILE_CREATE_MODE,
    };
    let fd = fs.open(FsClock::EPOCH, "/db", read_write).unwrap();
    fs.set_len(FsClock::EPOCH, fd, 4096).unwrap();
    fs.write_at(FsClock::EPOCH, fd, OFFSET, b"positional")
        .unwrap();
    fs.seek(fd, 0, SeekWhence::Start).unwrap();
    let positional = fs
        .read_at(FsClock::EPOCH, fd, OFFSET, b"positional".len())
        .unwrap();
    assert_eq!(positional, b"positional");
    let cursor_pos = fs.seek(fd, 0, SeekWhence::Current).unwrap();
    assert_eq!(cursor_pos, 0, "read_at disturbed the shared cursor");

    fs.seek(fd, 1, SeekWhence::Start).unwrap();
    fs.write_at(FsClock::EPOCH, fd, OFFSET + 32, b"X").unwrap();
    fs.write(FsClock::EPOCH, fd, b"Y").unwrap();
    let after = fs.contents("/db").unwrap();
    assert_eq!(after[1], b'Y', "write_at moved the shared cursor");
    assert_eq!(after[OFFSET as usize + 32], b'X');
}

/// A page is dirty from a write until a durability point: an fsync of
/// its file, a whole-volume sync or a crash; a truncation (an `O_TRUNC`
/// open included) drops the pages past the new end, a punched or zeroed
/// range its whole pages, and a positional write dirties its pages. A
/// file with no name or descriptor left keeps none.
#[test]
fn written_pages_are_dirty_until_made_durable() {
    let page = DIRTY_PAGE as usize;
    let mut fs = CrashFs::default();
    let fd = write(&mut fs, "/f", &vec![b'x'; 3 * page]);
    let dirty = |fs: &mut CrashFs| fs.dirty_pages(fd, 0, u64::MAX).unwrap();
    assert_eq!(dirty(&mut fs), 3);
    assert_eq!(fs.dirty_pages(fd, 1, 1).unwrap(), 1);
    fs.set_len(FsClock::EPOCH, fd, page as u64 + 1).unwrap();
    assert_eq!(dirty(&mut fs), 2);
    fs.sync(fd).unwrap();
    assert_eq!(dirty(&mut fs), 0);
    fs.write_at(FsClock::EPOCH, fd, page as u64 - 1, b"yz")
        .unwrap();
    assert_eq!(dirty(&mut fs), 2);
    fs.sync_all().unwrap();
    assert_eq!(dirty(&mut fs), 0);
    fs.write_at(FsClock::EPOCH, fd, 0, b"w").unwrap();
    fs.crash().unwrap();
    assert_eq!(dirty(&mut fs), 0);

    // An O_TRUNC open drops them, however far the file grows back.
    fs.write_at(FsClock::EPOCH, fd, 0, &vec![b'x'; 2 * page])
        .unwrap();
    let again = fs
        .open(FsClock::EPOCH, "/f", OpenFlags::create_truncate_write())
        .unwrap();
    fs.set_len(FsClock::EPOCH, again, 2 * page as u64).unwrap();
    assert_eq!(dirty(&mut fs), 0);

    // A punched or zeroed range is written back and its whole pages
    // dropped; a page it covers in part is zeroed, so dirty again, when
    // its block holds data. The second punch's end falls in the first
    // one's hole, which stays clean.
    fs.write_at(FsClock::EPOCH, fd, 0, &vec![b'x'; 4 * page])
        .unwrap();
    fs.allocate(
        FsClock::EPOCH,
        fd,
        page as u64,
        2 * page as u64,
        FsAllocateMode::PunchHole,
        true,
    )
    .unwrap();
    assert_eq!(dirty(&mut fs), 2);
    fs.sync(fd).unwrap();
    fs.allocate(
        FsClock::EPOCH,
        fd,
        100,
        page as u64,
        FsAllocateMode::PunchHole,
        true,
    )
    .unwrap();
    assert_eq!(dirty(&mut fs), 1);

    // A file with no name and no descriptor left has no pages to keep.
    fs.remove_file(FsClock::EPOCH, "/f").unwrap();
    assert!(!fs.dirty.is_empty(), "still open");
    fs.close(again).unwrap();
    fs.close(fd).unwrap();
    assert!(fs.dirty.is_empty());
}

#[test]
fn sync_persists_a_checkpoint_and_later_changes_are_lost() {
    let mut fs = CrashFs::default();
    let fd = write(&mut fs, "/state", b"stable");
    fs.sync(fd).unwrap();
    fs.sync_directory("/").unwrap();
    fs.write(FsClock::EPOCH, fd, b"-volatile").unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.contents("/state").unwrap(), b"stable");
}

#[test]
fn sync_all_makes_every_change_durable_at_once() {
    let mut fs = lossy();
    let fd = write(&mut fs, "/d/f", b"data");
    fs.close(fd).unwrap();
    fs.make_fifo(FsClock::EPOCH, "/d/pipe", 0o600).unwrap();
    fs.sync_all().unwrap();
    fs.crash().unwrap();
    assert_eq!(fs.contents("/d/f").unwrap(), b"data");
    assert_eq!(fs.metadata("/d/pipe").unwrap().kind, FsEntryKind::Fifo);
}
