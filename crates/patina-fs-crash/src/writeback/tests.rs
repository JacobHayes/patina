//! Tests for writeback errors: dropped pages and once-per-description reports.

use crate::CrashFs;
use crate::tests::write;
use patina_dst_abi::{CrashKind, ErrorCode, FsAllocateMode, FsClock, OpenFlags, SeekWhence};
use patina_dst_driver_api::FsDriver;

/// A durable `/log` holding `synced`, with `pending` written over it unsynced.
fn log_with_pending(synced: &[u8], pending: &[u8]) -> (CrashFs, patina_dst_abi::Fd) {
    let mut fs = CrashFs::default();
    let fd = write(&mut fs, "/log", synced);
    fs.sync(fd).unwrap();
    fs.write(FsClock::EPOCH, fd, pending).unwrap();
    (fs, fd)
}

fn on_disk(fs: &mut CrashFs, path: &str) -> Vec<u8> {
    fs.crash_and_snapshot(FsClock::EPOCH, CrashKind::Machine)
        .unwrap()
        .into_memfs()
        .contents(path)
        .unwrap()
}

/// The pages a writeback error dropped stay readable but clean, so neither a
/// retried `fsync` nor `sync(2)` puts them on disk, and a machine crash
/// brings back what the disk held there (the size the append reached is
/// kept). A process crash keeps the page cache.
#[test]
fn a_failed_writeback_keeps_the_bytes_cached_but_never_durable() {
    let (mut fs, fd) = log_with_pending(b"committed;", b"acknowledged;");
    fs.fail_writeback(fd, ErrorCode::Io).unwrap();
    assert_eq!(fs.contents("/log").unwrap(), b"committed;acknowledged;");
    assert_eq!(fs.dirty_pages(fd, 0, 0).unwrap(), 0);

    fs.sync(fd).unwrap();
    fs.sync_all().unwrap();
    let process = fs
        .crash_and_snapshot(FsClock::EPOCH, CrashKind::Process)
        .unwrap()
        .into_memfs();
    assert_eq!(
        process.contents("/log").unwrap(),
        b"committed;acknowledged;"
    );
    let mut expected = b"committed;".to_vec();
    expected.resize(b"committed;acknowledged;".len(), 0);
    assert_eq!(on_disk(&mut fs, "/log"), expected);
}

/// Writing a dropped page again dirties all of it, and the next successful
/// `fsync` writes it whole, the bytes the error dropped included.
#[test]
fn rewriting_a_dropped_page_makes_it_durable_at_the_next_fsync() {
    let (mut fs, fd) = log_with_pending(b"committed;", b"acknowledged;");
    fs.fail_writeback(fd, ErrorCode::NoSpace).unwrap();
    fs.write(FsClock::EPOCH, fd, b"retried;").unwrap();
    fs.sync(fd).unwrap();
    assert_eq!(on_disk(&mut fs, "/log"), b"committed;acknowledged;retried;");
}

/// A page the error dropped stays off disk while the file's other pages,
/// written later, reach it, and the size the appends reached is kept.
#[test]
fn only_the_dropped_pages_stay_off_disk() {
    let page = 4096;
    let (mut fs, fd) = log_with_pending(&vec![b'a'; page], &vec![b'b'; page]);
    fs.fail_writeback(fd, ErrorCode::Io).unwrap();
    fs.write(FsClock::EPOCH, fd, &vec![b'c'; page]).unwrap();
    fs.sync(fd).unwrap();
    let mut expected = vec![b'a'; page];
    expected.extend(vec![0; page]);
    expected.extend(vec![b'c'; page]);
    assert_eq!(on_disk(&mut fs, "/log"), expected);

    let (mut fs, fd) = log_with_pending(b"a", b"b");
    fs.fail_writeback(fd, ErrorCode::Io).unwrap();
    fs.sync(fd).unwrap();
    assert_eq!(on_disk(&mut fs, "/log"), b"a\0");
}

/// Truncating through a dropped page zeroes its tail through the block,
/// which dirties the page, so the next `fsync` writes what is left of it.
#[test]
fn truncating_through_a_dropped_page_dirties_it_again() {
    let (mut fs, fd) = log_with_pending(&[b'a'; 4096], &[]);
    fs.seek(fd, 0, SeekWhence::Start).unwrap();
    fs.write(FsClock::EPOCH, fd, &[b'b'; 4096]).unwrap();
    fs.fail_writeback(fd, ErrorCode::Io).unwrap();
    fs.set_len(FsClock::EPOCH, fd, 2048).unwrap();
    fs.sync(fd).unwrap();
    assert_eq!(on_disk(&mut fs, "/log"), vec![b'b'; 2048]);
}

/// A hole punched past the end changes nothing, so a dropped page stays off
/// disk.
#[test]
fn a_punch_past_the_end_leaves_a_dropped_page_dropped() {
    let (mut fs, fd) = log_with_pending(&[b'a'; 2000], &[]);
    fs.seek(fd, 0, SeekWhence::Start).unwrap();
    fs.write(FsClock::EPOCH, fd, &[b'b'; 2000]).unwrap();
    fs.fail_writeback(fd, ErrorCode::Io).unwrap();
    fs.allocate(FsClock::EPOCH, fd, 3000, 1, FsAllocateMode::PunchHole, true)
        .unwrap();
    fs.sync(fd).unwrap();
    assert_eq!(on_disk(&mut fs, "/log"), vec![b'a'; 2000]);
}

/// The error reaches every open file description of the file once: the
/// failing one at once, another open at the time on its next `fsync` (which
/// still writes back what is dirty), its duplicate never again, and a
/// description opened afterwards, or of another file, not at all.
#[test]
fn a_writeback_error_reports_once_per_open_description() {
    let (mut fs, failing) = log_with_pending(b"committed;", b"lost;");
    let read_write = OpenFlags {
        read: true,
        write: true,
        ..OpenFlags::read_only()
    };
    let other = fs.open(FsClock::EPOCH, "/log", read_write).unwrap();
    let duplicate = fs.dup(other).unwrap();
    let unrelated = write(&mut fs, "/other", b"x");
    fs.fail_writeback(failing, ErrorCode::NoSpace).unwrap();
    let later = fs.open(FsClock::EPOCH, "/log", read_write).unwrap();

    assert!(fs.sync(failing).is_ok());
    assert!(fs.sync(later).is_ok());
    assert!(fs.sync(unrelated).is_ok());

    fs.seek(other, 0, SeekWhence::End).unwrap();
    fs.write(FsClock::EPOCH, other, b"kept;").unwrap();
    let reported = fs.sync(other).unwrap_err();
    assert_eq!(reported.code, ErrorCode::NoSpace);
    assert!(fs.sync(other).is_ok());
    assert!(fs.sync(duplicate).is_ok());
    // Its write dirtied the page the error dropped, so the whole page went.
    assert_eq!(on_disk(&mut fs, "/log"), b"committed;lost;kept;");
}

/// A description closed with the error unseen takes it with it; another
/// that was open keeps its own.
#[test]
fn closing_a_description_drops_only_its_unseen_error() {
    let (mut fs, failing) = log_with_pending(b"committed;", b"lost;");
    let first = fs
        .open(FsClock::EPOCH, "/log", OpenFlags::read_only())
        .unwrap();
    let second = fs
        .open(FsClock::EPOCH, "/log", OpenFlags::read_only())
        .unwrap();
    fs.fail_writeback(failing, ErrorCode::Io).unwrap();
    fs.close(first).unwrap();
    assert_eq!(fs.sync(second).unwrap_err().code, ErrorCode::Io);
}

/// `DONTNEED` drops clean pages, so a page a writeback error dropped reads
/// back what the disk holds; a dirty page stays, and so does a page the
/// range only covers in part.
#[test]
fn dontneed_rereads_the_disk_under_a_dropped_page() {
    let page = 4096;
    let (mut fs, fd) = log_with_pending(&vec![b'a'; 2 * page], &[]);
    fs.seek(fd, 0, SeekWhence::Start).unwrap();
    fs.write(FsClock::EPOCH, fd, &vec![b'b'; 2 * page]).unwrap();
    fs.fail_writeback(fd, ErrorCode::Io).unwrap();

    // The range covers neither page whole.
    fs.drop_cache(fd, 1, 2 * page as u64 - 2).unwrap();
    assert_eq!(fs.contents("/log").unwrap(), vec![b'b'; 2 * page]);

    // Page 1 dirty again, then the whole file advised away: page 0 reads the
    // disk, page 1 keeps the write.
    fs.write_at(FsClock::EPOCH, fd, page as u64, &vec![b'c'; page])
        .unwrap();
    fs.drop_cache(fd, 0, 0).unwrap();
    let mut expected = vec![b'a'; page];
    expected.extend(vec![b'c'; page]);
    assert_eq!(fs.contents("/log").unwrap(), expected);
    // What it read back is clean and on disk already.
    fs.sync(fd).unwrap();
    assert_eq!(on_disk(&mut fs, "/log"), expected);
}

/// A range that ends at the end of the file covers its last page whole,
/// partial or not.
#[test]
fn dontneed_to_the_end_of_the_file_covers_its_last_page() {
    let (mut fs, fd) = log_with_pending(b"a", &[]);
    fs.write_at(FsClock::EPOCH, fd, 0, b"b").unwrap();
    fs.fail_writeback(fd, ErrorCode::Io).unwrap();
    fs.drop_cache(fd, 0, 1).unwrap();
    assert_eq!(fs.contents("/log").unwrap(), b"a");
}

/// An append a writeback error dropped reads back as the zeros the disk
/// holds past its old end; the size it reached stays.
#[test]
fn dontneed_past_the_durable_end_reads_zeros() {
    let (mut fs, fd) = log_with_pending(b"committed;", b"lost;");
    fs.fail_writeback(fd, ErrorCode::Io).unwrap();
    fs.drop_cache(fd, 0, 0).unwrap();
    let mut expected = b"committed;".to_vec();
    expected.resize(b"committed;lost;".len(), 0);
    assert_eq!(fs.contents("/log").unwrap(), expected);
}

/// A failed `sync`/`syncfs` drops every file's dirty pages from writeback.
/// `sync(2)` reports nothing; `syncfs` reports the filesystem's error once per
/// description, and each file's error reaches `fsync` (and a `WAIT`ing
/// `sync_file_range`) once per description, a description opened after an
/// error nobody saw included.
#[test]
fn a_failed_volume_writeback_reports_through_syncfs_and_fsync() {
    let (mut fs, log) = log_with_pending(b"committed;", b"lost;");
    let other = write(&mut fs, "/other", b"unsynced");
    let watcher = fs
        .open(FsClock::EPOCH, "/log", OpenFlags::read_only())
        .unwrap();
    fs.fail_writeback_all(ErrorCode::Io).unwrap();
    fs.sync_all().unwrap();
    let later = fs
        .open(FsClock::EPOCH, "/log", OpenFlags::read_only())
        .unwrap();

    assert_eq!(fs.sync_filesystem(log).unwrap_err().code, ErrorCode::Io);
    assert!(fs.sync_filesystem(log).is_ok());
    assert_eq!(fs.sync_filesystem(other).unwrap_err().code, ErrorCode::Io);
    // The filesystem's error was seen by then, so a description opened after
    // that never reports it.
    let after_seen = fs
        .open(FsClock::EPOCH, "/other", OpenFlags::read_only())
        .unwrap();
    assert!(fs.sync_filesystem(after_seen).is_ok());

    // The file errors are separate: nobody has checked /log's yet, so the
    // description opened after the failure sees it too.
    assert_eq!(fs.sync(later).unwrap_err().code, ErrorCode::Io);
    assert_eq!(fs.wait_writeback(watcher).unwrap_err().code, ErrorCode::Io);
    assert!(fs.sync(watcher).is_ok());
    assert_eq!(fs.sync(log).unwrap_err().code, ErrorCode::Io);
    assert!(fs.sync(log).is_ok());

    let mut expected = b"committed;".to_vec();
    expected.resize(b"committed;lost;".len(), 0);
    assert_eq!(on_disk(&mut fs, "/log"), expected);
}

/// A failed `fsync` is recorded against the filesystem too: every
/// description, the failing one included, reports it on its next `syncfs`.
#[test]
fn a_failed_fsync_reaches_syncfs() {
    let (mut fs, log) = log_with_pending(b"committed;", b"lost;");
    let unrelated = write(&mut fs, "/other", b"x");
    fs.fail_writeback(log, ErrorCode::NoSpace).unwrap();
    assert_eq!(
        fs.sync_filesystem(unrelated).unwrap_err().code,
        ErrorCode::NoSpace
    );
    assert_eq!(
        fs.sync_filesystem(log).unwrap_err().code,
        ErrorCode::NoSpace
    );
    assert!(fs.sync_filesystem(log).is_ok());
    assert!(fs.sync(log).is_ok());
}
