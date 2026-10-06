//! Tests for timestamps, metadata assembly and permission checks.

use crate::MemFs;
use crate::tests::{read_write, times, write_only};
use patina_dst_abi::{AtimePolicy, ErrorCode, FsAllocateMode, FsClock, FsEntryKind, OpenFlags};
use patina_dst_driver_api::FsDriver;

/// RED before the mode model: every entry reported one fabricated constant,
/// `set_mode` did not exist, and nothing was ever refused for permissions —
/// so a guest could not tell a genuine `EACCES` from "missing".
#[test]
fn modes_are_the_creation_modes_handed_down_and_chmod_changes_them() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::EPOCH, "/perm", 0o755).unwrap();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/perm/file",
            OpenFlags {
                path_only: false,
                mode: 0o644,
                ..OpenFlags::create_truncate_write()
            },
        )
        .unwrap();
    fs.close(fd).unwrap();
    fs.symlink(FsClock::EPOCH, "/perm/file", "/perm/link")
        .unwrap();

    assert_eq!(fs.metadata("/perm").unwrap().mode, 0o755);
    assert_eq!(fs.metadata("/perm/file").unwrap().mode, 0o644);
    // The initial image's root and /tmp carry the conventional 0o755.
    assert_eq!(fs.metadata("/").unwrap().mode, 0o755);
    // Linux gives a symlink no mode of its own; it always reads 0o777 and
    // cannot be changed.
    assert_eq!(fs.metadata("/perm/link").unwrap().mode, 0o777);
    assert_eq!(
        fs.set_mode(FsClock::EPOCH, "/perm/link", 0o600)
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );

    fs.set_mode(FsClock::EPOCH, "/perm/file", 0o600).unwrap();
    assert_eq!(fs.metadata("/perm/file").unwrap().mode, 0o600);
    // Only the permission bits are stored; file-type bits are the kind's.
    fs.set_mode(FsClock::EPOCH, "/perm/file", 0o100_644)
        .unwrap();
    assert_eq!(fs.metadata("/perm/file").unwrap().mode, 0o644);
}

/// RED before creating calls carried a mode: `open(path, O_CREAT, mode)`
/// and `mkdir(path, mode)` dropped the argument and every new entry got a
/// fixed default for its kind, so a file asked for at `0o400` came
/// back writable and a directory asked for at `0o500` accepted new names.
#[test]
fn a_creating_call_gets_the_mode_it_asked_for_and_the_bits_are_enforced() {
    let mut fs = MemFs::new();

    // A creation mode is the caller's, verbatim.
    let read_only_file = OpenFlags {
        path_only: false,
        mode: 0o400,
        ..OpenFlags::create_truncate_write()
    };
    let fd = fs
        .open(FsClock::EPOCH, "/tmp/strict", read_only_file)
        .unwrap();
    fs.close(fd).unwrap();
    assert_eq!(fs.metadata("/tmp/strict").unwrap().mode, 0o400);

    // And it is JUDGED on a later open: `r--` is readable, never writable.
    let opened = fs
        .open(FsClock::EPOCH, "/tmp/strict", OpenFlags::read_only())
        .unwrap();
    fs.close(opened).unwrap();
    assert_eq!(
        fs.open(FsClock::EPOCH, "/tmp/strict", write_only())
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );

    // No umask is applied here: the group/other triads arrive as the layer
    // above (the process umask's owner) already masked them, so `0o666`
    // handed down is `0o666` stored — the umask is the caller's business.
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/tmp/plain",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.close(fd).unwrap();
    assert_eq!(fs.metadata("/tmp/plain").unwrap().mode, 0o666);
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/tmp/wide",
            OpenFlags {
                path_only: false,
                mode: 0o777,
                ..OpenFlags::create_truncate_write()
            },
        )
        .unwrap();
    fs.close(fd).unwrap();
    assert_eq!(fs.metadata("/tmp/wide").unwrap().mode, 0o777);

    // A directory's mode is the caller's too, and `0o500` refuses creation
    // inside it while still resolving through and listing.
    fs.create_directory(FsClock::EPOCH, "/tmp/locked", 0o500)
        .unwrap();
    assert_eq!(fs.metadata("/tmp/locked").unwrap().mode, 0o500);
    assert_eq!(
        fs.open(
            FsClock::EPOCH,
            "/tmp/locked/new",
            OpenFlags::create_truncate_write()
        )
        .unwrap_err()
        .code,
        ErrorCode::Denied
    );
    assert!(
        fs.read_directory(FsClock::EPOCH, "/tmp/locked")
            .unwrap()
            .is_empty()
    );
}

/// An `open` of an EXISTING entry must never touch its mode, whatever third
/// argument the caller passes — POSIX does not read one on that branch.
#[test]
fn opening_an_existing_file_leaves_its_mode_alone() {
    let mut fs = MemFs::new();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/tmp/kept",
            OpenFlags {
                path_only: false,
                mode: 0o640,
                ..OpenFlags::create_truncate_write()
            },
        )
        .unwrap();
    fs.close(fd).unwrap();
    assert_eq!(fs.metadata("/tmp/kept").unwrap().mode, 0o640);

    // `O_CREAT` on a name that is already there is not a creation.
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/tmp/kept",
            OpenFlags {
                path_only: false,
                mode: 0o777,
                ..OpenFlags::create_truncate_write()
            },
        )
        .unwrap();
    fs.close(fd).unwrap();
    assert_eq!(fs.metadata("/tmp/kept").unwrap().mode, 0o640);

    // Neither does an ordinary non-creating open.
    let fd = fs
        .open(FsClock::EPOCH, "/tmp/kept", OpenFlags::read_only())
        .unwrap();
    fs.close(fd).unwrap();
    assert_eq!(fs.metadata("/tmp/kept").unwrap().mode, 0o640);
}

/// What `fstat` on a FIFO descriptor reads: the LIVE entry, by inode, so a
/// `chmod` after the open is visible exactly as it is through a regular
/// file's descriptor.
#[test]
fn inode_metadata_reads_the_live_entry() {
    let mut fs = MemFs::new();
    fs.make_fifo(FsClock::EPOCH, "/tmp/pipe", 0o644).unwrap();
    let ino = fs.metadata("/tmp/pipe").unwrap().ino;
    assert_eq!(fs.inode_metadata(ino).unwrap().mode, 0o644);

    fs.set_mode(FsClock::EPOCH, "/tmp/pipe", 0o400).unwrap();
    assert_eq!(fs.inode_metadata(ino).unwrap().mode, 0o400);

    // A rename moves the name, never the node, so the inode still answers.
    fs.rename(FsClock::EPOCH, "/tmp/pipe", "/tmp/moved")
        .unwrap();
    let after = fs.inode_metadata(ino).unwrap();
    assert_eq!(after.ino, ino);
    assert_eq!(after.mode, 0o400);

    // A regular file's inode answers here too (the same node identity the
    // link table uses), and an unknown inode is `NotFound`, never a guess.
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/tmp/file",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.close(fd).unwrap();
    let file_ino = fs.metadata("/tmp/file").unwrap().ino;
    assert_eq!(fs.inode_metadata(file_ino).unwrap().kind, FsEntryKind::File);
    assert_eq!(
        fs.inode_metadata(u64::MAX).unwrap_err().code,
        ErrorCode::NotFound
    );
}

#[test]
fn file_modes_are_enforced_for_read_and_write() {
    let mut fs = MemFs::new();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/tmp/data",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.write(FsClock::EPOCH, fd, b"bytes").unwrap();
    fs.close(fd).unwrap();

    fs.set_mode(FsClock::EPOCH, "/tmp/data", 0o000).unwrap();
    assert_eq!(
        fs.open(FsClock::EPOCH, "/tmp/data", OpenFlags::read_only())
            .unwrap_err()
            .code,
        ErrorCode::Denied,
        "a 0o000 file must be denied, not reported missing"
    );
    assert_eq!(
        fs.open(
            FsClock::EPOCH,
            "/tmp/data",
            OpenFlags::create_truncate_write()
        )
        .unwrap_err()
        .code,
        ErrorCode::Denied
    );

    fs.set_mode(FsClock::EPOCH, "/tmp/data", 0o400).unwrap();
    let fd = fs
        .open(FsClock::EPOCH, "/tmp/data", OpenFlags::read_only())
        .unwrap();
    assert_eq!(fs.read(FsClock::EPOCH, fd, 8).unwrap(), b"bytes");
    fs.close(fd).unwrap();
    assert_eq!(
        fs.open(
            FsClock::EPOCH,
            "/tmp/data",
            OpenFlags::create_truncate_write()
        )
        .unwrap_err()
        .code,
        ErrorCode::Denied,
        "a read-only mode must not be openable for write"
    );
    // A descriptor opened while the mode allowed it keeps working: the
    // check belongs to `open`, not to every later read (POSIX).
    let fd = fs
        .open(FsClock::EPOCH, "/tmp/data", OpenFlags::read_only())
        .unwrap();
    fs.set_mode(FsClock::EPOCH, "/tmp/data", 0o000).unwrap();
    assert_eq!(fs.read(FsClock::EPOCH, fd, 8).unwrap(), b"bytes");
    fs.close(fd).unwrap();
}

#[test]
fn directory_modes_gate_search_listing_and_name_creation() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::EPOCH, "/gate", 0o777).unwrap();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/gate/inner",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.close(fd).unwrap();

    // No `x`: nothing resolves THROUGH it, and the refusal is a permission
    // one even though the name behind it exists.
    fs.set_mode(FsClock::EPOCH, "/gate", 0o000).unwrap();
    assert_eq!(
        fs.open(FsClock::EPOCH, "/gate/inner", OpenFlags::read_only())
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );
    assert_eq!(
        fs.metadata("/gate/inner").unwrap_err().code,
        ErrorCode::Denied
    );
    assert_eq!(
        fs.read_directory(FsClock::EPOCH, "/gate").unwrap_err().code,
        ErrorCode::Denied
    );
    // Same refusal for a name that does NOT exist, so the error cannot be
    // used to probe what is behind an unsearchable directory.
    assert_eq!(
        fs.metadata("/gate/absent").unwrap_err().code,
        ErrorCode::Denied
    );

    // `r-x`: listing and traversal work, creating a name does not.
    fs.set_mode(FsClock::EPOCH, "/gate", 0o500).unwrap();
    assert_eq!(fs.read_directory(FsClock::EPOCH, "/gate").unwrap().len(), 1);
    let opened = fs
        .open(FsClock::EPOCH, "/gate/inner", OpenFlags::read_only())
        .expect("search + read bits allow the open");
    fs.close(opened).unwrap();
    assert_eq!(
        fs.open(
            FsClock::EPOCH,
            "/gate/new",
            OpenFlags::create_truncate_write()
        )
        .unwrap_err()
        .code,
        ErrorCode::Denied
    );
    assert_eq!(
        fs.create_directory(FsClock::EPOCH, "/gate/sub", 0o777)
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );
    assert_eq!(
        fs.remove_file(FsClock::EPOCH, "/gate/inner")
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );
    assert_eq!(
        fs.rename(FsClock::EPOCH, "/gate/inner", "/gate/moved")
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );
    assert_eq!(
        fs.symlink(FsClock::EPOCH, "/gate/inner", "/gate/link")
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );

    // `--x`: traversal only. The entry behind it is reachable, the listing
    // is not — the distinction a search-only directory exists to make.
    fs.set_mode(FsClock::EPOCH, "/gate", 0o100).unwrap();
    let opened = fs
        .open(FsClock::EPOCH, "/gate/inner", OpenFlags::read_only())
        .expect("search alone is enough to resolve through");
    fs.close(opened).unwrap();
    assert_eq!(
        fs.read_directory(FsClock::EPOCH, "/gate").unwrap_err().code,
        ErrorCode::Denied
    );

    fs.set_mode(FsClock::EPOCH, "/gate", 0o755).unwrap();
    fs.remove_file(FsClock::EPOCH, "/gate/inner").unwrap();
}

#[test]
fn explicit_timestamp_updates_are_reflected_in_metadata() {
    let mut fs = MemFs::new().with_file("/value", b"x").unwrap();
    let fd = fs
        .open(FsClock::EPOCH, "/value", OpenFlags::read_only())
        .unwrap();
    fs.set_times(FsClock::EPOCH, fd, Some(10), Some(20))
        .unwrap();
    assert_eq!(fs.fd_metadata(fd).unwrap().atime_nanos, 10);
    assert_eq!(fs.metadata("/value").unwrap().mtime_nanos, 20);
    fs.close(fd).unwrap();
    fs.create_directory(FsClock::EPOCH, "/state", 0o777)
        .unwrap();
    let state_ino = fs.metadata("/state").unwrap().ino;
    fs.symlink(FsClock::EPOCH, "missing", "/state/link")
        .unwrap();
    let link_metadata = fs.metadata("/state/link").unwrap();
    assert_ne!(state_ino, link_metadata.ino);
    assert_eq!(link_metadata.nlink, 1);
    fs.set_times_by_path(FsClock::EPOCH, "/state", Some(30), None)
        .unwrap();
    fs.set_times_by_path(FsClock::EPOCH, "/state/link", None, Some(40))
        .unwrap();
    assert_eq!(fs.metadata("/state").unwrap().atime_nanos, 30);
    assert_eq!(fs.metadata("/state/link").unwrap().mtime_nanos, 40);
}

#[test]
fn creation_stamps_all_four_times_and_the_parent_directory() {
    let mut fs = MemFs::new();
    assert_eq!(
        times(&mut fs, "/"),
        (0, 0, 0, 0),
        "the image is stamped at the epoch"
    );
    fs.create_directory(FsClock::at(10), "/d", 0o755).unwrap();
    assert_eq!(times(&mut fs, "/d"), (10, 10, 10, 10));
    assert_eq!(
        times(&mut fs, "/"),
        (0, 10, 10, 0),
        "a new name is a data change to its parent"
    );
    let fd = fs
        .open(FsClock::at(20), "/d/f", OpenFlags::create_truncate_write())
        .unwrap();
    fs.close(fd).unwrap();
    assert_eq!(times(&mut fs, "/d/f"), (20, 20, 20, 20));
    assert_eq!(times(&mut fs, "/d"), (10, 20, 20, 10));
    fs.symlink(FsClock::at(30), "f", "/d/l").unwrap();
    assert_eq!(times(&mut fs, "/d/l"), (30, 30, 30, 30));
    fs.make_fifo(FsClock::at(40), "/d/p", 0o644).unwrap();
    assert_eq!(times(&mut fs, "/d/p"), (40, 40, 40, 40));
    assert_eq!(times(&mut fs, "/d"), (10, 40, 40, 10));
    // Opening an existing entry touches nothing.
    let fd = fs.open(FsClock::at(50), "/d/f", read_write()).unwrap();
    fs.close(fd).unwrap();
    assert_eq!(times(&mut fs, "/d/f"), (20, 20, 20, 20));
}

#[test]
fn data_changes_move_mtime_and_ctime_and_leave_atime_and_btime() {
    let mut fs = MemFs::new();
    let fd = fs
        .open(FsClock::at(10), "/f", OpenFlags::create_truncate_write())
        .unwrap();
    fs.write(FsClock::at(20), fd, b"abc").unwrap();
    assert_eq!(times(&mut fs, "/f"), (10, 20, 20, 10));
    fs.write_at(FsClock::at(30), fd, 1, b"x").unwrap();
    assert_eq!(times(&mut fs, "/f"), (10, 30, 30, 10));
    // A truncation to the SAME length still moves the times (do_truncate).
    fs.set_len(FsClock::at(40), fd, 3).unwrap();
    assert_eq!(times(&mut fs, "/f"), (10, 40, 40, 10));
    fs.allocate(FsClock::at(50), fd, 0, 8, FsAllocateMode::Reserve, false)
        .unwrap();
    assert_eq!(times(&mut fs, "/f"), (10, 50, 50, 10));
    fs.close(fd).unwrap();
    fs.set_len_by_path(FsClock::at(60), "/f", 2).unwrap();
    assert_eq!(times(&mut fs, "/f"), (10, 60, 60, 10));
    // O_TRUNC on an already-empty file is a truncation too.
    fs.set_len_by_path(FsClock::at(61), "/f", 0).unwrap();
    let fd = fs
        .open(FsClock::at(70), "/f", OpenFlags::create_truncate_write())
        .unwrap();
    fs.close(fd).unwrap();
    assert_eq!(times(&mut fs, "/f"), (10, 70, 70, 10));
}

#[test]
fn relatime_refreshes_atime_after_a_data_change_or_a_day_and_not_otherwise() {
    let mut fs = MemFs::new();
    let fd = fs
        .open(FsClock::at(10), "/f", OpenFlags::create_truncate_write())
        .unwrap();
    fs.write(FsClock::at(10), fd, b"abc").unwrap();
    fs.close(fd).unwrap();
    let fd = fs
        .open(FsClock::at(10), "/f", OpenFlags::read_only())
        .unwrap();
    // atime == now: nothing to write, even though mtime >= atime.
    fs.read(FsClock::at(10), fd, 1).unwrap();
    assert_eq!(times(&mut fs, "/f").0, 10);
    // mtime (10) >= atime (10): the first read after the write refreshes.
    fs.read(FsClock::at(20), fd, 1).unwrap();
    assert_eq!(times(&mut fs, "/f").0, 20);
    // atime (20) is now newer than mtime/ctime and less than a day old.
    fs.read(FsClock::at(30), fd, 1).unwrap();
    assert_eq!(times(&mut fs, "/f").0, 20);
    // A day later it refreshes again.
    let day = super::RELATIME_REFRESH_NANOS;
    fs.read(FsClock::at(20 + day), fd, 1).unwrap();
    assert_eq!(times(&mut fs, "/f").0, i128::from(20 + day));
    // A metadata change (ctime >= atime) re-arms it as well.
    fs.set_fd_mode(FsClock::at(20 + day + 5), fd, 0o600)
        .unwrap();
    fs.read(FsClock::at(20 + day + 6), fd, 1).unwrap();
    assert_eq!(times(&mut fs, "/f").0, i128::from(20 + day + 6));
    // strictatime: every read; noatime: never.
    let strict = FsClock {
        now_nanos: 20 + day + 7,
        atime: AtimePolicy::Strict,
    };
    fs.read(strict, fd, 1).unwrap();
    assert_eq!(times(&mut fs, "/f").0, i128::from(20 + day + 7));
    let noatime = FsClock {
        now_nanos: 20 + day + 9,
        atime: AtimePolicy::NoAtime,
    };
    fs.set_fd_mode(FsClock::at(20 + day + 8), fd, 0o644)
        .unwrap();
    fs.read(noatime, fd, 1).unwrap();
    assert_eq!(times(&mut fs, "/f").0, i128::from(20 + day + 7));
    fs.close(fd).unwrap();
    // Directory listings and readlink are reads of their entries.
    fs.create_directory(FsClock::at(100), "/d", 0o755).unwrap();
    fs.read_directory(FsClock::at(110), "/d").unwrap();
    assert_eq!(times(&mut fs, "/d").0, 110);
    fs.symlink(FsClock::at(120), "f", "/l").unwrap();
    fs.read_link(FsClock::at(130), "/l").unwrap();
    assert_eq!(times(&mut fs, "/l").0, 130);
}

#[test]
fn metadata_changes_move_ctime_only() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::at(5), "/a", 0o755).unwrap();
    fs.create_directory(FsClock::at(5), "/b", 0o755).unwrap();
    let fd = fs
        .open(FsClock::at(10), "/a/f", OpenFlags::create_truncate_write())
        .unwrap();
    fs.close(fd).unwrap();
    fs.set_mode(FsClock::at(20), "/a/f", 0o600).unwrap();
    assert_eq!(times(&mut fs, "/a/f"), (10, 10, 20, 10));
    // Same bits again: the inode is still written.
    fs.set_mode(FsClock::at(21), "/a/f", 0o600).unwrap();
    assert_eq!(times(&mut fs, "/a/f"), (10, 10, 21, 10));
    fs.link(FsClock::at(30), "/a/f", "/b/g").unwrap();
    assert_eq!(
        times(&mut fs, "/a/f"),
        (10, 10, 30, 10),
        "a link count change"
    );
    assert_eq!(
        times(&mut fs, "/b"),
        (5, 30, 30, 5),
        "the new name's directory"
    );
    assert_eq!(times(&mut fs, "/a"), (5, 10, 10, 5), "not the old one's");
    fs.rename(FsClock::at(40), "/b/g", "/a/h").unwrap();
    assert_eq!(times(&mut fs, "/a/h"), (10, 10, 40, 10), "the moved node");
    assert_eq!(times(&mut fs, "/a"), (5, 40, 40, 5));
    assert_eq!(times(&mut fs, "/b"), (5, 40, 40, 5));
    let fd = fs
        .open(FsClock::at(45), "/a/f", OpenFlags::read_only())
        .unwrap();
    fs.remove_file(FsClock::at(50), "/a/h").unwrap();
    assert_eq!(
        fs.fd_metadata(fd).unwrap().ctime_nanos,
        50,
        "unlinking one name changes the node every other name and descriptor sees"
    );
    fs.close(fd).unwrap();
    assert_eq!(times(&mut fs, "/a"), (5, 50, 50, 5));
    // Explicit times: what was handed over, plus ctime; OMIT/OMIT is no-op.
    fs.set_times_by_path(FsClock::at(60), "/a/f", Some(1), None)
        .unwrap();
    assert_eq!(times(&mut fs, "/a/f"), (1, 10, 60, 10));
    fs.set_times_by_path(FsClock::at(70), "/a/f", None, None)
        .unwrap();
    assert_eq!(times(&mut fs, "/a/f"), (1, 10, 60, 10));
    let fd = fs
        .open(FsClock::at(75), "/a", OpenFlags::read_only())
        .unwrap();
    fs.set_times(FsClock::at(80), fd, None, Some(2)).unwrap();
    assert_eq!(
        times(&mut fs, "/a"),
        (5, 2, 80, 5),
        "a directory descriptor"
    );
    fs.close(fd).unwrap();
    let fd = fs
        .open(FsClock::at(85), "/a/f", OpenFlags::path_only())
        .unwrap();
    assert_eq!(
        fs.set_times(FsClock::at(90), fd, Some(3), Some(3))
            .unwrap_err()
            .code,
        ErrorCode::InvalidHandle,
        "an O_PATH descriptor cannot set times (futimens is EBADF)"
    );
}

/// `timestamp_truncate`, for every door that sets times (the native
/// shim and the WASI host alike): a named node holds ext4's range, an
/// anonymous file tmpfs's.
#[test]
fn a_set_time_is_truncated_to_the_filesystems_range_never_refused_or_wrapped() {
    const SEC: i128 = 1_000_000_000;
    let (ext4_min, ext4_max) = (-(1 << 31), 15_032_385_535);
    let mut fs = MemFs::new();
    let fd = fs
        .open(FsClock::EPOCH, "/f", OpenFlags::create_truncate_write())
        .unwrap();
    fs.close(fd).unwrap();
    let atime = |fs: &mut MemFs| times(fs, "/f").0;
    // Inside the range a time is kept exactly, before the epoch too.
    fs.set_times_by_path(FsClock::EPOCH, "/f", Some(-SEC + 5), None)
        .unwrap();
    assert_eq!(atime(&mut fs), -SEC + 5);
    // Past either end it clamps, and the nanoseconds go with it, as they
    // do at the bound itself.
    for (set, stored) in [
        (i128::from(u64::MAX), ext4_max * SEC),
        (i128::from(i64::MIN) * SEC + 7, ext4_min * SEC),
        (ext4_max * SEC + 7, ext4_max * SEC),
    ] {
        fs.set_times_by_path(FsClock::EPOCH, "/f", Some(set), None)
            .unwrap();
        assert_eq!(atime(&mut fs), stored);
    }
    // An anonymous file (tmpfs) holds every 64-bit second.
    let fd = fs
        .create_anonymous(FsClock::EPOCH, "buffer", 0o777, 0, 0)
        .unwrap();
    let past_ext4 = (ext4_max + 1) * SEC + 7;
    fs.set_times(FsClock::EPOCH, fd, None, Some(past_ext4))
        .unwrap();
    assert_eq!(fs.fd_metadata(fd).unwrap().mtime_nanos, past_ext4);
}

#[test]
fn a_directory_link_count_is_two_plus_its_subdirectories() {
    let mut fs = MemFs::new();
    // `/` holds `/tmp` in the initial image.
    assert_eq!(fs.metadata("/").unwrap().nlink, 3);
    fs.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
    assert_eq!(fs.metadata("/d").unwrap().nlink, 2);
    assert_eq!(fs.metadata("/").unwrap().nlink, 4);
    fs.create_directory(FsClock::EPOCH, "/d/a", 0o755).unwrap();
    fs.create_directory(FsClock::EPOCH, "/d/a/deeper", 0o755)
        .unwrap();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/d/file",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.close(fd).unwrap();
    assert_eq!(
        fs.metadata("/d").unwrap().nlink,
        3,
        "files and grandchildren do not count"
    );
    let fd = fs
        .open(FsClock::EPOCH, "/d", OpenFlags::read_only())
        .unwrap();
    assert_eq!(fs.fd_metadata(fd).unwrap().nlink, 3);
    fs.close(fd).unwrap();
    fs.remove_directory(FsClock::EPOCH, "/d/a/deeper").unwrap();
    fs.remove_directory(FsClock::EPOCH, "/d/a").unwrap();
    assert_eq!(fs.metadata("/d").unwrap().nlink, 2);
}
