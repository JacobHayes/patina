//! Tests for file contents, positional writes, size limits and seals.

use crate::tests::{read_write, times};
use crate::{MemFs, VOLUME_MAX_BYTES};
use patina_dst_abi::seals::{F_SEAL_GROW, F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_WRITE};
use patina_dst_abi::{ErrorCode, FsAllocateMode, FsClock, FsEntryKind, OpenFlags, SeekWhence};
use patina_dst_driver_api::FsDriver;

#[test]
fn writes_reads_and_truncates_files() {
    let mut fs = MemFs::new();
    let write_fd = fs
        .open(
            FsClock::EPOCH,
            "/state/value",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    assert_eq!(fs.write(FsClock::EPOCH, write_fd, b"patina").unwrap(), 6);
    fs.close(write_fd).unwrap();

    let read_fd = fs
        .open(FsClock::EPOCH, "/state//./value", OpenFlags::read_only())
        .unwrap();
    assert_eq!(fs.read(FsClock::EPOCH, read_fd, 3).unwrap(), b"pat");
    assert_eq!(fs.read(FsClock::EPOCH, read_fd, 99).unwrap(), b"ina");
    assert!(fs.read(FsClock::EPOCH, read_fd, 1).unwrap().is_empty());
    fs.close(read_fd).unwrap();
    assert_eq!(fs.contents("/state/value").unwrap(), b"patina");

    let truncate_fd = fs
        .open(
            FsClock::EPOCH,
            "/state/value",
            OpenFlags::create_truncate_write(),
        )
        .unwrap();
    fs.close(truncate_fd).unwrap();
    assert!(fs.contents("/state/value").unwrap().is_empty());
}

#[test]
fn append_descriptions_use_current_eof_and_write_at_stays_positional() {
    let mut fs = MemFs::new().with_file("/log", b"head").unwrap();
    let append = fs
        .open(
            FsClock::EPOCH,
            "/log",
            OpenFlags {
                read: false,
                write: true,
                create: false,
                truncate: false,
                append: true,
                exclusive: false,
                path_only: false,
                mode: patina_dst_abi::CREATE_MODE_UNUSED,
            },
        )
        .unwrap();
    let duplicate = fs.dup(append).unwrap();

    let regular = fs
        .open(
            FsClock::EPOCH,
            "/log",
            OpenFlags {
                read: false,
                write: true,
                create: false,
                truncate: false,
                append: false,
                exclusive: false,
                path_only: false,
                mode: patina_dst_abi::CREATE_MODE_UNUSED,
            },
        )
        .unwrap();
    fs.seek(regular, 0, SeekWhence::End).unwrap();
    fs.write(FsClock::EPOCH, regular, b"-intervening").unwrap();
    fs.close(regular).unwrap();

    fs.seek(append, 0, SeekWhence::Start).unwrap();
    fs.write(FsClock::EPOCH, append, b"-a").unwrap();
    fs.write(FsClock::EPOCH, duplicate, b"-d").unwrap();
    fs.write_at(FsClock::EPOCH, append, 1, b"EA").unwrap();
    fs.write(FsClock::EPOCH, append, b"-tail").unwrap();

    assert_eq!(fs.contents("/log").unwrap(), b"hEAd-intervening-a-d-tail");
}

#[test]
fn positional_write_does_not_move_the_shared_cursor() {
    let mut fs = MemFs::new().with_file("/value", b"abcde").unwrap();
    let fd = fs
        .open(
            FsClock::EPOCH,
            "/value",
            OpenFlags {
                read: true,
                write: true,
                create: false,
                truncate: false,
                append: false,
                exclusive: false,
                path_only: false,
                mode: patina_dst_abi::CREATE_MODE_UNUSED,
            },
        )
        .unwrap();
    fs.seek(fd, 2, SeekWhence::Start).unwrap();
    fs.write_at(FsClock::EPOCH, fd, 0, b"X").unwrap();
    fs.write(FsClock::EPOCH, fd, b"Y").unwrap();

    assert_eq!(fs.contents("/value").unwrap(), b"XbYde");
}

#[test]
fn an_anonymous_file_lives_behind_its_handle_and_obeys_its_seals() {
    let mut fs = MemFs::new().with_file("/named", b"x").unwrap();
    let fd = fs
        .create_anonymous(FsClock::EPOCH, "buffer", 0o777, 0, 0)
        .unwrap();
    let metadata = fs.fd_metadata(fd).unwrap();
    assert_eq!(
        (metadata.kind, metadata.len, metadata.mode),
        (FsEntryKind::File, 0, 0o777)
    );
    assert_eq!(fs.write(FsClock::EPOCH, fd, b"hello").unwrap(), 5);
    assert_eq!(fs.seals(fd).unwrap(), 0);
    // Only an anonymous file can be sealed.
    let named = fs
        .open(FsClock::EPOCH, "/named", OpenFlags::read_only())
        .unwrap();
    assert_eq!(fs.seals(named).unwrap_err().code, ErrorCode::InvalidInput);
    // A live shared writable mapping refuses a new write seal; an unknown
    // seal bit is judged before anything else about the node.
    assert_eq!(
        fs.add_seals(fd, F_SEAL_WRITE, true).unwrap_err().code,
        ErrorCode::Busy
    );
    assert_eq!(
        fs.add_seals(fd, 0x100, false).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    fs.add_seals(fd, F_SEAL_WRITE | F_SEAL_SHRINK, false)
        .unwrap();
    assert_eq!(
        fs.write(FsClock::EPOCH, fd, b"x").unwrap_err().code,
        ErrorCode::NotPermitted
    );
    assert_eq!(
        fs.write_at(FsClock::EPOCH, fd, 0, b"x").unwrap_err().code,
        ErrorCode::NotPermitted
    );
    assert_eq!(
        fs.set_len(FsClock::EPOCH, fd, 1).unwrap_err().code,
        ErrorCode::NotPermitted
    );
    fs.set_len(FsClock::EPOCH, fd, 8).unwrap();
    // The page cache's write-back is not a write the seal refuses.
    assert_eq!(fs.write_back_at(FsClock::EPOCH, fd, 0, b"J").unwrap(), 1);
    assert_eq!(fs.read_at(FsClock::EPOCH, fd, 0, 5).unwrap(), b"Jello");
    fs.add_seals(fd, F_SEAL_SEAL, false).unwrap();
    assert_eq!(
        fs.add_seals(fd, F_SEAL_GROW, false).unwrap_err().code,
        ErrorCode::NotPermitted
    );
    assert_eq!(
        fs.seals(fd).unwrap(),
        F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_SEAL
    );
    // No name reaches it, and the last handle frees it.
    let ino = metadata.ino;
    fs.close(fd).unwrap();
    assert_eq!(
        fs.inode_metadata(ino).unwrap_err().code,
        ErrorCode::NotFound
    );
}

/// A hugetlbfs file on a machine with no huge pages reserved: no write
/// method, sized in whole huge pages, a punch frees nothing and an
/// allocation finds no page.
#[test]
fn a_hugetlb_file_sizes_in_huge_pages_and_cannot_be_written() {
    const HUGE: u64 = 2 << 20;
    let mut fs = MemFs::new();
    let fd = fs
        .create_anonymous(FsClock::EPOCH, "huge", 0o777, 0, HUGE)
        .unwrap();
    assert_eq!(
        fs.write(FsClock::EPOCH, fd, b"x").unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        fs.write_at(FsClock::EPOCH, fd, 0, b"x").unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        fs.set_len(FsClock::EPOCH, fd, 4096).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    fs.set_len(FsClock::EPOCH, fd, HUGE).unwrap();
    assert_eq!(fs.fd_metadata(fd).unwrap().len, HUGE);
    fs.allocate(FsClock::EPOCH, fd, 0, HUGE, FsAllocateMode::PunchHole, true)
        .unwrap();
    assert_eq!(
        fs.allocate(FsClock::EPOCH, fd, 0, HUGE, FsAllocateMode::Reserve, false)
            .unwrap_err()
            .code,
        ErrorCode::NoSpace
    );
    assert_eq!(fs.read_at(FsClock::EPOCH, fd, 0, 4).unwrap(), [0; 4]);
}

/// One step of a [`sparse_allocation_is_ext4s`] row.
#[derive(Clone, Copy)]
enum Step {
    /// `pwrite` of that many `x` bytes at the offset.
    Write(u64, u64),
    Truncate(u64),
    /// `fallocate(mode | keep_size, offset, len)`.
    Allocate(FsAllocateMode, bool, u64, u64),
}

#[test]
fn size_limits_are_the_nodes_filesystems() {
    // Each row is one call on a fresh empty file, on the volume (ext4's
    // s_maxbytes) or a memfd (tmpfs's MAX_LFS_FILESIZE), and its answer:
    // the bytes written or the size reached, or the error code.
    const MAX: u64 = VOLUME_MAX_BYTES;
    const OFF_MAX: u64 = i64::MAX as u64;
    #[derive(Clone, Copy)]
    enum Call {
        Pwrite(u64, usize),
        /// A cursor write after seeking to the offset.
        Write(u64, usize),
        Truncate(u64),
        Reserve(u64, u64),
        /// A seek to the first offset, then one by the whence and
        /// offset.
        Seek(u64, SeekWhence, i64),
    }
    use Call::{Pwrite, Reserve, Seek, Truncate, Write};
    use ErrorCode::{FileTooBig, InvalidInput};
    use SeekWhence::{Current, End, Start};
    let rows: &[(&str, bool, Call, Result<u64, ErrorCode>)] = &[
        (
            "a pwrite at the limit",
            false,
            Pwrite(MAX, 10),
            Err(FileTooBig),
        ),
        (
            "a pwrite across the limit is shortened",
            false,
            Pwrite(MAX - 4, 10),
            Ok(4),
        ),
        (
            "a pwrite below the limit",
            false,
            Pwrite(MAX - 10, 10),
            Ok(10),
        ),
        (
            "a cursor write at the limit",
            false,
            Write(MAX, 1),
            Err(FileTooBig),
        ),
        (
            "a cursor write across the limit is shortened",
            false,
            Write(MAX - 1, 3),
            Ok(1),
        ),
        (
            "a write past the largest offset",
            false,
            Pwrite(OFF_MAX - 1, 10),
            Err(InvalidInput),
        ),
        (
            "a memfd write past the largest offset",
            true,
            Pwrite(OFF_MAX - 1, 10),
            Err(InvalidInput),
        ),
        (
            "a memfd write past the volume's limit",
            true,
            Pwrite(MAX, 10),
            Ok(10),
        ),
        ("a truncate to the limit", false, Truncate(MAX), Ok(MAX)),
        (
            "a truncate past the limit",
            false,
            Truncate(MAX + 1),
            Err(FileTooBig),
        ),
        (
            "a memfd truncate past the volume's limit",
            true,
            Truncate(MAX + 1),
            Ok(MAX + 1),
        ),
        (
            "an allocation to the limit",
            false,
            Reserve(MAX - 4096, 4096),
            Ok(MAX),
        ),
        (
            "an allocation past the limit",
            false,
            Reserve(MAX - 4096, 4097),
            Err(FileTooBig),
        ),
        (
            "a seek to the limit",
            false,
            Seek(0, Start, MAX as i64),
            Ok(MAX),
        ),
        (
            "a seek past the limit",
            false,
            Seek(0, Start, MAX as i64 + 1),
            Err(InvalidInput),
        ),
        (
            "a relative seek past the limit",
            false,
            Seek(MAX, Current, 1),
            Err(InvalidInput),
        ),
        (
            "a seek from the end past the limit",
            false,
            Seek(0, End, MAX as i64 + 1),
            Err(InvalidInput),
        ),
        (
            "a memfd seek past the volume's limit",
            true,
            Seek(0, Start, MAX as i64 + 1),
            Ok(MAX + 1),
        ),
    ];
    for (what, memfd, call, expected) in rows {
        let mut fs = MemFs::new();
        let fd = if *memfd {
            fs.create_anonymous(FsClock::EPOCH, "m", 0o600, 0, 0)
                .unwrap()
        } else {
            fs.open(FsClock::EPOCH, "/f", OpenFlags::create_truncate_write())
                .unwrap()
        };
        let clock = FsClock::EPOCH;
        let answer = match *call {
            Pwrite(offset, len) => fs
                .write_at(clock, fd, offset, &vec![b'x'; len])
                .map(|written| written as u64),
            Write(offset, len) => {
                fs.seek(fd, offset as i64, SeekWhence::Start).unwrap();
                fs.write(clock, fd, &vec![b'x'; len])
                    .map(|written| written as u64)
            }
            Truncate(len) => fs
                .set_len(clock, fd, len)
                .map(|()| fs.fd_metadata(fd).unwrap().len),
            Reserve(offset, len) => fs
                .allocate(clock, fd, offset, len, FsAllocateMode::Reserve, false)
                .map(|()| fs.fd_metadata(fd).unwrap().len),
            Seek(first, whence, offset) => {
                fs.seek(fd, first as i64, Start).unwrap();
                fs.seek(fd, offset, whence)
            }
        };
        assert_eq!(answer.map_err(|error| error.code), *expected, "{what}");
    }
}

const GIB: u64 = 1 << 30;

#[test]
fn sparse_allocation_is_ext4s() {
    // Each row is a file shaped by `steps` and what the host answered for
    // it (Linux 6.8, ext4; XFS answered the same unless a row says
    // otherwise): its size, `st_blocks`, and `SEEK_DATA`/`SEEK_HOLE` from
    // each probe offset (`None` for ENXIO).
    use FsAllocateMode::{PunchHole, Reserve, ZeroRange};
    use Step::{Allocate, Truncate, Write};
    type Row = (
        &'static str,
        &'static [Step],
        u64,
        u64,
        &'static [(u64, Option<u64>, Option<u64>)],
    );
    let rows: &[Row] = &[
        (
            "five bytes 10 GiB into the file hold one block",
            &[Write(10 * GIB, 5)],
            10 * GIB + 5,
            8,
            &[
                (0, Some(10 * GIB), Some(0)),
                (10 * GIB + 2, Some(10 * GIB + 2), Some(10 * GIB + 5)),
                (10 * GIB - 100, Some(10 * GIB), Some(10 * GIB - 100)),
            ],
        ),
        (
            "two written ranges with a hole between",
            &[Write(10 * GIB, 4096), Write(8192, 100)],
            10 * GIB + 4096,
            16,
            &[
                (0, Some(8192), Some(0)),
                (8392, Some(8392), Some(12288)),
                (12288, Some(10 * GIB), Some(12288)),
            ],
        ),
        (
            "an extending truncate is a hole",
            &[Truncate(1 << 20)],
            1 << 20,
            0,
            &[(0, None, Some(0))],
        ),
        (
            "a truncate past written bytes leaves the rest a hole",
            &[Write(0, 100), Truncate(1 << 20)],
            1 << 20,
            8,
            &[(0, Some(0), Some(4096)), (4096, None, Some(4096))],
        ),
        (
            "KEEP_SIZE on an empty file allocates past the end",
            &[Allocate(Reserve, true, 0, 4096)],
            0,
            8,
            &[(0, None, None)],
        ),
        (
            "a reservation past the size counts; the size is the last hole",
            &[Write(0, 100), Allocate(Reserve, true, 0, 65536)],
            100,
            128,
            &[(0, Some(0), Some(100)), (50, Some(50), Some(100))],
        ),
        (
            "an unwritten reservation inside the file reads as a hole",
            &[Truncate(1 << 20), Allocate(Reserve, true, 65536, 65536)],
            1 << 20,
            128,
            &[(0, None, Some(0)), (65536, None, Some(65536))],
        ),
        (
            "mode 0 grows the file with unwritten blocks",
            &[Allocate(Reserve, false, 0, 65536)],
            65536,
            128,
            &[(0, None, Some(0)), (100, None, Some(100))],
        ),
        (
            "a write into a reservation writes that block alone",
            &[Allocate(Reserve, false, 0, 65536), Write(8192, 1)],
            65536,
            128,
            &[(0, Some(8192), Some(0)), (9000, Some(9000), Some(12288))],
        ),
        (
            "a punched hole frees its whole blocks",
            &[Write(0, 65536), Allocate(PunchHole, true, 4096, 8192)],
            65536,
            112,
            &[
                (0, Some(0), Some(4096)),
                (4096, Some(12288), Some(4096)),
                (12288, Some(12288), Some(65536)),
            ],
        ),
        (
            "an unaligned punch zeroes its partial blocks in place",
            &[Write(0, 65536), Allocate(PunchHole, true, 100, 8192)],
            65536,
            120,
            &[
                (100, Some(100), Some(4096)),
                (4096, Some(8192), Some(4096)),
                (8292, Some(8292), Some(65536)),
            ],
        ),
        (
            "punching every block empties the file of blocks",
            &[
                Write(0, 4096),
                Write(65536, 4096),
                Allocate(PunchHole, true, 0, 1 << 20),
            ],
            69632,
            0,
            &[(0, None, Some(0))],
        ),
        (
            // XFS frees the reservation (16 blocks).
            "ext4 punches nothing at or past the size",
            &[
                Write(0, 8192),
                Allocate(Reserve, true, 0, 65536),
                Allocate(PunchHole, true, 8192, 65536),
            ],
            8192,
            128,
            &[],
        ),
        (
            // XFS frees the reservation (8 blocks).
            "ext4 ends a punch past the size with the page holding it",
            &[
                Write(0, 5000),
                Allocate(Reserve, true, 0, 65536),
                Allocate(PunchHole, true, 4096, 65536),
            ],
            5000,
            120,
            &[],
        ),
        (
            "a zeroed range over data keeps its blocks, unwritten",
            &[Write(0, 65536), Allocate(ZeroRange, false, 4096, 8192)],
            65536,
            128,
            &[(0, Some(0), Some(4096)), (4096, Some(12288), Some(4096))],
        ),
        (
            "a zeroed range allocates every block it touches",
            &[Truncate(65536), Allocate(ZeroRange, false, 100, 8192)],
            65536,
            24,
            &[(0, None, Some(0))],
        ),
        (
            "a zeroed range grows the file",
            &[Truncate(10000), Allocate(ZeroRange, false, 9000, 4000)],
            13000,
            16,
            &[(0, None, Some(0))],
        ),
        (
            "a zeroed range inside one written block leaves it written",
            &[Write(0, 8192), Allocate(ZeroRange, true, 100, 50)],
            8192,
            16,
            &[(0, Some(0), Some(8192))],
        ),
        (
            "KEEP_SIZE zeroes and reserves past the end",
            &[Write(0, 8192), Allocate(ZeroRange, true, 4096, 65536)],
            8192,
            136,
            &[(0, Some(0), Some(4096)), (4096, None, Some(4096))],
        ),
        (
            "a shrink frees the blocks past the end",
            &[Write(0, 65536), Truncate(5000)],
            5000,
            16,
            &[],
        ),
        (
            "a truncate to the size frees a reservation past it",
            &[
                Write(0, 100),
                Allocate(Reserve, true, 0, 65536),
                Truncate(100),
            ],
            100,
            8,
            &[],
        ),
        (
            "a growing truncate keeps it",
            &[
                Write(0, 100),
                Allocate(Reserve, true, 0, 65536),
                Truncate(8192),
            ],
            8192,
            128,
            &[(0, Some(0), Some(4096))],
        ),
    ];
    for (name, steps, size, blocks, seeks) in rows {
        let mut fs = MemFs::new().with_file("/f", Vec::new()).unwrap();
        let fd = fs.open(FsClock::EPOCH, "/f", read_write()).unwrap();
        for step in *steps {
            match *step {
                Step::Write(offset, len) => {
                    let bytes = vec![b'x'; len as usize];
                    fs.write_at(FsClock::EPOCH, fd, offset, &bytes).unwrap();
                }
                Step::Truncate(len) => fs.set_len(FsClock::EPOCH, fd, len).unwrap(),
                Step::Allocate(mode, keep_size, offset, len) => fs
                    .allocate(FsClock::EPOCH, fd, offset, len, mode, keep_size)
                    .unwrap(),
            }
        }
        let metadata = fs.fd_metadata(fd).unwrap();
        assert_eq!((metadata.len, metadata.blocks), (*size, *blocks), "{name}");
        for &(offset, data, hole) in *seeks {
            let answer = |fs: &mut MemFs, whence| {
                fs.seek(fd, offset as i64, whence)
                    .map_err(|error| error.code)
            };
            let enxio = Err(ErrorCode::NoSuchPosition);
            let data_answer = answer(&mut fs, SeekWhence::Data);
            assert_eq!(
                data_answer,
                data.ok_or(ErrorCode::NoSuchPosition),
                "{name}: SEEK_DATA {offset}"
            );
            let hole_answer = answer(&mut fs, SeekWhence::Hole);
            assert_eq!(
                hole_answer,
                hole.map_or(enxio, Ok),
                "{name}: SEEK_HOLE {offset}"
            );
        }
    }
}

#[test]
fn zero_io_preserves_times_size_and_cursor() {
    let mut fs = MemFs::new().with_file("/f", b"abc".to_vec()).unwrap();
    let fd = fs.open(FsClock::at(10), "/f", read_write()).unwrap();
    fs.seek(fd, 20, SeekWhence::Start).unwrap();
    let before = times(&mut fs, "/f");
    assert_eq!(fs.read(FsClock::at(30), fd, 0).unwrap(), b"");
    assert_eq!(fs.write(FsClock::at(40), fd, b"").unwrap(), 0);
    assert_eq!(fs.write_at(FsClock::at(50), fd, 30, b"").unwrap(), 0);
    assert_eq!(times(&mut fs, "/f"), before);
    assert_eq!(fs.metadata("/f").unwrap().len, 3);
    assert_eq!(fs.seek(fd, 0, SeekWhence::Current).unwrap(), 20);
}

#[test]
fn read_after_truncate_past_cursor_returns_eof_without_rewinding() {
    let mut fs = MemFs::new().with_file("/f", b"abc".to_vec()).unwrap();
    let fd = fs.open(FsClock::at(10), "/f", read_write()).unwrap();
    fs.seek(fd, 3, SeekWhence::Start).unwrap();
    fs.set_len(FsClock::at(20), fd, 0).unwrap();
    assert!(fs.read(FsClock::at(30), fd, 8).unwrap().is_empty());
    assert_eq!(fs.seek(fd, 0, SeekWhence::Current).unwrap(), 3);
}

#[test]
fn truncation_by_descriptor_and_by_name_answer_the_kernels_errnos() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
    fs.make_fifo(FsClock::EPOCH, "/p", 0o644).unwrap();
    fs.symlink(FsClock::EPOCH, "f", "/l").unwrap();
    let fd = fs
        .open(FsClock::EPOCH, "/f", OpenFlags::create_truncate_write())
        .unwrap();
    fs.write(FsClock::EPOCH, fd, b"abcdef").unwrap();
    fs.close(fd).unwrap();
    let dir = fs
        .open(FsClock::EPOCH, "/d", OpenFlags::read_only())
        .unwrap();
    assert_eq!(
        fs.set_len(FsClock::EPOCH, dir, 0).unwrap_err().code,
        ErrorCode::InvalidInput,
        "ftruncate on a directory is EINVAL; EISDIR is the by-name answer"
    );
    let location = fs
        .open(FsClock::EPOCH, "/f", OpenFlags::path_only())
        .unwrap();
    assert_eq!(
        fs.set_len(FsClock::EPOCH, location, 0).unwrap_err().code,
        ErrorCode::InvalidHandle
    );
    let reader = fs
        .open(FsClock::EPOCH, "/f", OpenFlags::read_only())
        .unwrap();
    assert_eq!(
        fs.set_len(FsClock::EPOCH, reader, 0).unwrap_err().code,
        ErrorCode::InvalidInput,
        "not open for writing is EINVAL, not EBADF"
    );
    assert_eq!(
        fs.set_len_by_path(FsClock::EPOCH, "/d", 0)
            .unwrap_err()
            .code,
        ErrorCode::IsDirectory
    );
    assert_eq!(
        fs.set_len_by_path(FsClock::EPOCH, "/p", 0)
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        fs.set_len_by_path(FsClock::EPOCH, "/l", 0)
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput,
        "a link the caller declined to follow"
    );
    assert_eq!(
        fs.set_len_by_path(FsClock::EPOCH, "/missing", 0)
            .unwrap_err()
            .code,
        ErrorCode::NotFound
    );
    fs.set_mode(FsClock::EPOCH, "/f", 0o444).unwrap();
    assert_eq!(
        fs.set_len_by_path(FsClock::EPOCH, "/f", 0)
            .unwrap_err()
            .code,
        ErrorCode::Denied
    );
    fs.set_mode(FsClock::EPOCH, "/f", 0o644).unwrap();
    fs.set_len_by_path(FsClock::EPOCH, "/f", 8).unwrap();
    assert_eq!(fs.contents("/f").unwrap(), b"abcdef\0\0");
    fs.set_len_by_path(FsClock::EPOCH, "/f", 2).unwrap();
    assert_eq!(fs.contents("/f").unwrap(), b"ab");
}

#[test]
fn allocate_grows_keeps_or_zeroes_and_answers_the_kernels_errnos() {
    let mut fs = MemFs::new();
    fs.create_directory(FsClock::EPOCH, "/d", 0o755).unwrap();
    let fd = fs
        .open(FsClock::EPOCH, "/f", OpenFlags::create_truncate_write())
        .unwrap();
    fs.write(FsClock::EPOCH, fd, b"abcdef").unwrap();
    // mode 0 past the end grows, zero-filled; within the end changes nothing.
    fs.allocate(FsClock::EPOCH, fd, 4, 4, FsAllocateMode::Reserve, false)
        .unwrap();
    assert_eq!(fs.contents("/f").unwrap(), b"abcdef\0\0");
    fs.allocate(FsClock::EPOCH, fd, 0, 2, FsAllocateMode::Reserve, false)
        .unwrap();
    assert_eq!(fs.contents("/f").unwrap(), b"abcdef\0\0");
    // KEEP_SIZE reserves without changing the visible length.
    fs.allocate(FsClock::EPOCH, fd, 0, 100, FsAllocateMode::Reserve, true)
        .unwrap();
    assert_eq!(fs.metadata("/f").unwrap().len, 8);
    // PUNCH_HOLE|KEEP_SIZE zeroes inside the file and never grows it.
    fs.allocate(FsClock::EPOCH, fd, 1, 2, FsAllocateMode::PunchHole, true)
        .unwrap();
    assert_eq!(fs.contents("/f").unwrap(), b"a\0\0def\0\0");
    fs.allocate(FsClock::EPOCH, fd, 6, 100, FsAllocateMode::PunchHole, true)
        .unwrap();
    assert_eq!(fs.metadata("/f").unwrap().len, 8);
    // ZERO_RANGE without KEEP_SIZE grows to cover the range.
    fs.allocate(FsClock::EPOCH, fd, 7, 3, FsAllocateMode::ZeroRange, false)
        .unwrap();
    assert_eq!(fs.contents("/f").unwrap(), b"a\0\0def\0\0\0\0");
    fs.close(fd).unwrap();
    let reader = fs
        .open(FsClock::EPOCH, "/f", OpenFlags::read_only())
        .unwrap();
    assert_eq!(
        fs.allocate(FsClock::EPOCH, reader, 0, 1, FsAllocateMode::Reserve, false)
            .unwrap_err()
            .code,
        ErrorCode::NotWritable
    );
    let location = fs
        .open(FsClock::EPOCH, "/f", OpenFlags::path_only())
        .unwrap();
    assert_eq!(
        fs.allocate(
            FsClock::EPOCH,
            location,
            0,
            1,
            FsAllocateMode::Reserve,
            false
        )
        .unwrap_err()
        .code,
        ErrorCode::NotWritable
    );
    let dir = fs
        .open(FsClock::EPOCH, "/d", OpenFlags::read_only())
        .unwrap();
    assert_eq!(
        fs.allocate(FsClock::EPOCH, dir, 0, 1, FsAllocateMode::Reserve, false)
            .unwrap_err()
            .code,
        ErrorCode::NotWritable,
        "a directory descriptor is never open for writing, which the kernel checks first"
    );
}
