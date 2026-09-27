//! fs/sparse — a regular file's allocation, as ext4 and XFS on 6.8 answer it
//! alike: one table of shapes, each built on a fresh file by writes,
//! truncates and `fallocate`, then judged by its size, its `st_blocks` and
//! `SEEK_DATA`/`SEEK_HOLE` from chosen offsets:
//!
//! * a write far past the end holds one block, with a hole before it;
//! * a truncate past the written bytes extends the file with a hole;
//! * `FALLOC_FL_KEEP_SIZE` counts blocks past the end without growing;
//! * mode 0 allocates unwritten blocks: counted, yet a hole to `SEEK_DATA`;
//! * `FALLOC_FL_PUNCH_HOLE` frees the blocks it covers whole and keeps the
//!   ones it covers in part (zeroed, still data);
//! * `FALLOC_FL_ZERO_RANGE|FALLOC_FL_KEEP_SIZE` turns the blocks it covers
//!   whole unwritten and allocates to its end;
//! * a store through a shared mapping allocates its block at once:
//!   `stat` by name and `statx` of the descriptor count it before any
//!   write-back.
//!
//! The shapes are the ones both filesystems answer the same: at most four
//! extents (ext4 adds an extent-tree block past that), no write of a MiB or
//! more (XFS preallocates speculatively past such an end), no punch of a
//! reservation past the end (ext4 stops at the page holding the size, XFS
//! does not), and no read over an unwritten block before a seek (a cached
//! page there is data to `SEEK_DATA`). Hence the need: a run directory on
//! ext4 or XFS.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{AT_FDCWD, At, Probe, neg};
use libc::*;
use patina_dst_syscalls::Syscall;

const KIB: i64 = 1024;
const GIB: i64 = 1 << 30;

/// One step of a shape.
#[derive(Clone, Copy)]
enum Step {
    /// Write that many `x` bytes at the offset.
    Write(i64, usize),
    /// `ftruncate` to the length.
    Truncate(i64),
    /// `fallocate(mode, offset, len)`.
    Allocate(i32, i64, i64),
}

/// A file's shape after its steps, as the host answers it.
struct Shape {
    what: &'static str,
    steps: &'static [Step],
    size: i64,
    /// `st_blocks`: allocated 512-byte units.
    blocks: i64,
    /// From each offset, `SEEK_DATA`'s and `SEEK_HOLE`'s answers (`None`:
    /// ENXIO).
    seeks: &'static [(i64, Option<i64>, Option<i64>)],
}

const PUNCH: i32 = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

const SHAPES: &[Shape] = &[
    Shape {
        what: "five bytes 10 GiB in",
        steps: &[Step::Write(10 * GIB, 5)],
        size: 10 * GIB + 5,
        blocks: 8,
        seeks: &[
            (0, Some(10 * GIB), Some(0)),
            (10 * GIB - 100, Some(10 * GIB), Some(10 * GIB - 100)),
            (10 * GIB + 2, Some(10 * GIB + 2), Some(10 * GIB + 5)),
        ],
    },
    Shape {
        what: "100 bytes truncated up to 1 MiB",
        steps: &[Step::Write(0, 100), Step::Truncate(1024 * KIB)],
        size: 1024 * KIB,
        blocks: 8,
        seeks: &[(50, Some(50), Some(4096)), (4096, None, Some(4096))],
    },
    Shape {
        what: "100 bytes and 64 KiB reserved with KEEP_SIZE",
        steps: &[
            Step::Write(0, 100),
            Step::Allocate(FALLOC_FL_KEEP_SIZE, 0, 64 * KIB),
        ],
        size: 100,
        blocks: 128,
        seeks: &[(50, Some(50), Some(100))],
    },
    Shape {
        what: "64 KiB allocated with mode 0",
        steps: &[Step::Allocate(0, 0, 64 * KIB)],
        size: 64 * KIB,
        blocks: 128,
        seeks: &[(0, None, Some(0)), (100, None, Some(100))],
    },
    Shape {
        what: "64 KiB written, two whole blocks punched",
        steps: &[Step::Write(0, 64 * 1024), Step::Allocate(PUNCH, 4096, 8192)],
        size: 64 * KIB,
        blocks: 112,
        seeks: &[
            (0, Some(0), Some(4096)),
            (5000, Some(12288), Some(5000)),
            (12288, Some(12288), Some(64 * KIB)),
        ],
    },
    Shape {
        what: "64 KiB written, a block punched across two",
        steps: &[Step::Write(0, 64 * 1024), Step::Allocate(PUNCH, 100, 8192)],
        size: 64 * KIB,
        blocks: 120,
        seeks: &[(100, Some(100), Some(4096)), (4096, Some(8192), Some(4096))],
    },
    Shape {
        what: "8 KiB written, zeroed from 4 KiB through 68 KiB with KEEP_SIZE",
        steps: &[
            Step::Write(0, 8192),
            Step::Allocate(FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE, 4096, 64 * KIB),
        ],
        size: 8192,
        blocks: 136,
        seeks: &[(0, Some(0), Some(4096)), (4096, None, Some(4096))],
    },
];

fn seek_answer(found: Option<i64>) -> i64 {
    found.unwrap_or(neg(ENXIO))
}

pub fn run(p: &Probe) {
    let root = p.dir();
    for (index, shape) in SHAPES.iter().enumerate() {
        let what = shape.what;
        let fd = p.openat(
            AT_FDCWD,
            &format!("{root}/{index}"),
            O_RDWR | O_CREAT | O_EXCL,
            0o600,
        );
        p.require("create the file", fd >= 0);
        for step in shape.steps {
            let done = match *step {
                Step::Write(offset, len) => {
                    p.lseek(fd, offset, SEEK_SET) == offset
                        && p.write(fd, &vec![b'x'; len]) == len as i64
                }
                Step::Truncate(len) => p.ftruncate(fd, len) == 0,
                Step::Allocate(mode, offset, len) => p.fallocate(fd, mode, offset, len) == 0,
            };
            p.require(what, done);
        }
        let st = p.fstat_or_stop(fd);
        p.check(&format!("{what}: the size"), st.size == shape.size);
        p.check(
            &format!("{what}: st_blocks counts the allocated blocks"),
            st.blocks == shape.blocks,
        );
        for &(offset, data, hole) in shape.seeks {
            p.check(
                &format!("{what}: SEEK_DATA from {offset}"),
                p.lseek(fd, offset, SEEK_DATA) == seek_answer(data),
            );
            p.check(
                &format!("{what}: SEEK_HOLE from {offset}"),
                p.lseek(fd, offset, SEEK_HOLE) == seek_answer(hole),
            );
        }
        p.close(fd);
    }
    mapped_stores(p, &root);
}

/// A file of 3 bytes grown to 64 KiB by truncation, mapped shared: a store
/// into its second page allocates that block, and a store into its third
/// one more.
fn mapped_stores(p: &Probe, root: &str) {
    let path = format!("{root}/mapped");
    let fd = p.openat(AT_FDCWD, &path, O_RDWR | O_CREAT | O_EXCL, 0o600);
    p.require("create the file", fd >= 0);
    p.require(
        "3 bytes, then 64 KiB by truncation",
        p.write(fd, b"abc") == 3 && p.ftruncate(fd, 64 * KIB) == 0,
    );
    let (r, view) = p.mmap(
        "v",
        &At::null(),
        64 * 1024,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        fd,
        0,
    );
    p.require("map it shared and writable", r >= 0);
    let view = view.unwrap();
    view.store(4096, b'x');
    p.check(
        "a mapped store's block counts in stat by name",
        p.stat_or_stop(&path, 0).blocks == 16,
    );
    let (r, st, _) = p.statx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS);
    p.check(
        "and in statx of the descriptor",
        r == 0 && st.is_some_and(|st| st.blocks == 16),
    );
    view.store(8192 + 100, b'z');
    p.check(
        "a store into another page allocates one more",
        p.stat_or_stop(&path, 0).blocks == 24,
    );
    p.check("unmap it", p.munmap(&view.at(0), 64 * 1024) == 0);
    p.close(fd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/sparse",
    run,
    covers: &[
        Syscall::N_openat,
        Syscall::N_lseek,
        Syscall::N_write,
        Syscall::N_ftruncate,
        Syscall::N_fallocate,
        Syscall::N_fstat,
        Syscall::N_close,
        Syscall::N_newfstatat,
        Syscall::N_statx,
        Syscall::N_mmap,
        Syscall::N_munmap,
    ],
    symbols: &[
        "openat",
        "lseek",
        "write",
        "ftruncate",
        "fallocate",
        "fstat",
        "close",
        "fstatat",
        "statx",
        "mmap",
        "munmap",
    ],
    needs: &[Need::ExtentAllocation],
    ..DEFAULTS
};
