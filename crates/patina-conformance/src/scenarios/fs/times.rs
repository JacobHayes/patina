//! fs/times — the four timestamps and the utimensat family: what a creation,
//! a write, a read, a truncation, a link, a rename and a directory change do to
//! atime/mtime/ctime/btime; explicit times (nanosecond, microsecond and
//! whole-second spellings), UTIME_NOW, UTIME_OMIT, the null-times shape, the
//! descriptor shape, AT_SYMLINK_NOFOLLOW, and the EINVAL/EFAULT/EBADF/ENOENT
//! vocabulary. Absolute times are never recorded — only their relations, as
//! checks — and no check depends on the mount's atime policy (the oracle may
//! be `noatime`, the virtual kernel is `relatime`).

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Difference, Failure, Observed};
use crate::vehicle::Vehicle;

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, TimeArg, neg};
use libc::*;

const SEC: i128 = 1_000_000_000;

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let link = format!("{root}/l");
    let dir = format!("{root}/d");

    // ---- creation, data changes, reads ---------------------------------
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f", fd >= 0);
    let created = p.fstat_or_stop(fd);
    p.check(
        "creation stamps atime, mtime and ctime at one instant",
        created.atime_ns == created.mtime_ns && created.mtime_ns == created.ctime_ns,
    );
    // Only the type and the birth time: fs/metadata owns the basic-stats mask.
    let (r, sx, _) = p.statx(fd, "", AT_EMPTY_PATH, STATX_TYPE | STATX_BTIME);
    p.check(
        "statx reports a birth time equal to the creation ctime",
        r == 0
            && sx
                .as_ref()
                .is_some_and(|s| s.btime_ns == Some(created.ctime_ns)),
    );
    let btime = sx.and_then(|s| s.btime_ns);

    p.tick();
    p.write(fd, b"12345");
    let written = p.fstat_or_stop(fd);
    p.check(
        "a write moves mtime forward",
        written.mtime_ns > created.mtime_ns,
    );
    p.check(
        "a write moves ctime forward",
        written.ctime_ns > created.ctime_ns,
    );
    p.check(
        "a write leaves atime alone",
        written.atime_ns == created.atime_ns,
    );
    let (r, sx, _) = p.statx(fd, "", AT_EMPTY_PATH, STATX_BTIME);
    p.check(
        "a write leaves the birth time alone",
        r == 0 && sx.as_ref().is_some_and(|s| s.btime_ns == btime),
    );

    p.tick();
    p.lseek(fd, 0, SEEK_SET);
    let (r, _) = p.read(fd, 5);
    p.check("read back", r == 5);
    let read = p.fstat_or_stop(fd);
    p.check(
        "a read leaves mtime alone",
        read.mtime_ns == written.mtime_ns,
    );
    p.check(
        "a read leaves ctime alone",
        read.ctime_ns == written.ctime_ns,
    );
    p.check(
        "a read never moves atime backwards",
        read.atime_ns >= written.atime_ns,
    );

    p.tick();
    p.check("ftruncate to the same length", p.ftruncate(fd, 5) == 0);
    let truncated = p.fstat_or_stop(fd);
    p.check(
        "a truncation to the same length still moves mtime and ctime",
        truncated.mtime_ns > read.mtime_ns && truncated.ctime_ns > read.ctime_ns,
    );

    p.tick();
    p.check(
        "linkat f -> h",
        p.linkat(AT_FDCWD, &file, AT_FDCWD, &format!("{root}/h"), 0) == 0,
    );
    let linked = p.fstat_or_stop(fd);
    p.check(
        "a link moves ctime forward",
        linked.ctime_ns > truncated.ctime_ns,
    );
    p.check(
        "a link leaves mtime alone",
        linked.mtime_ns == truncated.mtime_ns,
    );

    p.tick();
    p.check(
        "renameat h -> g",
        p.renameat(
            AT_FDCWD,
            &format!("{root}/h"),
            AT_FDCWD,
            &format!("{root}/g"),
        ) == 0,
    );
    let renamed = p.fstat_or_stop(fd);
    p.check(
        "a rename moves the node's ctime forward",
        renamed.ctime_ns > linked.ctime_ns,
    );
    p.check(
        "a rename leaves mtime alone",
        renamed.mtime_ns == linked.mtime_ns,
    );

    // ---- explicit times ------------------------------------------------
    p.tick();
    let r = p.utimensat(
        AT_FDCWD,
        Some(&file),
        Some([TimeArg::Set(1000, 5), TimeArg::Set(2000, 7)]),
        0,
    );
    p.check("utimensat with explicit nanosecond times", r == 0);
    let set = p.fstat_or_stop(fd);
    p.check(
        "atime is exactly what was set",
        set.atime_ns == 1000 * SEC + 5,
    );
    p.check(
        "mtime is exactly what was set",
        set.mtime_ns == 2000 * SEC + 7,
    );
    p.check(
        "setting times moves ctime forward",
        set.ctime_ns > renamed.ctime_ns,
    );

    p.tick();
    let r = p.utimensat(
        AT_FDCWD,
        Some(&file),
        Some([TimeArg::Omit, TimeArg::Set(3000, 9)]),
        0,
    );
    p.check("UTIME_OMIT on atime with an explicit mtime", r == 0);
    let omitted = p.fstat_or_stop(fd);
    p.check(
        "UTIME_OMIT leaves atime alone",
        omitted.atime_ns == set.atime_ns,
    );
    p.check(
        "the explicit mtime landed",
        omitted.mtime_ns == 3000 * SEC + 9,
    );
    p.check(
        "ctime moved for the mtime change",
        omitted.ctime_ns > set.ctime_ns,
    );

    p.tick();
    let r = p.utimensat(
        AT_FDCWD,
        Some(&file),
        Some([TimeArg::Omit, TimeArg::Omit]),
        0,
    );
    p.check("UTIME_OMIT on both is a success", r == 0);
    let untouched = p.fstat_or_stop(fd);
    p.check(
        "UTIME_OMIT on both changes nothing, ctime included",
        untouched.atime_ns == omitted.atime_ns
            && untouched.mtime_ns == omitted.mtime_ns
            && untouched.ctime_ns == omitted.ctime_ns,
    );

    p.tick();
    let r = p.utimensat(AT_FDCWD, Some(&file), Some([TimeArg::Now, TimeArg::Now]), 0);
    p.check("UTIME_NOW on both", r == 0);
    let now = p.fstat_or_stop(fd);
    p.check(
        "UTIME_NOW sets atime and mtime to one instant",
        now.atime_ns == now.mtime_ns,
    );
    // Relative to an earlier now-based stamp, never to the explicit past:
    // where the virtual clock's epoch lies is the runtime's business.
    p.check(
        "UTIME_NOW is after the creation instant",
        now.mtime_ns > created.mtime_ns,
    );
    p.check(
        "UTIME_NOW is the ctime instant",
        now.ctime_ns == now.mtime_ns,
    );

    p.tick();
    let r = p.utimensat(AT_FDCWD, Some(&file), None, 0);
    p.check("a null times pointer is now/now", r == 0);
    let null_now = p.fstat_or_stop(fd);
    p.check(
        "null times set atime and mtime to one later instant",
        null_now.atime_ns == null_now.mtime_ns && null_now.mtime_ns > now.mtime_ns,
    );

    // Errno vocabulary.
    let r = p.utimensat(
        AT_FDCWD,
        Some(&file),
        Some([TimeArg::Set(1, 1_000_000_000), TimeArg::Omit]),
        0,
    );
    p.check("tv_nsec out of range is EINVAL", r == neg(EINVAL));
    let r = p.utimensat(AT_FDCWD, Some(&file), None, 0x1);
    p.check("an unknown flag is EINVAL", r == neg(EINVAL));
    let r = p.utimensat(AT_FDCWD, Some(&format!("{root}/missing")), None, 0);
    p.check("a missing path is ENOENT", r == neg(ENOENT));

    // The descriptor shape: utimensat(fd, NULL, times, 0), which glibc
    // spells futimens(fd, times).
    let r = p.utimensat(
        fd,
        None,
        Some([TimeArg::Set(4000, 11), TimeArg::Set(5000, 13)]),
        0,
    );
    p.check(
        "utimensat(fd, NULL, times, 0) sets the descriptor's times",
        r == 0,
    );
    let by_fd = p.fstat_or_stop(fd);
    p.check(
        "the descriptor's times are what was set",
        by_fd.atime_ns == 4000 * SEC + 11 && by_fd.mtime_ns == 5000 * SEC + 13,
    );
    let location = p.openat(AT_FDCWD, &file, O_PATH, 0);
    p.require("open f O_PATH", location >= 0);
    let r = p.utimensat(location, None, None, 0);
    p.check("an O_PATH descriptor is EBADF", r == neg(EBADF));
    let r = p.utimensat(4000, None, None, 0);
    p.check("a closed descriptor is EBADF", r == neg(EBADF));
    p.close(location);

    // ---- the microsecond and whole-second spellings --------------------
    let r = p.utimes(&file, Some([(6000, 123_456), (7000, 654_321)]));
    p.check("utimes with microsecond times", r == 0);
    let micro = p.fstat_or_stop(fd);
    p.check(
        "utimes round-trips microseconds",
        micro.atime_ns == 6000 * SEC + 123_456_000 && micro.mtime_ns == 7000 * SEC + 654_321_000,
    );
    let r = p.utimes(&file, Some([(1, 1_000_000), (1, 0)]));
    p.check("tv_usec out of range is EINVAL", r == neg(EINVAL));
    p.tick();
    let r = p.utimes(&file, None);
    p.check("utimes with null times is now/now", r == 0);
    let micro_now = p.fstat_or_stop(fd);
    p.check(
        "utimes now/now is one later instant",
        micro_now.atime_ns == micro_now.mtime_ns && micro_now.mtime_ns > null_now.mtime_ns,
    );

    let r = p.utime(&file, Some((8000, 9000)));
    p.check("utime with whole-second times", r == 0);
    let whole = p.fstat_or_stop(fd);
    p.check(
        "utime round-trips whole seconds",
        whole.atime_ns == 8000 * SEC && whole.mtime_ns == 9000 * SEC,
    );
    p.tick();
    let r = p.utime(&file, None);
    p.check("utime with a null buffer is now/now", r == 0);
    let whole_now = p.fstat_or_stop(fd);
    p.check(
        "utime now/now is one later instant",
        whole_now.atime_ns == whole_now.mtime_ns && whole_now.mtime_ns > micro_now.mtime_ns,
    );

    p.check("mkdirat d", p.mkdirat(AT_FDCWD, &dir, 0o755) == 0);
    let dirfd = p.openat(AT_FDCWD, &dir, O_RDONLY | O_DIRECTORY, 0);
    p.require("open d", dirfd >= 0);
    let inner = p.openat(dirfd, "inner", O_WRONLY | O_CREAT | O_EXCL, 0o644);
    p.require("create d/inner", inner >= 0);
    let r = p.futimesat(dirfd, "inner", Some([(10_000, 1), (11_000, 2)]));
    p.check("futimesat relative to a directory descriptor", r == 0);
    let via_dir = p.fstat_or_stop(inner);
    p.check(
        "futimesat round-trips microseconds through the dirfd",
        via_dir.atime_ns == 10_000 * SEC + 1_000 && via_dir.mtime_ns == 11_000 * SEC + 2_000,
    );

    // ---- directories -----------------------------------------------------
    let before = p.fstat_or_stop(dirfd);
    p.tick();
    let child = p.openat(dirfd, "child", O_WRONLY | O_CREAT | O_EXCL, 0o644);
    p.require("create d/child", child >= 0);
    p.close(child);
    let after_create = p.fstat_or_stop(dirfd);
    p.check(
        "a name appearing moves the directory's mtime and ctime forward",
        after_create.mtime_ns > before.mtime_ns && after_create.ctime_ns > before.ctime_ns,
    );
    p.tick();
    p.check("unlinkat d/child", p.unlinkat(dirfd, "child", 0) == 0);
    let after_unlink = p.fstat_or_stop(dirfd);
    p.check(
        "a name disappearing moves the directory's mtime and ctime forward",
        after_unlink.mtime_ns > after_create.mtime_ns
            && after_unlink.ctime_ns > after_create.ctime_ns,
    );
    p.tick();
    let r = p.utimensat(
        dirfd,
        Some("."),
        Some([TimeArg::Set(12_000, 0), TimeArg::Set(13_000, 0)]),
        0,
    );
    p.check("utimensat on a directory", r == 0);
    let dir_set = p.fstat_or_stop(dirfd);
    p.check(
        "a directory's times are what was set",
        dir_set.atime_ns == 12_000 * SEC && dir_set.mtime_ns == 13_000 * SEC,
    );

    // ---- symlinks --------------------------------------------------------
    p.check("symlinkat l -> f", p.symlinkat("f", AT_FDCWD, &link) == 0);
    p.tick();
    let target_before = p.stat_or_stop(&file, 0);
    let r = p.utimensat(
        AT_FDCWD,
        Some(&link),
        Some([TimeArg::Set(14_000, 0), TimeArg::Set(15_000, 0)]),
        AT_SYMLINK_NOFOLLOW,
    );
    p.check("AT_SYMLINK_NOFOLLOW names the link itself", r == 0);
    let link_times = p.stat_or_stop(&link, AT_SYMLINK_NOFOLLOW);
    p.check(
        "the link's own times are what was set",
        link_times.atime_ns == 14_000 * SEC && link_times.mtime_ns == 15_000 * SEC,
    );
    let target_after = p.stat_or_stop(&file, 0);
    p.check(
        "the target's times are untouched",
        target_after.atime_ns == target_before.atime_ns
            && target_after.mtime_ns == target_before.mtime_ns
            && target_after.ctime_ns == target_before.ctime_ns,
    );
    let r = p.utimensat(
        AT_FDCWD,
        Some(&link),
        Some([TimeArg::Set(16_000, 0), TimeArg::Set(17_000, 0)]),
        0,
    );
    p.check("without the flag the target is named", r == 0);
    let followed = p.stat_or_stop(&file, 0);
    p.check(
        "the target's times are what was set through the link",
        followed.atime_ns == 16_000 * SEC && followed.mtime_ns == 17_000 * SEC,
    );
    // Traversing the link is a read of it (`pick_link` touches its atime
    // under the mount's policy), so only its mtime/ctime are pinned here.
    let link_after = p.stat_or_stop(&link, AT_SYMLINK_NOFOLLOW);
    p.check(
        "the link's own mtime and ctime are untouched",
        link_after.mtime_ns == link_times.mtime_ns && link_after.ctime_ns == link_times.ctime_ns,
    );

    // Class pairing: zero-transfer effects and inode-addressed timestamps.
    p.tick();
    let before = p.fstat_or_stop(fd);
    p.lseek(fd, 100, SEEK_SET);
    p.check("zero read past EOF", p.read(fd, 0).0 == 0);
    p.check("zero write past EOF", p.write(fd, b"") == 0);
    let after = p.fstat_or_stop(fd);
    p.check(
        "zero I/O stamps nothing and never grows",
        after.size == before.size
            && after.atime_ns == before.atime_ns
            && after.mtime_ns == before.mtime_ns
            && after.ctime_ns == before.ctime_ns,
    );
    p.check("zero I/O preserves cursor", p.lseek(fd, 0, SEEK_CUR) == 100);
    p.check("truncate below cursor", p.ftruncate(fd, 0) == 0);
    p.check("read past truncated EOF", p.read(fd, 1).0 == 0);
    p.check("EOF read preserves cursor", p.lseek(fd, 0, SEEK_CUR) == 100);
    for flags in [0, 1] {
        p.check(
            "OMIT ignores missing path and flags",
            p.utimensat(
                AT_FDCWD,
                Some(&format!("{root}/missing")),
                Some([TimeArg::Omit, TimeArg::Omit]),
                flags,
            ) == 0,
        );
    }
    p.check(
        "OMIT ignores closed fd",
        p.utimensat(4000, None, Some([TimeArg::Omit, TimeArg::Omit]), 0) == 0,
    );
    let location = p.openat(AT_FDCWD, &file, O_PATH, 0);
    p.require("open timestamp location", location >= 0);
    p.check(
        "utimensat AT_EMPTY_PATH on O_PATH",
        p.utimensat(
            location,
            Some(""),
            Some([TimeArg::Set(21, 3), TimeArg::Set(22, 4)]),
            AT_EMPTY_PATH,
        ) == 0,
    );
    let after = p.fstat_or_stop(fd);
    p.check(
        "empty path reached the inode",
        after.atime_ns == 21 * SEC + 3 && after.mtime_ns == 22 * SEC + 4,
    );
    p.close(location);
    let fifo = format!("{root}/fifo-times");
    p.require(
        "create FIFO for timestamps",
        p.mknodat(AT_FDCWD, &fifo, S_IFIFO | 0o600, 0) == 0,
    );
    let pipe = p.openat(AT_FDCWD, &fifo, O_RDWR, 0);
    p.require("open FIFO for timestamps", pipe >= 0);
    for unlinked in [false, true] {
        if unlinked {
            p.unlinkat(AT_FDCWD, &fifo, 0);
        }
        p.check(
            "futimens reaches retained FIFO",
            p.utimensat(
                pipe,
                None,
                Some([TimeArg::Set(23, 5), TimeArg::Set(24, 6)]),
                0,
            ) == 0,
        );
        let after = p.fstat_or_stop(pipe);
        p.check(
            "FIFO times landed",
            after.atime_ns == 23 * SEC + 5 && after.mtime_ns == 24 * SEC + 6,
        );
    }
    p.close(pipe);
    // Linux accepts and clamps to its filesystem range; Patina's unsigned
    // nanosecond ABI explicitly refuses unrepresentable values (registry gap).
    let overflow = 18_446_744_074;
    for spelling in 0..3 {
        let r = match spelling {
            0 => p.utimensat(
                fd,
                None,
                Some([TimeArg::Set(overflow, 0), TimeArg::Set(overflow, 0)]),
                0,
            ),
            1 => p.utimes(&file, Some([(overflow, 0), (overflow, 0)])),
            _ => p.utime(&file, Some((overflow, overflow))),
        };
        let after = p.fstat_or_stop(fd);
        p.check(
            "time overflow is refused or clamped, never wrapped",
            r == neg(EINVAL) || (r == 0 && after.mtime_ns > 10_000_000_000_000_000_000),
        );
    }
    // Exercise the literal libc symbol too: the adapter above intentionally
    // spells a null-path request as futimens, which cannot detect this split.
    let literal_ok = if p.vehicle == crate::vehicle::Vehicle::Libc {
        let r = unsafe { libc::utimensat(fd, std::ptr::null(), std::ptr::null(), 0) };
        r == -1 && std::io::Error::last_os_error().raw_os_error() == Some(EINVAL)
    } else {
        p.vehicle
            .call(Syscall::N_utimensat, [fd as i64, 0, 0, 0, 0, 0])
            == 0
    };
    p.check(
        "literal null path preserves libc versus kernel contract",
        literal_ok,
    );
    p.close(inner);
    p.close(dirfd);
    p.close(fd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/times",
    run,
    covers: &[
        Syscall::N_utimensat,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_utime,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_utimes,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_futimesat,
        Syscall::N_ftruncate,
        Syscall::N_fstat,
        Syscall::N_newfstatat,
        Syscall::N_statx,
        Syscall::N_openat,
        Syscall::N_read,
        Syscall::N_write,
        Syscall::N_close,
        Syscall::N_nanosleep,
        Syscall::N_linkat,
        Syscall::N_renameat,
        Syscall::N_mkdirat,
        Syscall::N_unlinkat,
        Syscall::N_symlinkat,
    ],
    symbols: &[
        "utimensat",
        "futimens",
        "utime",
        "utimes",
        "futimesat",
        "ftruncate",
        "fstat",
        "fstatat",
        "statx",
        "openat",
        "read",
        "write",
        "close",
        "nanosleep",
        "linkat",
        "renameat",
        "mkdirat",
        "unlinkat",
        "symlinkat",
    ],
    gaps: &[Gap {
        status: Status::Pending(Arc::Fs),
        vehicles: Vehicle::ALL,
        what: "signed/wide filesystem timestamps: the unsigned-nanosecond ABI refuses out-of-range seconds with EINVAL; Linux accepts them and clamps to its filesystem range (checked conversion, never wrap)",
        failure: Failure::Differs(&[
            Difference::field(186, "utimensat", "errno", Observed::Str("EINVAL")),
            Difference::field(186, "utimensat", "ret", Observed::Int(-1)),
            Difference::field(189, "utimes", "errno", Observed::Str("EINVAL")),
            Difference::field(189, "utimes", "ret", Observed::Int(-1)),
            Difference::field(192, "utime", "errno", Observed::Str("EINVAL")),
            Difference::field(192, "utime", "ret", Observed::Int(-1)),
        ]),
    }],
    ..DEFAULTS
};
