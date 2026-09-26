//! fs/mount_query — reading the mount table by unique mount id
//! (fs/namespace.c `statmount`, `listmount`). Neither needs a privilege for
//! a mount reachable from the caller's root (`CAP_SYS_ADMIN` only reaches
//! past it), so the unprivileged caller is answered:
//!
//! * an unknown `flags` bit is `EINVAL` first; the request is then read
//!   (`copy_mnt_id_req`): unreadable `EFAULT`, a `size` past a page `E2BIG`,
//!   short of `MNT_ID_REQ_SIZE_VER0` `EINVAL`, a nonzero `spare` `EINVAL`
//!   (6.17 makes that word `mnt_ns_fd`, a descriptor not open `EBADF`);
//! * a mount id no mount has is `ENOENT` (unique ids start past 2^32; 6.11
//!   moves that to 2^31 and refuses an id at or below it as `EINVAL`: the id
//!   asked for is far past both);
//! * the entropy device is on a devtmpfs mount of the namespace, at its path
//!   or above it;
//! * a pipe's, a socket's or a namespace file's node is on an internal
//!   mount `statx` names but `statmount` does not know (`ENOENT`), with no
//!   birth time;
//! * `statmount` of the root's mount (its id from `statx`'s
//!   `STATX_MNT_ID_UNIQUE`) answers the requested mask, that id and the
//!   mount point `/`; a buffer with no room for a requested string is
//!   `EOVERFLOW`, an unwritable one `EFAULT`; the strings follow the fixed
//!   part after an empty one (Ubuntu's 6.8 carries 6.14's reserved empty
//!   string), and `size` counts every byte written;
//! * `listmount` of `LSMT_ROOT` into no room answers 0, and into room lists
//!   the root's own mount among the mounts below it (how many there are is
//!   the host's business); below the root's mount by its id, the mount
//!   itself is left out;
//! * `access_ok` judges a buffer's range before the lookup without
//!   touching it: on x86_64 a range ending below the sign bit passes.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `struct mnt_id_req`, `MNT_ID_REQ_SIZE_VER0` bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct Request {
    size: u32,
    spare: u32,
    mnt_id: u64,
    param: u64,
}
const REQUEST_SIZE: u32 = 24;

/// The fixed part of `struct statmount` (512 bytes), then room for strings.
#[repr(C)]
#[allow(dead_code)] // the kernel's layout; the scenario reads a few members
struct Statmount {
    size: u32,
    spare1: u32,
    mask: u64,
    sb_dev_major: u32,
    sb_dev_minor: u32,
    sb_magic: u64,
    sb_flags: u32,
    fs_type: u32,
    mnt_id: u64,
    mnt_parent_id: u64,
    mnt_id_old: u32,
    mnt_parent_id_old: u32,
    mnt_attr: u64,
    mnt_propagation: u64,
    mnt_peer_group: u64,
    mnt_master: u64,
    propagate_from: u64,
    mnt_root: u32,
    mnt_point: u32,
    spare2: [u64; 50],
    strings: [u8; 3584],
}
const FIXED: usize = 512;

const STATMOUNT_MNT_BASIC: u64 = 0x2;
const STATMOUNT_MNT_POINT: u64 = 0x10;
const STATMOUNT_FS_TYPE: u64 = 0x20;
const LSMT_ROOT: u64 = u64::MAX;
const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
/// No mount has this unique id: past every release's first id, and not
/// `LSMT_ROOT`.
const NO_MOUNT: u64 = u64::MAX - 1;
/// A flag bit neither row defines on any kernel (7.0's `statmount` takes
/// `STATMOUNT_BY_FD`, 1; 6.11's `listmount` takes `LISTMOUNT_REVERSE`, 1).
const UNKNOWN_FLAG: i64 = 1 << 31;
/// A descriptor number the run never opens.
const CLOSED: u32 = 4000;
/// Unmapped ranges `access_ok` admits (6.8 on both architectures: x86_64
/// checks the end's sign bit, arm64 the 48-bit user space), and one ending
/// past the user address space: the answer below a mount no mount has.
const USER_RANGES: [(usize, usize, i32); 4] = [
    (0x7fff_ffff_f000, 16, ENOENT),
    (0x8000_0000_0000, 16, ENOENT),
    (0, 1 << 47, ENOENT),
    (0x7fff_ffff_ffff_f000, 0x2000, EFAULT),
];

pub fn run(p: &Probe) {
    let request = |mnt_id: u64, param: u64| Request {
        size: REQUEST_SIZE,
        spare: 0,
        mnt_id,
        param,
    };
    // SAFETY: plain data.
    let mut sm: Box<Statmount> = Box::new(unsafe { std::mem::zeroed() });
    let statmount = |req: Option<&Request>, buf: *mut Statmount, len: usize, flags: i64| {
        let req = req.map_or(std::ptr::null(), |req| req as *const Request);
        p.call_observed(
            Syscall::N_statmount,
            [req as i64, buf as i64, len as i64, flags, 0, 0],
        )
    };
    let whole = std::mem::size_of::<Statmount>();
    let buf: *mut Statmount = &mut *sm;
    p.check(
        "an unknown flag is EINVAL before the request is read",
        statmount(None, std::ptr::null_mut(), 0, UNKNOWN_FLAG) == neg(EINVAL),
    );
    p.check(
        "an unreadable request is EFAULT",
        statmount(None, buf, whole, 0) == neg(EFAULT),
    );
    let big = Request {
        size: 8192,
        ..request(NO_MOUNT, 0)
    };
    p.check(
        "a request size past a page is E2BIG",
        statmount(Some(&big), buf, whole, 0) == neg(E2BIG),
    );
    let short = Request {
        size: 16,
        ..request(NO_MOUNT, 0)
    };
    p.check(
        "a request size short of MNT_ID_REQ_SIZE_VER0 is EINVAL",
        statmount(Some(&short), buf, whole, 0) == neg(EINVAL),
    );
    let spare = Request {
        spare: CLOSED,
        ..request(NO_MOUNT, 0)
    };
    p.check(
        "a nonzero spare is EINVAL",
        statmount(Some(&spare), buf, whole, 0) == neg(EINVAL),
    );
    p.check(
        "a mount id no mount has is ENOENT",
        statmount(Some(&request(NO_MOUNT, 0)), buf, whole, 0) == neg(ENOENT),
    );
    // `access_ok` judges the buffer's range before the lookup, and never
    // touches it: a range ending inside the user address space passes
    // (x86_64 checks only the sign bit of its end, not `TASK_SIZE_MAX`),
    // one ending past it is EFAULT.
    for (at, len, answer) in USER_RANGES {
        p.check(
            &format!("a buffer of {len:#x} bytes at {at:#x} is judged by access_ok"),
            statmount(Some(&request(NO_MOUNT, 0)), at as *mut Statmount, len, 0) == neg(answer),
        );
    }

    // SAFETY: plain data.
    let mut stx: statx = unsafe { std::mem::zeroed() };
    let slash = c"/";
    let r = p.call_observed(
        Syscall::N_statx,
        [
            AT_FDCWD as i64,
            slash.as_ptr() as i64,
            0,
            STATX_MNT_ID_UNIQUE as i64,
            &mut stx as *mut statx as i64,
            0,
        ],
    );
    let root = stx.stx_mnt_id;
    p.require(
        "statx names the root's unique mount id",
        r == 0 && stx.stx_mask & STATX_MNT_ID_UNIQUE != 0,
    );
    p.check("a unique mount id is past 2^32", root > 1 << 32);

    // A pipe's, a socket's and a namespace file's nodes are on the kernel's
    // internal mounts (pipefs, sockfs, nsfs), in no namespace: `statx` names
    // a mount of their own, which `statmount` does not know, and none of
    // those filesystems records a birth time.
    let (_, pipe) = p.pipe2(0);
    let (_, pair) = p.socketpair(AF_UNIX, SOCK_STREAM, 0);
    let ns = p.openat(AT_FDCWD, "/proc/self/ns/uts", O_RDONLY | O_CLOEXEC, 0);
    p.require("open the caller's UTS namespace", ns >= 0);
    for (what, fd) in [
        ("a pipe", pipe[0]),
        ("a socket", pair[0]),
        ("a namespace file", ns),
    ] {
        // SAFETY: plain data.
        let mut node: statx = unsafe { std::mem::zeroed() };
        let r = p.call_observed(
            Syscall::N_statx,
            [
                fd as i64,
                c"".as_ptr() as i64,
                AT_EMPTY_PATH as i64,
                (STATX_MNT_ID_UNIQUE | STATX_BTIME) as i64,
                &mut node as *mut statx as i64,
                0,
            ],
        );
        p.check(
            &format!("{what}'s node is on a mount of its own, with no birth time"),
            r == 0
                && node.stx_mask & STATX_MNT_ID_UNIQUE != 0
                && node.stx_mask & STATX_BTIME == 0
                && node.stx_mnt_id != root,
        );
        p.check(
            &format!("statmount knows no mount of {what}'s"),
            statmount(
                Some(&request(node.stx_mnt_id, STATMOUNT_MNT_BASIC)),
                buf,
                whole,
                0,
            ) == neg(ENOENT),
        );
    }
    for fd in [pipe[0], pipe[1], pair[0], pair[1], ns] {
        p.close(fd);
    }

    // The entropy device is on a devtmpfs mount of the namespace: `statx`
    // names it, and `statmount` of it answers devtmpfs mounted at the
    // device's path or a directory above it.
    // SAFETY: plain data.
    let mut device: statx = unsafe { std::mem::zeroed() };
    let r = p.call_observed(
        Syscall::N_statx,
        [
            AT_FDCWD as i64,
            c"/dev/urandom".as_ptr() as i64,
            0,
            STATX_MNT_ID_UNIQUE as i64,
            &mut device as *mut statx as i64,
            0,
        ],
    );
    p.check(
        "the entropy device is on a mount of its own",
        r == 0 && device.stx_mask & STATX_MNT_ID_UNIQUE != 0 && device.stx_mnt_id != root,
    );
    let r = statmount(
        Some(&request(
            device.stx_mnt_id,
            STATMOUNT_MNT_POINT | STATMOUNT_FS_TYPE,
        )),
        buf,
        whole,
        0,
    );
    let string = |offset: u32| {
        sm.strings
            .get(offset as usize..)
            .and_then(|rest| std::ffi::CStr::from_bytes_until_nul(rest).ok())
            .map(|text| text.to_bytes().to_vec())
    };
    let (fs_type, point) = (string(sm.fs_type), string(sm.mnt_point));
    p.check(
        "statmount of it answers devtmpfs, mounted at or above the device",
        r == 0
            && fs_type.as_deref() == Some(b"devtmpfs".as_slice())
            && point.is_some_and(|point| {
                let device = b"/dev/urandom".as_slice();
                point == b"/"
                    || point == device
                    || device
                        .strip_prefix(point.as_slice())
                        .is_some_and(|rest| rest.starts_with(b"/"))
            }),
    );

    let wanted = STATMOUNT_MNT_BASIC | STATMOUNT_MNT_POINT;
    let r = statmount(Some(&request(root, wanted)), buf, whole, 0);
    let point = sm
        .strings
        .get(sm.mnt_point as usize..)
        .and_then(|rest| std::ffi::CStr::from_bytes_until_nul(rest).ok())
        .map(|point| point.to_bytes().to_vec());
    p.check(
        "statmount of the root's mount answers the requested mask",
        r == 0 && sm.mask == wanted,
    );
    p.check("it is the requested mount", sm.mnt_id == root);
    p.check(
        "mounted at the caller's root",
        point.as_deref() == Some(b"/".as_slice()),
    );
    p.check(
        "a buffer with no room for a requested string is EOVERFLOW",
        statmount(Some(&request(root, STATMOUNT_MNT_POINT)), buf, FIXED, 0) == neg(EOVERFLOW),
    );
    // "\0/\0": the reserved empty string, then the mount point.
    let room = FIXED + 3;
    let r = statmount(Some(&request(root, STATMOUNT_MNT_POINT)), buf, room, 0);
    p.check(
        "room for the fixed part, an empty string and the mount point suffices, and size counts it all",
        r == 0 && sm.size as usize == room && sm.mnt_point == 1,
    );
    p.check(
        "an unwritable buffer is EFAULT",
        statmount(
            Some(&request(root, STATMOUNT_MNT_BASIC)),
            std::ptr::null_mut(),
            whole,
            0,
        ) == neg(EFAULT),
    );

    let mut ids = [0u64; 64];
    let into = ids.as_mut_ptr();
    let listmount = |req: &Request, room: usize, flags: i64| {
        p.call_observed(
            Syscall::N_listmount,
            [
                req as *const Request as i64,
                into as i64,
                room as i64,
                flags,
                0,
                0,
            ],
        )
    };
    p.check(
        "listmount with an unknown flag is EINVAL",
        listmount(&request(LSMT_ROOT, 0), ids.len(), UNKNOWN_FLAG) == neg(EINVAL),
    );
    p.check(
        "listmount below a mount id no mount has is ENOENT",
        listmount(&request(NO_MOUNT, 0), ids.len(), 0) == neg(ENOENT),
    );
    // (`listmount` bounds the count first: a million ids.)
    for (at, len, answer) in USER_RANGES.into_iter().filter(|(_, len, _)| *len < 1 << 20) {
        let room = len.div_ceil(size_of::<u64>());
        let r = p.call_observed(
            Syscall::N_listmount,
            [
                &request(NO_MOUNT, 0) as *const Request as i64,
                at as i64,
                room as i64,
                0,
                0,
                0,
            ],
        );
        p.check(
            &format!("an array of {room} ids at {at:#x} is judged by access_ok"),
            r == neg(answer),
        );
    }
    p.check(
        "listmount into no room answers 0",
        listmount(&request(LSMT_ROOT, 0), 0, 0) == 0,
    );
    let listed = p.call_unrecorded(
        Syscall::N_listmount,
        [
            &request(LSMT_ROOT, 0) as *const Request as i64,
            into as i64,
            ids.len() as i64,
            0,
            0,
            0,
        ],
    );
    p.check(
        "listing below the root names the root's own mount",
        listed >= 1 && ids[..(listed as usize).min(ids.len())].contains(&root),
    );
    let listed = p.call_unrecorded(
        Syscall::N_listmount,
        [
            &request(root, 0) as *const Request as i64,
            into as i64,
            ids.len() as i64,
            0,
            0,
            0,
        ],
    );
    // Something is always mounted below the root's mount (the host's
    // `/proc`, `/dev`; patina's `/dev/urandom`), so an empty answer would
    // not show the mount left out.
    p.check(
        "listing below the root's mount by its id leaves that mount out",
        listed >= 1 && !ids[..(listed as usize).min(ids.len())].contains(&root),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/mount_query",
    run,
    // glibc has no wrapper for either row: the libc spelling would be
    // `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_statmount, Syscall::N_listmount, Syscall::N_statx],
    ..DEFAULTS
};
