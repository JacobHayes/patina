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
//! * `statmount` of the root's mount (its id from `statx`'s
//!   `STATX_MNT_ID_UNIQUE`) answers the requested mask, that id and the
//!   mount point `/`; a buffer with no room for a requested string is
//!   `EOVERFLOW`, an unwritable one `EFAULT`;
//! * `listmount` of `LSMT_ROOT` into no room answers 0, and into room lists
//!   the root's own mount among the mounts below it (how many there are is
//!   the host's business).

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
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
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/mount_query",
    run,
    // glibc has no wrapper for either row: the libc spelling would be
    // `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_statmount, Syscall::N_listmount, Syscall::N_statx],
    gaps: &[Gap {
        status: Status::Pending(Arc::Privileged),
        vehicles: Vehicle::KERNEL,
        what: "statmount is a fatal privileged trap (patina-syscalls linux.rs Trap(TRAP_PRIVILEGED)), as is listmount, where the kernel answers any caller about the mounts reachable from its root",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall statmount (nr 457, class privileged",
        },
    }],
    ..DEFAULTS
};
