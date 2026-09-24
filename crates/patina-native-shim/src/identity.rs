//! The virtual process's credentials, its place in the process tree, and
//! the virtual kernel's self-description (`kernel/sys.c`, `kernel/groups.c`,
//! `kernel/capability.c`): the rows both doors answer from the one identity
//! the runtime models (`registry::IDENTITY_*`).
//!
//! The identity is an ordinary unprivileged user: its real, effective, saved
//! and filesystem ids are all [`IDENTITY_UID`]/[`IDENTITY_GID`], its only
//! supplementary group is its own, and every capability set is empty. So the
//! `set*id` rows succeed exactly when every id they name is that one id (the
//! kernel's rule for a caller without `CAP_SETUID`/`CAP_SETGID`), which
//! changes nothing; anything else is `EPERM`.
//!
//! The process tree is a pid namespace of two processes: its init
//! ([`INIT_PID`], leader of process group 1 and session 1) and the guest
//! ([`IDENTITY_PID`]), init's child, starting as the leader of its own group
//! inside init's session, as a program a container's init started. The
//! guest's group and session are process state its `setpgid`/`setsid` change
//! under the kernel's rules; init's never change. Init runs as the same user
//! with no signal handlers, is not dumpable and sleeps (see
//! `registry::INIT_PID`).

use crate::SpinMutex;
use crate::neg_errno as errno;
use crate::registry::{IDENTITY_GID, IDENTITY_PID, IDENTITY_UID, INIT_PID};
use crate::{EFAULT, EINVAL, EPERM, ESRCH};
use std::ffi::c_int;

const GUEST: i32 = IDENTITY_PID as i32;
const INIT: i32 = INIT_PID as i32;

/// A process of the virtual pid namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Process {
    Init,
    Guest,
}

/// The guest's process group and session.
struct Membership {
    pgid: i32,
    sid: i32,
}

static MEMBERSHIP: SpinMutex<Membership> = SpinMutex::new(Membership {
    pgid: GUEST,
    sid: INIT,
});

/// `find_task_by_vpid`: the process a pid (or one of its thread ids) names,
/// and whether it names the process's main thread (its thread-group leader).
pub(crate) fn lookup(pid: i32) -> Option<(Process, bool)> {
    if pid == INIT {
        return Some((Process::Init, true));
    }
    crate::thread::live_tid(pid).then_some((Process::Guest, pid == GUEST))
}

/// The guest's process group.
pub(crate) fn pgid() -> i32 {
    MEMBERSHIP.lock().pgid
}

/// The processes `kill(pid, …)` reaches that a signal can be delivered to
/// (`kill_something_info`): a pid or thread id names its process; with
/// `groups`, 0 is the caller's group, -1 every process but init and the
/// caller (none here), and another negative number the group it negates.
/// `None` is `ESRCH`. Init is reported so the caller can answer for it.
pub(crate) fn signal_target(pid: i32, groups: bool) -> Option<Process> {
    if pid > 0 {
        return lookup(pid).map(|(process, _)| process);
    }
    if !groups {
        return None;
    }
    match pid {
        // The caller's group holds the caller (and init, when the guest
        // joined group 1, which takes nothing).
        0 => Some(Process::Guest),
        -1 => None,
        group => (group.checked_neg() == Some(pgid())).then_some(Process::Guest),
    }
}

/// `(uid_t)-1`: "unchanged" to the `set*id` rows.
const UNCHANGED: u32 = u32::MAX;

/// Which credential a row names.
#[derive(Clone, Copy)]
pub(crate) enum Id {
    User,
    Group,
}

impl Id {
    fn own(self) -> u32 {
        match self {
            Id::User => IDENTITY_UID,
            Id::Group => IDENTITY_GID,
        }
    }
}

/// `getresuid`/`getresgid`: the id three times.
///
/// # Safety
/// Each pointer must be NULL or writable for an id.
pub(crate) unsafe fn getres(id: Id, real: *mut u32, effective: *mut u32, saved: *mut u32) -> i64 {
    for out in [real, effective, saved] {
        if out.is_null() {
            return errno(EFAULT);
        }
        // SAFETY: per this function's contract.
        unsafe { out.write_unaligned(id.own()) };
    }
    0
}

/// `setuid`/`setgid`: `-1` is no id (`EINVAL`); the own id succeeds.
pub(crate) fn set(id: Id, value: u32) -> i64 {
    match value {
        UNCHANGED => errno(EINVAL),
        value if value == id.own() => 0,
        _ => errno(EPERM),
    }
}

/// `setreuid`/`setregid`, `setresuid`/`setresgid`: every id other than `-1`
/// must be one the caller holds.
pub(crate) fn set_many(id: Id, values: &[u32]) -> i64 {
    if values
        .iter()
        .all(|value| *value == UNCHANGED || *value == id.own())
    {
        0
    } else {
        errno(EPERM)
    }
}

/// `setfsuid`/`setfsgid`: the previous filesystem id, always; a change to an
/// id the caller does not hold is refused silently, and `-1` only queries.
pub(crate) fn set_fs(id: Id) -> i64 {
    i64::from(id.own())
}

/// The supplementary groups: the identity's own group.
const GROUPS: [u32; 1] = [IDENTITY_GID];

/// `getgroups(size, list)`: the count for a size of 0, the list into a
/// buffer at least that long, `EINVAL` for a shorter or negative size.
///
/// # Safety
/// `list` must be NULL or writable for `size` ids.
pub(crate) unsafe fn getgroups(size: i32, list: *mut u32) -> i64 {
    if size < 0 {
        return errno(EINVAL);
    }
    let count = GROUPS.len();
    if size != 0 {
        if count > size as usize {
            return errno(EINVAL);
        }
        if list.is_null() {
            return errno(EFAULT);
        }
        // SAFETY: per this function's contract.
        unsafe { std::ptr::copy_nonoverlapping(GROUPS.as_ptr(), list, count) };
    }
    count as i64
}

/// `setgroups`: `CAP_SETGID` first, so `EPERM` before the size is looked at.
pub(crate) fn setgroups() -> i64 {
    errno(EPERM)
}

/// `struct __user_cap_header_struct`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CapHeader {
    version: u32,
    pid: i32,
}

/// `struct __user_cap_data_struct`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAPABILITY_V1: u32 = 0x1998_0330;
const CAPABILITY_V2: u32 = 0x2007_1026;
const CAPABILITY_V3: u32 = 0x2008_0522;

/// `cap_validate_magic`: how many data structs the version carries; an
/// unknown version gets the kernel's own written back, and `EINVAL`.
///
/// # Safety
/// `header` must be readable and writable.
unsafe fn cap_version(header: *mut CapHeader) -> Result<usize, c_int> {
    // SAFETY: per this function's contract.
    let version = unsafe { (*header).version };
    match version {
        CAPABILITY_V1 => Ok(1),
        CAPABILITY_V2 | CAPABILITY_V3 => Ok(2),
        _ => {
            // SAFETY: as above.
            unsafe { (*header).version = CAPABILITY_V3 };
            Err(EINVAL)
        }
    }
}

/// `capget`: a NULL data pointer only negotiates the version (an unknown
/// one answers 0 with the kernel's written back); the sets of the caller —
/// pid 0 or its own — are empty; a negative pid is `EINVAL`, another `ESRCH`.
///
/// # Safety
/// `header` must be NULL or a readable and writable header, `data` NULL or
/// writable for the version's data structs.
pub(crate) unsafe fn capget(header: *mut CapHeader, data: *mut CapData) -> i64 {
    if header.is_null() {
        return errno(EFAULT);
    }
    // SAFETY: per this function's contract.
    let version = unsafe { cap_version(header) };
    if data.is_null() {
        return match version {
            Ok(_) | Err(EINVAL) => 0,
            Err(other) => errno(other),
        };
    }
    let count = match version {
        Ok(count) => count,
        Err(other) => return errno(other),
    };
    // SAFETY: as above.
    let pid = unsafe { (*header).pid };
    if pid < 0 {
        return errno(EINVAL);
    }
    // Any process's (or thread's) sets may be read: init's are empty too.
    if pid != 0 && lookup(pid).is_none() {
        return errno(ESRCH);
    }
    for index in 0..count {
        // SAFETY: as above.
        unsafe { data.add(index).write_unaligned(CapData::default()) };
    }
    0
}

/// `capset`: only the caller's own sets (another pid `EPERM`), and an
/// unprivileged caller can only keep them empty: an inheritable or permitted
/// set beyond the current (empty) ones, or an effective set beyond the new
/// permitted one, is `EPERM`.
///
/// # Safety
/// As [`capget`], with `data` readable.
pub(crate) unsafe fn capset(header: *mut CapHeader, data: *const CapData) -> i64 {
    if header.is_null() {
        return errno(EFAULT);
    }
    // SAFETY: per this function's contract.
    let count = match unsafe { cap_version(header) } {
        Ok(count) => count,
        Err(other) => return errno(other),
    };
    // SAFETY: as above.
    let pid = unsafe { (*header).pid };
    // Only the caller's own sets (`pid != task_pid_vnr(current)`).
    if pid != 0 && pid != crate::thread::current_tid() {
        return errno(EPERM);
    }
    if data.is_null() {
        return errno(EFAULT);
    }
    let (mut effective, mut permitted, mut inheritable) = (0u64, 0u64, 0u64);
    for index in 0..count {
        // SAFETY: as above.
        let set = unsafe { data.add(index).read_unaligned() };
        effective |= u64::from(set.effective) << (32 * index);
        permitted |= u64::from(set.permitted) << (32 * index);
        inheritable |= u64::from(set.inheritable) << (32 * index);
    }
    if inheritable != 0 || permitted != 0 || effective & !permitted != 0 {
        return errno(EPERM);
    }
    0
}

/// `getpgrp` (a row of the x86_64 table only): the caller's group.
#[cfg(target_arch = "x86_64")]
pub(crate) fn getpgrp() -> i64 {
    i64::from(pgid())
}

/// `setpgid(pid, pgid)` (`kernel/sys.c`): 0 names the caller, and a group of
/// 0 the pid itself; a negative group is `EINVAL`. The process must exist
/// (`ESRCH`) and be named by its main thread (`EINVAL`); the caller has no
/// children, so any process but itself is `ESRCH`; a session leader cannot
/// move (`EPERM`); and a group other than its own pid must exist in the
/// caller's session (`EPERM`) — group 1 does while the guest is in init's
/// session, and the guest's current group always does.
pub(crate) fn setpgid(pid: i32, group: i32) -> i64 {
    // 0 is the caller's process, named by its leader's pid
    // (`task_pid_vnr(group_leader)`), whichever thread calls.
    let pid = if pid == 0 { GUEST } else { pid };
    let group = if group == 0 { pid } else { group };
    if group < 0 {
        return errno(EINVAL);
    }
    let Some((process, leader)) = lookup(pid) else {
        return errno(ESRCH);
    };
    if !leader {
        return errno(EINVAL);
    }
    if process != Process::Guest {
        return errno(ESRCH);
    }
    let mut membership = MEMBERSHIP.lock();
    if membership.sid == GUEST {
        return errno(EPERM);
    }
    let exists_in_session = group == membership.pgid || (group == INIT && membership.sid == INIT);
    if group != GUEST && !exists_in_session {
        return errno(EPERM);
    }
    membership.pgid = group;
    0
}

/// The group and session of `pid` (0: the caller), or `ESRCH`.
fn membership_of(pid: i32) -> Result<(i32, i32), i64> {
    let process = if pid == 0 {
        Process::Guest
    } else {
        lookup(pid).ok_or(errno(ESRCH))?.0
    };
    Ok(match process {
        Process::Init => (INIT, INIT),
        Process::Guest => {
            let membership = MEMBERSHIP.lock();
            (membership.pgid, membership.sid)
        }
    })
}

/// `getpgid(pid)`: the group of any process (0: the caller).
pub(crate) fn getpgid(pid: i32) -> i64 {
    membership_of(pid).map_or_else(|errno| errno, |(pgid, _)| i64::from(pgid))
}

/// `getsid(pid)`: the session of any process (0: the caller).
pub(crate) fn getsid(pid: i32) -> i64 {
    membership_of(pid).map_or_else(|errno| errno, |(_, sid)| i64::from(sid))
}

/// `setsid` (`ksys_setsid`): a session leader, or a process whose pid names
/// a group (a group leader), is `EPERM`; otherwise the guest leads a new
/// session and group, both its pid, which it answers.
pub(crate) fn setsid() -> i64 {
    let mut membership = MEMBERSHIP.lock();
    if membership.sid == GUEST || membership.pgid == GUEST {
        return errno(EPERM);
    }
    membership.sid = GUEST;
    membership.pgid = GUEST;
    i64::from(GUEST)
}

/// `struct new_utsname`: six 65-byte fields.
#[repr(C)]
pub(crate) struct Utsname {
    fields: [[u8; UTS_LEN]; 6],
}
const UTS_LEN: usize = 65;

/// The virtual kernel's release: its ABI level (`registry::VIRTUAL_ABI`).
fn release() -> String {
    let (major, minor, patch) =
        crate::registry::parse_release(crate::registry::VIRTUAL_ABI).expect("a kernel release");
    format!("{major}.{minor}.{patch}-patina")
}

/// `override_release`: a `UNAME26` persona reads the release as `2.6.x`,
/// x being 60 past the patch level, the rest of the release kept.
fn release_for(persona: u32) -> String {
    let release = release();
    if persona & UNAME26 == 0 {
        return release;
    }
    let mut dots = 0;
    let rest = release
        .char_indices()
        .find(|(_, c)| {
            if *c == '.' {
                dots += 1;
                dots >= 3
            } else {
                !c.is_ascii_digit()
            }
        })
        .map_or("", |(index, _)| &release[index..]);
    let minor = crate::registry::parse_release(&release).map_or(0, |(_, minor, _)| minor);
    format!("2.6.{}{rest}", minor + 60)
}

/// The `UNAME26` persona flag.
const UNAME26: u32 = 0x0002_0000;
/// `PER_LINUX32`: `uname` reports the compat machine.
const PER_LINUX32: u32 = 0x0008;
const PER_MASK: u32 = 0x00ff;

/// `uname(2)`: `Linux`, the node name (the run's `--hostname`), the virtual
/// kernel's release and version, the machine, and no NIS domain; the
/// caller's persona can override the release and the machine.
///
/// # Safety
/// `out` must be NULL or writable for a `struct new_utsname`.
pub(crate) unsafe fn uname(out: *mut Utsname, persona: u32) -> i64 {
    if out.is_null() {
        return errno(EFAULT);
    }
    let machine = match (
        cfg!(target_arch = "x86_64"),
        persona & PER_MASK == PER_LINUX32,
    ) {
        (true, false) => "x86_64",
        (true, true) => "i686",
        (false, false) => "aarch64",
        (false, true) => "armv8l",
    };
    let release = release_for(persona);
    // The run's node name (`--hostname`), a recorded run fact: read from the
    // installed runtime, which a call before installation installs or, from
    // a static constructor that ran before Patina's, refuses by name — never
    // a default a constructor could cache for the whole run.
    if let Err(code) = crate::ensure_runtime() {
        return errno(code);
    }
    let hostname = match crate::with_context_raw(|context| Ok(context.hostname().to_owned())) {
        Ok(hostname) => hostname,
        Err(code) => return errno(code),
    };
    let values = [
        "Linux",
        hostname.as_str(),
        release.as_str(),
        "#1 SMP PREEMPT_DYNAMIC",
        machine,
        "(none)",
    ];
    let mut name = Utsname {
        fields: [[0; UTS_LEN]; 6],
    };
    for (field, value) in name.fields.iter_mut().zip(values) {
        let bytes = &value.as_bytes()[..value.len().min(UTS_LEN - 1)];
        field[..bytes.len()].copy_from_slice(bytes);
    }
    // SAFETY: per this function's contract.
    unsafe { out.write_unaligned(name) };
    0
}

/// `struct sysinfo` on the 64-bit targets.
#[repr(C)]
#[derive(Default)]
pub(crate) struct Sysinfo {
    uptime: i64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    pad: u16,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
}

/// `sysinfo(2)`: the uptime is the boot clock's seconds rounded up; the
/// virtual machine's memory (`limits::MACHINE_MEMORY`) is half free, with no
/// swap, no high memory, no shared or buffer pages; its load is idle; the
/// threads it runs are init's and the guest's.
///
/// # Safety
/// `out` must be NULL or writable for a `struct sysinfo`.
pub(crate) unsafe fn sysinfo(out: *mut Sysinfo) -> i64 {
    let boot = match crate::clocks::read(crate::clocks::Clock::Boottime) {
        Ok(boot) => boot,
        Err(other) => return errno(other),
    };
    if out.is_null() {
        return errno(EFAULT);
    }
    let info = Sysinfo {
        uptime: boot.div_ceil(crate::clocks::NANOS) as i64,
        totalram: crate::limits::MACHINE_MEMORY,
        freeram: crate::limits::MACHINE_MEMORY / 2,
        // The kernel reports the machine's thread count (`nr_threads`,
        // kernel threads included), which no pid namespace sees; the virtual
        // machine runs nothing but init's thread and the guest's, so that is
        // the model's figure.
        procs: u16::try_from(crate::thread::live_threads() + 1).unwrap_or(u16::MAX),
        mem_unit: 1,
        ..Sysinfo::default()
    };
    // SAFETY: per this function's contract.
    unsafe { out.write_unaligned(info) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_ids_succeed_only_for_the_ids_held() {
        let own = IDENTITY_UID;
        assert_eq!(set(Id::User, own), 0);
        assert_eq!(set(Id::User, own + 1), errno(EPERM));
        assert_eq!(set(Id::User, UNCHANGED), errno(EINVAL));
        assert_eq!(set_many(Id::User, &[UNCHANGED, UNCHANGED, UNCHANGED]), 0);
        assert_eq!(set_many(Id::User, &[own, UNCHANGED, own]), 0);
        assert_eq!(set_many(Id::User, &[own, own + 1, own]), errno(EPERM));
        assert_eq!(set_fs(Id::Group), i64::from(IDENTITY_GID));
    }

    #[test]
    fn getgroups_answers_the_count_and_refuses_a_short_buffer() {
        let mut list = [0u32; 4];
        // SAFETY: local buffers.
        unsafe {
            assert_eq!(getgroups(0, std::ptr::null_mut()), 1);
            assert_eq!(getgroups(4, list.as_mut_ptr()), 1);
            assert_eq!(getgroups(-1, list.as_mut_ptr()), errno(EINVAL));
        }
        assert_eq!(list[0], IDENTITY_GID);
    }

    #[test]
    fn capability_versions_negotiate_as_the_kernel_does() {
        let mut header = CapHeader { version: 0, pid: 0 };
        let mut data = [CapData::default(); 2];
        // SAFETY: local buffers.
        unsafe {
            assert_eq!(capget(&mut header, std::ptr::null_mut()), 0);
            assert_eq!(header.version, CAPABILITY_V3);
            header.version = 0;
            assert_eq!(capget(&mut header, data.as_mut_ptr()), errno(EINVAL));
            assert_eq!(header.version, CAPABILITY_V3);
            header.pid = -1;
            assert_eq!(capget(&mut header, data.as_mut_ptr()), errno(EINVAL));
            header.pid = 0;
            data[0].effective = 1 << 13;
            assert_eq!(capset(&mut header, data.as_ptr()), errno(EPERM));
            data[0] = CapData::default();
            assert_eq!(capset(&mut header, data.as_ptr()), 0);
            header.pid = 99;
            assert_eq!(capset(&mut header, data.as_ptr()), errno(EPERM));
        }
    }

    /// The one test that moves the guest's group and session: the tree's
    /// rules in order, then the starting membership restored.
    #[test]
    fn the_guest_moves_through_the_tree_as_the_kernel_allows() {
        // A group leader in init's session.
        assert_eq!((getpgid(0), getsid(0)), (i64::from(GUEST), i64::from(INIT)));
        assert_eq!((getpgid(INIT), getsid(INIT)), (1, 1));
        assert_eq!(setpgid(0, 0), 0);
        assert_eq!(setpgid(GUEST, GUEST), 0);
        assert_eq!(setpgid(0, -1), errno(EINVAL));
        assert_eq!(setpgid(77, 0), errno(ESRCH));
        assert_eq!(setpgid(INIT, 0), errno(ESRCH));
        assert_eq!(setpgid(0, 77), errno(EPERM));
        assert_eq!(setsid(), errno(EPERM));
        // Into init's group, which leaves no group 2: a session may start.
        assert_eq!(setpgid(0, INIT), 0);
        assert_eq!(getpgid(0), 1);
        assert_eq!(signal_target(-GUEST, true), None);
        assert_eq!(setsid(), i64::from(GUEST));
        assert_eq!(
            (getpgid(0), getsid(0)),
            (i64::from(GUEST), i64::from(GUEST))
        );
        // A session leader cannot move, nor start another session, and
        // init's group is no longer in its session.
        assert_eq!(setpgid(0, 0), errno(EPERM));
        assert_eq!(setsid(), errno(EPERM));
        assert_eq!(signal_target(-1, true), None);
        assert_eq!(signal_target(-GUEST, true), Some(Process::Guest));
        assert_eq!(signal_target(INIT, false), Some(Process::Init));
        *MEMBERSHIP.lock() = Membership {
            pgid: GUEST,
            sid: INIT,
        };
    }

    #[test]
    fn uname26_reads_the_release_as_two_six() {
        let (_, minor, _) = crate::registry::parse_release(&release()).unwrap();
        let release = release_for(UNAME26);
        assert!(
            release.starts_with(&format!("2.6.{}", minor + 60)),
            "{release}"
        );
        assert!(release.ends_with("-patina"), "{release}");
        assert!(crate::registry::parse_release(&release_for(0)).is_some());
    }
}
