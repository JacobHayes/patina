//! The virtual processes' credentials, their place in the process tree, and
//! the virtual kernel's self-description (`kernel/sys.c`, `kernel/groups.c`,
//! `kernel/capability.c`): the rows both doors answer from the identities
//! the runtime models (`registry::IDENTITY_*`, `registry::INIT_PID`).
//!
//! Each process holds its own credential ([`Credential`], looked up by pid
//! through [`lookup`] and [`Process::credential`]). The guest's
//! ([`credential`], the caller's: every caller is a guest thread) is an
//! ordinary unprivileged user whose real, effective, saved and filesystem
//! ids are all [`IDENTITY_UID`]/[`IDENTITY_GID`], whose only supplementary
//! group is its own, and whose capability sets are empty but for the full
//! bounding set every process starts with. Init's is root's, as a machine's
//! init runs (`init_cred`): uid and gid 0, every capability effective and
//! permitted. Every Linux reader of the caller's ids reads the guest's: the
//! id rows of both doors, the owner `stat` reports and `chown`
//! (`crate::caller`), System V IPC ownership, `SO_PEERCRED`, a signal's
//! `si_uid` and `PRIO_USER`; so do the capability checks of the privileged
//! rows (`sud::privileged`). A check the kernel makes against another
//! process reads that process's credential: `capget` of a pid, the signal
//! permission check ([`may_signal`]) and the ptrace-mode check
//! ([`ptrace_may_access`]). The shim's other capability
//! refusals answer for the guest's credential without consulting it yet
//! (ARCHITECTURE lists what an identity setting still needs). So the
//! `set*id` rows succeed exactly when every id they name is that one id
//! (the kernel's rule for a caller without `CAP_SETUID`/`CAP_SETGID`),
//! which changes nothing; anything else is `EPERM`.
//!
//! The process tree is a pid namespace of two processes: its init
//! ([`INIT_PID`], leader of process group 1 and session 1) and the guest
//! ([`IDENTITY_PID`]), init's child, starting as the leader of its own group
//! inside init's session, as a program a container's init started. The
//! guest's group and session are process state its `setpgid`/`setsid` change
//! under the kernel's rules; init's never change. Init has no signal
//! handlers and sleeps (see `registry::INIT_PID`).

use crate::SpinMutex;
use crate::neg_errno as errno;
use crate::registry::{Capability, IDENTITY_GID, IDENTITY_PID, IDENTITY_UID, INIT_PID};
use crate::{EFAULT, EINVAL, EPERM, ESRCH};
use std::ffi::c_int;

/// A process's credential (`struct cred`): its ids, its supplementary
/// groups, and its five capability sets as masks of [`Capability::bit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Credential {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) groups: &'static [u32],
    pub(crate) effective: u64,
    pub(crate) permitted: u64,
    pub(crate) inheritable: u64,
    pub(crate) bounding: u64,
    pub(crate) ambient: u64,
}

impl Credential {
    /// `capable`/`ns_capable` (`cap_capable`): whether the effective set
    /// holds `capability`. The virtual machine has one user namespace, so
    /// the namespace a check names changes nothing.
    pub(crate) const fn capable(&self, capability: Capability) -> bool {
        self.effective & capability.bit() != 0
    }
}

/// The credential the virtual kernel runs the guest with: uid/gid
/// [`IDENTITY_UID`]/[`IDENTITY_GID`], its own group, no capability in the
/// effective, permitted, inheritable or ambient set, and the full bounding
/// set (no ancestor dropped one). It is fixed for the run.
const CREDENTIAL: Credential = Credential {
    uid: IDENTITY_UID,
    gid: IDENTITY_GID,
    groups: &[IDENTITY_GID],
    effective: 0,
    permitted: 0,
    inheritable: 0,
    bounding: Capability::ALL,
    ambient: 0,
};

/// Init's credential, root's (`init_cred`): uid/gid 0, no supplementary
/// group, every capability effective and permitted and in the bounding set,
/// none inheritable or ambient. It is fixed for the run.
const ROOT: Credential = Credential {
    uid: 0,
    gid: 0,
    groups: &[],
    effective: Capability::ALL,
    permitted: Capability::ALL,
    inheritable: 0,
    bounding: Capability::ALL,
    ambient: 0,
};

/// The caller's credential (`current_cred`): every caller is a thread of the
/// guest, so the guest's ([`CREDENTIAL`]).
pub(crate) const fn credential() -> &'static Credential {
    Process::Guest.credential()
}

const GUEST: i32 = IDENTITY_PID as i32;
const INIT: i32 = INIT_PID as i32;

/// A process of the virtual pid namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Process {
    Init,
    Guest,
}

impl Process {
    /// The process's credential (`__task_cred`): init's is root's
    /// ([`ROOT`]), the guest's the unprivileged user's ([`CREDENTIAL`]).
    pub(crate) const fn credential(self) -> &'static Credential {
        match self {
            Process::Init => &ROOT,
            Process::Guest => &CREDENTIAL,
        }
    }

    /// The process's session (`task_session`).
    fn session(self) -> i32 {
        match self {
            Process::Init => INIT,
            Process::Guest => MEMBERSHIP.lock().sid,
        }
    }
}

/// `SIGCONT`, which `check_kill_permission` lets through within a session.
const SIGCONT: i32 = linux_raw_sys::general::SIGCONT as i32;

/// `kill_ok_by_cred`: whether a sender holding `sender` may signal a
/// process holding `target` — the sender's real or effective uid is the
/// target's real or saved one (each credential holds one uid), or the
/// sender has `CAP_KILL`.
fn kill_ok_by_cred(sender: &Credential, target: &Credential) -> bool {
    sender.uid == target.uid || sender.capable(Capability::Kill)
}

/// `check_kill_permission` for a signal from user space (`si_fromuser`) the
/// caller, in session `sender_sid`, sends a process of another thread group
/// holding `target` in session `target_sid`: [`kill_ok_by_cred`], or else
/// only `SIGCONT` within the same session. The signal is valid already.
fn kill_permitted(
    sender: &Credential,
    sender_sid: i32,
    target: &Credential,
    target_sid: i32,
    sig: i32,
) -> bool {
    kill_ok_by_cred(sender, target) || (sig == SIGCONT && sender_sid == target_sid)
}

/// Whether the caller may send `sig` (valid, from user space) to `target`
/// (`check_kill_permission`): always to its own thread group, the guest;
/// to init, root's, only a `SIGCONT` while the guest is in init's session
/// (it starts there, and leaves by `setsid`).
pub(crate) fn may_signal(target: Process, sig: i32) -> bool {
    target == Process::Guest
        || kill_permitted(
            credential(),
            Process::Guest.session(),
            target.credential(),
            target.session(),
            sig,
        )
}

/// `__ptrace_may_access` (kernel/ptrace.c) of a caller holding `caller` to
/// `target`, in any mode: the caller's own thread group, the guest, always;
/// another process when its real, effective and saved ids all equal the
/// caller's (each credential holds one uid and one gid), or with
/// `CAP_SYS_PTRACE`. Init is root's, so the guest reaches it only through
/// the capability (the kernel's further refusal of a non-dumpable target
/// passes with the capability too, so it never decides an answer here).
pub(crate) fn ptrace_may_access(caller: &Credential, target: Process) -> bool {
    let theirs = target.credential();
    target == Process::Guest
        || (caller.uid == theirs.uid && caller.gid == theirs.gid)
        || caller.capable(Capability::SysPtrace)
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
        // joined group 1: a group's signal succeeds when any member takes
        // it, and the caller always does).
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
            Id::User => credential().uid,
            Id::Group => credential().gid,
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

/// `getgroups(size, list)`: the credential's supplementary groups — the
/// count for a size of 0, the list into a
/// buffer at least that long, `EINVAL` for a shorter or negative size.
///
/// # Safety
/// `list` must be NULL or writable for `size` ids.
pub(crate) unsafe fn getgroups(size: i32, list: *mut u32) -> i64 {
    if size < 0 {
        return errno(EINVAL);
    }
    let groups = credential().groups;
    let count = groups.len();
    if size != 0 {
        if count > size as usize {
            return errno(EINVAL);
        }
        if list.is_null() {
            return errno(EFAULT);
        }
        // SAFETY: per this function's contract.
        unsafe { std::ptr::copy_nonoverlapping(groups.as_ptr(), list, count) };
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
/// one answers 0 with the kernel's written back); any process's sets may be
/// read, from its credential — pid 0 is the caller, init's are root's; a
/// negative pid is `EINVAL`, one no process has `ESRCH`.
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
    // Any process's (or thread's) sets may be read (`cap_get_target_pid`).
    let credential = match pid {
        0 => credential(),
        pid => match lookup(pid) {
            Some((process, _)) => process.credential(),
            None => return errno(ESRCH),
        },
    };
    for index in 0..count {
        let word = |set: u64| (set >> (32 * index)) as u32;
        let sets = CapData {
            effective: word(credential.effective),
            permitted: word(credential.permitted),
            inheritable: word(credential.inheritable),
        };
        // SAFETY: as above.
        unsafe { data.add(index).write_unaligned(sets) };
    }
    0
}

/// A process's three settable capability sets, as `capset` asks for them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CapSets {
    effective: u64,
    permitted: u64,
    inheritable: u64,
}

/// `cap_capset`'s rules for `old` asking for `new`: without `CAP_SETPCAP`
/// the new inheritable set stays within the old inheritable and permitted
/// ones, and always within the old inheritable and bounding ones; the
/// permitted set may only shrink; the effective set stays within the new
/// permitted one.
fn cap_capset(old: &Credential, new: CapSets) -> bool {
    let capped = !old.capable(Capability::Setpcap);
    !((capped && new.inheritable & !(old.inheritable | old.permitted) != 0)
        || new.inheritable & !(old.inheritable | old.bounding) != 0
        || new.permitted & !old.permitted != 0
        || new.effective & !new.permitted != 0)
}

/// `capset` for a caller holding `credential`: only the caller's own sets
/// (another pid `EPERM`), each assembled from its two words and cut to the
/// capabilities the kernel knows (`mk_kernel_cap`: a bit past
/// `CAP_LAST_CAP` is dropped, not refused), then [`cap_capset`]'s rules
/// (`EPERM`). Sets equal to the credential's change nothing (0); the
/// credential is fixed, so a change the rules would allow is a named fatal.
///
/// # Safety
/// As [`capget`], with `data` readable.
pub(crate) unsafe fn capset(
    credential: &Credential,
    header: *mut CapHeader,
    data: *const CapData,
) -> i64 {
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
    let mut new = CapSets {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    };
    for index in 0..count {
        // SAFETY: as above.
        let set = unsafe { data.add(index).read_unaligned() };
        new.effective |= u64::from(set.effective) << (32 * index);
        new.permitted |= u64::from(set.permitted) << (32 * index);
        new.inheritable |= u64::from(set.inheritable) << (32 * index);
    }
    new.effective &= Capability::ALL;
    new.permitted &= Capability::ALL;
    new.inheritable &= Capability::ALL;
    if !cap_capset(credential, new) {
        return errno(EPERM);
    }
    let old = CapSets {
        effective: credential.effective,
        permitted: credential.permitted,
        inheritable: credential.inheritable,
    };
    if new != old {
        crate::trap_fatal(
            "capset: changing the capability sets is not modeled (the virtual credential is \
             fixed); failing closed",
        );
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
    let hostname = match crate::node_name() {
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
            assert_eq!(
                capset(credential(), &mut header, data.as_ptr()),
                errno(EPERM)
            );
            data[0] = CapData::default();
            assert_eq!(capset(credential(), &mut header, data.as_ptr()), 0);
            header.pid = 99;
            assert_eq!(
                capset(credential(), &mut header, data.as_ptr()),
                errno(EPERM)
            );
            // Bits past `CAP_LAST_CAP` are dropped (`mk_kernel_cap`), so
            // sets naming only those are the current, empty ones.
            header.pid = 0;
            data[1] = CapData {
                effective: 0xffff_fe00,
                permitted: 0xffff_fe00,
                inheritable: 0xffff_fe00,
            };
            assert_eq!(capset(credential(), &mut header, data.as_ptr()), 0);
        }
    }

    /// `cap_capset` for credentials other than the guest's: `CAP_SETPCAP`
    /// lets the inheritable set take a capability outside the permitted set
    /// (but never outside the bounding set), and the permitted set never
    /// grows.
    #[test]
    fn capset_follows_cap_capset_for_any_credential() {
        let chown = Capability::Chown.bit();
        let setpcap = Capability::Setpcap.bit();
        let holding = |held: u64, bounding: u64| Credential {
            effective: held,
            permitted: held,
            bounding,
            ..*credential()
        };
        let inheriting = |set: u64| CapSets {
            effective: 0,
            permitted: 0,
            inheritable: set,
        };
        let pcap = holding(setpcap, Capability::ALL);
        assert!(cap_capset(
            &pcap,
            CapSets {
                permitted: setpcap,
                ..inheriting(chown)
            }
        ));
        assert!(!cap_capset(&holding(0, Capability::ALL), inheriting(chown)));
        assert!(!cap_capset(&holding(setpcap, setpcap), inheriting(chown)));
        assert!(!cap_capset(
            &pcap,
            CapSets {
                permitted: setpcap | chown,
                ..inheriting(0)
            }
        ));
        assert!(!cap_capset(
            &pcap,
            CapSets {
                effective: setpcap,
                ..inheriting(0)
            }
        ));
    }

    /// A check against another process reads that process's credential:
    /// init's sets are root's, and the guest reaches it (signal, ptrace
    /// mode) only as the kernel lets an unprivileged user reach root's.
    #[test]
    fn another_process_is_judged_by_its_own_credential() {
        let mut header = CapHeader {
            version: CAPABILITY_V3,
            pid: INIT,
        };
        let mut data = [CapData::default(); 2];
        // SAFETY: local buffers.
        assert_eq!(unsafe { capget(&mut header, data.as_mut_ptr()) }, 0);
        let word = |set: u64, index: u32| (set >> (32 * index)) as u32;
        for (index, sets) in data.iter().enumerate() {
            let full = word(Capability::ALL, index as u32);
            assert_eq!(
                (sets.effective, sets.permitted, sets.inheritable),
                (full, full, 0)
            );
        }

        let guest = credential();
        let root = Process::Init.credential();
        let with = |capability: Capability| Credential {
            effective: capability.bit(),
            permitted: capability.bit(),
            ..*guest
        };
        let usr1 = linux_raw_sys::general::SIGUSR1 as i32;
        assert!(!kill_permitted(guest, INIT, root, INIT, usr1));
        assert!(!kill_permitted(guest, INIT, root, INIT, 0));
        // `SIGCONT` only within the target's session.
        assert!(kill_permitted(guest, INIT, root, INIT, SIGCONT));
        assert!(!kill_permitted(guest, GUEST, root, INIT, SIGCONT));
        assert!(kill_permitted(
            &with(Capability::Kill),
            GUEST,
            root,
            INIT,
            usr1
        ));
        assert!(kill_permitted(guest, GUEST, guest, INIT, usr1));
        assert!(may_signal(Process::Guest, usr1));

        assert!(ptrace_may_access(guest, Process::Guest));
        assert!(!ptrace_may_access(guest, Process::Init));
        assert!(!ptrace_may_access(&with(Capability::Kill), Process::Init));
        assert!(ptrace_may_access(
            &with(Capability::SysPtrace),
            Process::Init
        ));
        assert!(ptrace_may_access(root, Process::Init));
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
