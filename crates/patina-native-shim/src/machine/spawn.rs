//! `posix_spawn` of an admitted program, and `wait4`/`waitid` over the
//! hub's process table.
//!
//! A spawn makes the child a process of the machine: the hub numbers it
//! from the machine's one id namespace, asks the supervisor to start the
//! admitted artifact with the child's end of a fresh channel and this
//! process's host stdio, waits for the child to report ready, and adds it
//! to the table and to its scheduler as a runnable foreign task. The child
//! runs when the scheduler picks it.
//!
//! What this slice does not model stops the run by name, as the spawn
//! entries' refusal does (`unsupported`, `deny_trap`): a spawn from a child,
//! a spawn while recording or replaying, file actions, spawn attributes
//! other than the signal mask and default dispositions a fresh process has
//! anyway, a signal mask that is not empty, a run the supervisor gave no
//! launch channel (crash-restart and the scheduling-policy knobs), and
//! arguments or environment that are not UTF-8.

use super::*;
use core::ffi::{CStr, c_char};
use patina_dst_runtime::{ENV_LAUNCH_FD, ExecutionMode};
use std::collections::BTreeMap;

/// `WNOHANG`, `WNOWAIT` and `WEXITED`.
const WNOHANG: u32 = 0x0000_0001;
const WEXITED: u32 = 0x0000_0004;
const WNOWAIT: u32 = 0x0100_0000;

/// `POSIX_SPAWN_SETSIGDEF`, `POSIX_SPAWN_SETSIGMASK` and
/// `POSIX_SPAWN_USEVFORK`: a fresh process has default dispositions and an
/// empty mask, and how glibc makes it does not show.
const SPAWN_MODELED_FLAGS: i16 = 0x04 | 0x08 | 0x40;
/// `POSIX_SPAWN_SETSIGMASK`.
const SPAWN_SETSIGMASK: i16 = 0x08;

/// Tasks of this process parked in a wait for a child.
static WAITERS: SpinMutex<Vec<TaskId>> = SpinMutex::new(Vec::new());

/// What a spawn entry was handed, as the caller handed it.
pub(crate) struct Spawn {
    pub(crate) symbol: &'static CStr,
    pub(crate) pid: *mut libc::pid_t,
    pub(crate) path: *const c_char,
    pub(crate) file_actions: *const libc::posix_spawn_file_actions_t,
    pub(crate) attr: *const libc::posix_spawnattr_t,
    pub(crate) argv: *const *mut c_char,
    pub(crate) envp: *const *mut c_char,
}

/// `posix_spawn`/`posix_spawnp` of `spawn.path`: `None` when the program is
/// not admitted (the caller refuses it as it refuses every spawn), else the
/// entry's answer.
///
/// # Safety
/// Every pointer follows libc's `posix_spawn` argument contract.
pub(crate) unsafe fn spawn(spawn: &Spawn) -> Option<c_int> {
    use crate::admission::{Admission, admitted_program};
    if spawn.path.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated string, per the entry's contract.
    let path = unsafe { CStr::from_ptr(spawn.path) };
    let Admission::Admitted(artifact) = admitted_program(path) else {
        return None;
    };
    if is_child() {
        refuse(spawn, "from a child process (nested spawn)");
    }
    let mode = context(|context| Ok(context.execution_mode()));
    if mode != ExecutionMode::Seeded {
        refuse(spawn, "while recording or replaying");
    }
    let Ok(Some(launcher)) = crate::parse_control_u64(ENV_LAUNCH_FD) else {
        refuse(spawn, "in a run the supervisor gives no launch channel");
    };
    // SAFETY: the caller's actions object, per the entry's contract.
    if !spawn.file_actions.is_null() && unsafe { actions_used(spawn.file_actions) } != 0 {
        refuse(spawn, "with file actions");
    }
    if !spawn.attr.is_null() {
        // SAFETY: the caller's attributes object, per the entry's contract.
        let (flags, mask_empty) = unsafe { attributes(spawn.attr) };
        if flags & !SPAWN_MODELED_FLAGS != 0 {
            refuse(spawn, "with spawn attributes");
        }
        if flags & SPAWN_SETSIGMASK != 0 && !mask_empty {
            refuse(spawn, "with a signal mask");
        }
    }
    // SAFETY: NULL-terminated arrays of strings, per the entry's contract.
    let argv = unsafe { strings(spawn.argv) }
        .unwrap_or_else(|| refuse(spawn, "with arguments that are not UTF-8"));
    // SAFETY: as above.
    let entries = unsafe { strings(spawn.envp) }
        .unwrap_or_else(|| refuse(spawn, "with an environment that is not UTF-8"));
    let mut env = BTreeMap::new();
    for entry in entries {
        if let Some((name, value)) = entry.split_once('=') {
            env.entry(name.to_owned())
                .or_insert_with(|| value.to_owned());
        }
    }
    if let Err(message) = thread::activate() {
        protocol_fatal_text(&message);
    }
    let pid = allocate_id();
    let (pgid, sid) = crate::identity::add_child(pid);
    let parent = crate::patina_pid();
    let seed = context(|context| Ok(child_seed(context.root_seed(), pid)));
    // The child starts in the caller's working directory.
    let cwd = crate::paths::cwd_path().unwrap_or_else(|errno| {
        protocol_fatal_text(&format!("the working directory is unreadable ({errno})"))
    });
    let [hub, child] = socketpair();
    // The launch request: the admitted artifact by its index in the
    // supervisor's list, and the child's arguments, environment, place in
    // the process tree, seed and working directory. Its descriptors are the child's channel
    // end, then stdin, stdout and stderr.
    let request = serde_json::json!({
        "artifact": artifact,
        "argv": argv,
        "env": env,
        "pid": pid,
        "parent": parent,
        "pgid": pgid,
        "sid": sid,
        "seed": seed,
        "cwd": cwd,
    });
    let payload = serde_json::to_vec(&request)
        .unwrap_or_else(|error| protocol_fatal_text(&format!("encoding a launch: {error}")));
    send_with_fds(launcher as c_int, &payload, &[child, 0, 1, 2]);
    close(child);
    // The child may use the filesystem before it is ready (its working
    // directory): the hub serves it meanwhile.
    match serve(pid, hub) {
        Message::Ready => {}
        other => protocol_fatal("a new process's ready", &other),
    }
    CHILDREN.lock().insert(
        pid,
        Child {
            parent,
            channel: hub,
            status: None,
        },
    );
    ROLE.store(ROLE_ROOT, Ordering::Relaxed);
    context(|context| context.task_foreign(foreign_task(pid), ForeignState::Runnable));
    if !spawn.pid.is_null() {
        // SAFETY: a writable pid, per the entry's contract.
        unsafe { spawn.pid.write(pid) };
    }
    Some(0)
}

/// A child's seed: the run's, mixed with the child's pid (splitmix64), so
/// each process draws its own stream and the same run draws the same ones.
fn child_seed(root: u64, pid: i32) -> u64 {
    let mut z = root ^ (pid as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The spawn stops the run: `what` is the part of it this slice does not
/// model.
fn refuse(spawn: &Spawn, what: &str) -> ! {
    // SAFETY: a NUL-terminated string (checked non-null by the caller).
    let path = unsafe { CStr::from_ptr(spawn.path) }.to_string_lossy();
    let detail = format!(
        "the guest called {} `{path}` {what}, which Patina does not model yet",
        spawn.symbol.to_string_lossy()
    );
    let line = format!("patina: process spawn reached under patina: {detail}; failing closed\n");
    let _ = crate::host_write_all(2, line.as_bytes());
    crate::patina_flush_captured_stdio();
    crate::host_abort(crate::RunStop::unmodeled(&[detail.as_bytes()]))
}

/// glibc's `posix_spawn_file_actions_t.__used`: how many actions it holds.
///
/// # Safety
/// `actions` is a live actions object.
unsafe fn actions_used(actions: *const libc::posix_spawn_file_actions_t) -> c_int {
    // SAFETY: `__used` is the second `int` of glibc's actions object.
    unsafe { actions.cast::<c_int>().add(1).read_unaligned() }
}

/// glibc's `posix_spawnattr_t`: its flags (`__flags`, the leading `short`)
/// and whether its signal mask (`__ss`, after the flags, the group and the
/// default set) is empty.
///
/// # Safety
/// `attr` is a live attributes object.
unsafe fn attributes(attr: *const libc::posix_spawnattr_t) -> (i16, bool) {
    const MASK_OFFSET: usize = 8 + size_of::<libc::sigset_t>();
    // SAFETY: both fields lie inside glibc's attributes object.
    unsafe {
        let flags = attr.cast::<i16>().read_unaligned();
        let mask = attr
            .cast::<u8>()
            .add(MASK_OFFSET)
            .cast::<libc::sigset_t>()
            .read_unaligned();
        let empty = (1..=64).all(|sig| libc::sigismember(&mask, sig) != 1);
        (flags, empty)
    }
}

/// The strings of a NULL-terminated array (none for NULL), or `None` if one
/// is not UTF-8.
///
/// # Safety
/// `array` is NULL or a NULL-terminated array of C strings.
unsafe fn strings(array: *const *mut c_char) -> Option<Vec<String>> {
    let mut strings = Vec::new();
    if array.is_null() {
        return Some(strings);
    }
    for index in 0.. {
        // SAFETY: within the NULL-terminated array.
        let item = unsafe { *array.add(index) };
        if item.is_null() {
            break;
        }
        // SAFETY: a C string, per the contract.
        let text = unsafe { CStr::from_ptr(item) }.to_str().ok()?;
        strings.push(text.to_owned());
    }
    Some(strings)
}

/// A `SOCK_SEQPACKET` pair, close-on-exec: the hub's end, the child's end.
fn socketpair() -> [c_int; 2] {
    let mut pair = [-1 as c_int; 2];
    // SAFETY: a writable pair of descriptors.
    let rc = unsafe {
        crate::sud_host_syscall(
            libc::SYS_socketpair,
            libc::AF_UNIX as _,
            (libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC) as _,
            0,
            pair.as_mut_ptr() as _,
            0,
            0,
        )
    };
    if rc != 0 {
        protocol_fatal_text("creating a process channel failed");
    }
    pair
}

/// Send `payload` on `fd` with `fds` as `SCM_RIGHTS`.
fn send_with_fds(fd: c_int, payload: &[u8], fds: &[c_int]) {
    let fd_bytes = size_of_val(fds);
    // SAFETY: `CMSG_SPACE` is arithmetic.
    let space = unsafe { libc::CMSG_SPACE(fd_bytes as u32) } as usize;
    let mut control = vec![0u64; space.div_ceil(8)];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: payload.len(),
    };
    // SAFETY: an all-zero msghdr is valid; the fields set below point at
    // buffers live for the call.
    let mut header: libc::msghdr = unsafe { core::mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = space as _;
    // SAFETY: the control buffer holds one header and `fds`.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&header);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
        core::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg).cast(), fds.len());
    }
    loop {
        // SAFETY: the header and its buffers are live for the call.
        let sent = unsafe {
            crate::sud_host_syscall(
                libc::SYS_sendmsg,
                fd as _,
                (&raw const header) as _,
                libc::MSG_NOSIGNAL as _,
                0,
                0,
                0,
            )
        };
        if sent == payload.len() as i64 {
            return;
        }
        if sent < 0 && crate::abi::host_errno() == libc::EINTR {
            continue;
        }
        protocol_fatal_text("asking the supervisor to launch a process failed");
    }
}

/// What a wait finds among the caller's children.
enum Found {
    /// A zombie: its pid and wait status.
    Zombie(i32, i32),
    /// Children that match, none of them a zombie yet.
    Running,
    /// No child matches (`ECHILD`).
    None,
}

/// Look for a child of the caller that `pid` matches (`wait4`'s `pid`: one
/// child, -1 any, 0 or minus the caller's group any in that group).
fn find(pid: i32) -> Found {
    let me = crate::patina_pid();
    let group = crate::identity::pgid();
    let any = pid == -1 || pid == 0 || pid == -group;
    let children = CHILDREN.lock();
    let mut running = false;
    for (child_pid, child) in children.iter() {
        if child.parent != me || !(any || *child_pid == pid) {
            continue;
        }
        match child.status {
            Some(status) => return Found::Zombie(*child_pid, status),
            None => running = true,
        }
    }
    if running { Found::Running } else { Found::None }
}

/// Reap zombie `pid`: it leaves the table.
fn reap(pid: i32) {
    CHILDREN.lock().remove(&pid);
}

/// Park the caller until a child changes state; `Err(errno)` when a signal
/// ends the wait.
fn park() -> Result<(), c_int> {
    let mut me = None;
    let parked = thread::wait_for_child(|task| {
        me = Some(task);
        WAITERS.lock().push(task);
    });
    // The waker took the task off the list; a signal left it there.
    if let Some(me) = me {
        WAITERS.lock().retain(|task| *task != me);
    }
    parked
}

/// A child exited: every task waiting for one looks again.
pub(super) fn wake_waiters() {
    let waiters = core::mem::take(&mut *WAITERS.lock());
    thread::wake_waiting(&waiters);
}

/// `wait4` (`pid`, the status out-pointer `status`, `options`) over the
/// table, its options already checked.
pub(crate) fn wait4(pid: i32, status: usize, options: u32) -> i64 {
    loop {
        match find(pid) {
            Found::Zombie(child, wait_status) => {
                if status != 0 && crate::uaccess::write(status, &wait_status).is_err() {
                    return -i64::from(libc::EFAULT);
                }
                reap(child);
                return i64::from(child);
            }
            Found::None => return -i64::from(libc::ECHILD),
            Found::Running if options & WNOHANG != 0 => return 0,
            Found::Running => {
                if let Err(errno) = park() {
                    return -i64::from(errno);
                }
            }
        }
    }
}

/// `waitid` (`P_ALL` as `id` -1, `P_PID` as the pid; the `siginfo_t`
/// out-pointer `info`; `options`) over the table, its options checked.
pub(crate) fn waitid(id: i32, info: usize, options: u32) -> i64 {
    if options & WEXITED == 0 {
        // Stopped and continued children are never: nothing to wait for.
        return match find(id) {
            Found::None => -i64::from(libc::ECHILD),
            _ if options & WNOHANG != 0 => write_info(info, None),
            _ => {
                thread::fatal_unmodeled(
                    "waitid for stopped or continued children only, which never come",
                );
            }
        };
    }
    loop {
        match find(id) {
            Found::Zombie(child, wait_status) => {
                let answer = write_info(info, Some((child, wait_status)));
                if answer == 0 && options & WNOWAIT == 0 {
                    reap(child);
                }
                return answer;
            }
            Found::None => return -i64::from(libc::ECHILD),
            Found::Running if options & WNOHANG != 0 => return write_info(info, None),
            Found::Running => {
                if let Err(errno) = park() {
                    return -i64::from(errno);
                }
            }
        }
    }
}

/// Fill the caller's `siginfo_t` for `found` (a child's pid and wait
/// status), or zero its fields when nothing changed state.
fn write_info(info: usize, found: Option<(i32, i32)>) -> i64 {
    if info == 0 {
        return 0;
    }
    // si_signo, si_errno, si_code, padding, si_pid, si_uid, si_status.
    let mut words = [0i32; 7];
    if let Some((pid, status)) = found {
        let (code, value) = if libc::WIFEXITED(status) {
            (libc::CLD_EXITED, libc::WEXITSTATUS(status))
        } else if libc::WCOREDUMP(status) {
            (libc::CLD_DUMPED, libc::WTERMSIG(status))
        } else {
            (libc::CLD_KILLED, libc::WTERMSIG(status))
        };
        words = [
            libc::SIGCHLD,
            0,
            code,
            0,
            pid,
            crate::identity::credential().uid as i32,
            value,
        ];
    }
    match crate::uaccess::write_slice(info, &words) {
        Ok(()) => 0,
        Err(_) => -i64::from(libc::EFAULT),
    }
}
