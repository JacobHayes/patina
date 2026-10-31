//! The registrations a thread makes with the kernel for user-space ABIs,
//! modeled per task: the robust-futex list head (`set_robust_list`,
//! `get_robust_list`, kernel/futex/syscalls.c; walked at thread exit,
//! kernel/futex/core.c `exit_robust_list`) and the restartable-sequence area
//! (`rseq`, kernel/rseq.c).
//!
//! glibc registers both from its own text at every thread's start: ld.so for
//! the main thread, before the shim runs, and `start_thread` for each managed
//! thread, before the shim's trampoline. Both reach the host kernel first.
//! [`adopt`] takes them over as the task's virtual registrations when the task
//! starts, before any guest code runs on it (and, for a managed thread,
//! before its creator's `pthread_create` returns):
//!
//! * the robust list head is read back from the host, so `get_robust_list`
//!   reports glibc's head as the kernel would. From then on the guest's calls
//!   change only the virtual head, and the virtual kernel walks it when the
//!   task exits, marking the futexes the task still owns `FUTEX_OWNER_DIED`
//!   and waking a waiter by the word's shared key. glibc's head needs no host
//!   registration, its list staying empty (the shim interposes glibc's robust
//!   mutexes, so glibc never links one into it): the host's is the thread's
//!   exit beacon (below);
//! * glibc's rseq area is unregistered from the host, which would otherwise
//!   keep writing host CPU ids into it (a determinism leak through
//!   `__rseq_offset`), and registered virtually instead. The area reads
//!   `cpu_id` and `cpu_id_start` as the CPU the task runs on (what `getcpu`
//!   answers, `thread::sched`), `node_id` 0 (the one node) and `mm_cid` 0,
//!   written at registration and again whenever a `sched_setaffinity` moves
//!   the task to another CPU, as the kernel's notify-resume writes it after a
//!   migration ([`migrated`]); nothing else moves a task.
//!   Tasks run one at a time and are switched only at a boundary call, which
//!   a restartable sequence never contains, so no sequence is ever preempted,
//!   migrated or interrupted by a handler, and no abort is ever due.
//!
//! The host list head is the shim's own instead: an [`ExitBeacon`] whose one
//! entry is a word naming the host thread, which the host kernel's exit walk
//! marks `FUTEX_OWNER_DIED` once the thread has run its last instruction.
//! What glibc runs on a thread after its task completes (its `pthread_key`
//! destructors, the allocator's thread shutdown, the stack's release) is host
//! code on no task, sharing glibc's locks and heap with the tasks; a task
//! that takes the baton after a completion waits for the beacon before it
//! runs (`super::exits`), so that teardown never runs beside one.

use super::*;
use linux_raw_sys::errno;
use linux_raw_sys::general::{
    __NR_futex, __NR_get_robust_list, __NR_gettid, __NR_rseq, __NR_set_robust_list,
};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};

/// `sizeof(struct robust_list_head)`: `next`, `futex_offset`, `list_op_pending`.
const HEAD_BYTES: usize = 24;
/// `ROBUST_LIST_LIMIT`: the most entries an exit walks.
const WALK_LIMIT: usize = 2048;
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

/// `ORIG_RSEQ_SIZE`: the original `struct rseq`, the least a registration
/// may name, and the alignment of any other size.
const RSEQ_ORIG_SIZE: u32 = 32;
/// `RSEQ_FLAG_UNREGISTER`.
const RSEQ_FLAG_UNREGISTER: i32 = 1;
/// `RSEQ_SIG`, the signature glibc registers with.
#[cfg(target_arch = "x86_64")]
const RSEQ_SIG: u32 = 0x5305_3053;
#[cfg(target_arch = "aarch64")]
const RSEQ_SIG: u32 = 0xd428_bc00;
/// `RSEQ_CPU_ID_UNINITIALIZED`, the `cpu_id` an unregistration leaves.
const RSEQ_CPU_ID_UNINITIALIZED: u32 = u32::MAX;
/// `RSEQ_CPU_ID_REGISTRATION_FAILED`, the `cpu_id` glibc leaves in a thread's
/// area when the kernel refused its registration.
const RSEQ_CPU_ID_REGISTRATION_FAILED: u32 = -2i32 as u32;
/// A registered rseq area (`current->rseq`, `rseq_len`, `rseq_sig`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rseq {
    area: usize,
    len: u32,
    sig: u32,
}

/// The fields of `struct rseq` the kernel keeps current, at their offsets:
/// `cpu_id_start`, `cpu_id`, then (past `rseq_cs` and `flags`) `node_id` and
/// `mm_cid`. A registered task's area names its CPU in both CPU fields.
fn write_cpu(area: usize, cpu: u32) -> Result<(), c_int> {
    write_fields(area, cpu, cpu)
}

/// Write the area's CPU fields: `cpu_id_start`, `cpu_id`, and node and mm
/// cid 0.
fn write_fields(area: usize, cpu_id_start: u32, cpu_id: u32) -> Result<(), c_int> {
    crate::uaccess::write(area, &[cpu_id_start, cpu_id])?;
    crate::uaccess::write(area + 20, &[0u32, 0])
}

/// One task's registrations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Registrations {
    /// `current->robust_list`: the head's address, 0 for none.
    robust: usize,
    /// The rseq registration, if any.
    rseq: Option<Rseq>,
}

/// Every task's registrations, by task.
#[derive(Default)]
pub(super) struct RegistrationRuntime {
    tasks: BTreeMap<TaskId, Registrations>,
}

/// A host thread's exit, as the host kernel reports it: a `struct
/// robust_list_head` registered with the host for the thread, whose one entry
/// is `word`. The word holds the host thread id, so the kernel's exit walk
/// (`handle_futex_death`) marks it `FUTEX_OWNER_DIED` and wakes its waiter
/// once the thread has left user space for good, after everything glibc
/// runs on it.
#[repr(C)]
struct ExitBeacon {
    /// The head's `list.next`: `entry`.
    next: usize,
    /// From `entry` to `word`.
    futex_offset: isize,
    list_op_pending: usize,
    /// The one entry, whose `next` is the head.
    entry: usize,
    word: AtomicU32,
}

const FUTEX_WAIT: u64 = 0;

thread_local! {
    /// This thread's beacon, until its task completes.
    static BEACON: Cell<usize> = const { Cell::new(0) };
}

/// Register a beacon as the calling thread's host robust list.
fn arm_beacon() {
    let tid = host(__NR_gettid, [0; 6]) as u32;
    let beacon = Box::into_raw(Box::new(ExitBeacon {
        next: 0,
        futex_offset: (std::mem::offset_of!(ExitBeacon, word)
            - std::mem::offset_of!(ExitBeacon, entry)) as isize,
        list_op_pending: 0,
        entry: 0,
        word: AtomicU32::new(tid & FUTEX_TID_MASK),
    }));
    // SAFETY: the beacon just leaked above, owned by this thread until its
    // task completes.
    unsafe {
        (*beacon).next = &raw const (*beacon).entry as usize;
        (*beacon).entry = beacon as usize;
    }
    if host(
        __NR_set_robust_list,
        [beacon as u64, HEAD_BYTES as u64, 0, 0, 0, 0],
    ) != 0
    {
        fatal("registering a thread's exit beacon with the host failed (set_robust_list)");
    }
    BEACON.with(|cell| cell.set(beacon as usize));
}

/// The calling thread's task completed: hand its beacon to the task that
/// takes the baton next. A thread whose host registration is no longer the
/// beacon (a fork child's, which glibc re-registers) has none to wait for.
pub(super) fn exiting() {
    let beacon = BEACON.with(|cell| cell.replace(0));
    if beacon == 0 {
        return;
    }
    let mut head = 0usize;
    let mut len = 0usize;
    let registered = host(
        __NR_get_robust_list,
        [0, &raw mut head as u64, &raw mut len as u64, 0, 0, 0],
    ) == 0
        && head == beacon;
    if registered {
        super::exits::publish(beacon);
    } else {
        // SAFETY: no host registration names it any more.
        drop(unsafe { Box::from_raw(beacon as *mut ExitBeacon) });
    }
}

/// Wait until the thread `beacon` (published by [`exiting`]) has left user
/// space, then free the beacon.
pub(super) fn await_exit(beacon: usize) {
    let beacon = beacon as *mut ExitBeacon;
    // SAFETY: a published beacon is alive until its waiter frees it here.
    let word = unsafe { &(*beacon).word };
    // A wait the exit beat answers EAGAIN through glibc's errno, whichever
    // way the host's timing went: the guest's errno is put back.
    let errno = crate::abi::host_errno();
    loop {
        let value = word.load(Ordering::Acquire);
        if value & FUTEX_OWNER_DIED != 0 {
            break;
        }
        if value & FUTEX_WAITERS == 0
            && word
                .compare_exchange(
                    value,
                    value | FUTEX_WAITERS,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
        {
            continue;
        }
        // The kernel's wake is by the word's shared key: no private flag.
        host(
            __NR_futex,
            [
                word.as_ptr() as u64,
                FUTEX_WAIT,
                u64::from(value | FUTEX_WAITERS),
                0,
                0,
                0,
            ],
        );
    }
    crate::abi::restore_host_errno(errno);
    // SAFETY: the kernel's walk has marked it, and its wake by the word's
    // key reads nothing of it; nothing else names it.
    drop(unsafe { Box::from_raw(beacon) });
}

/// The task the calling thread's registrations belong to: the main thread's
/// before the startup constructor claims its task id too.
fn owner() -> TaskId {
    match current_task() {
        UNMANAGED_TASK => MAIN_TASK,
        task => task,
    }
}

fn host(nr: u32, args: [u64; 6]) -> i64 {
    // SAFETY: glibc's real syscall(2), through the host alias table.
    unsafe {
        crate::sud_host_syscall(
            i64::from(nr),
            args[0] as i64,
            args[1] as i64,
            args[2] as i64,
            args[3] as i64,
            args[4] as i64,
            args[5] as i64,
        )
    }
}

/// glibc's `__rseq_offset` and `__rseq_size` (ld.so's): where each thread's
/// area sits from the thread pointer, and 0 if glibc did not register it.
fn glibc_rseq() -> (isize, u32) {
    static LAYOUT: OnceLock<(isize, u32)> = OnceLock::new();
    *LAYOUT.get_or_init(|| {
        let offset = crate::hostapi::symbol(c"__rseq_offset").cast::<isize>();
        let size = crate::hostapi::symbol(c"__rseq_size").cast::<u32>();
        if offset.is_null() || size.is_null() {
            return (0, 0);
        }
        // SAFETY: ld.so's exported data words, set before any constructor.
        unsafe { (offset.read(), size.read()) }
    })
}

/// The calling thread's thread pointer.
fn thread_pointer() -> usize {
    let tp: usize;
    // SAFETY: reads the thread pointer, as every TLS access does.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        std::arch::asm!("mov {}, fs:0", out(reg) tp, options(nostack, readonly, preserves_flags));
        #[cfg(target_arch = "aarch64")]
        std::arch::asm!("mrs {}, tpidr_el0", out(reg) tp, options(nostack, nomem, preserves_flags));
    }
    tp
}

/// Take glibc's rseq registration of the calling thread off the host: the
/// area it registered, if it has one. glibc registers `max(__rseq_size, 32)`
/// bytes. A refused unregistration leaves nothing to take over only when
/// glibc's own registration failed; any other refusal (another length than
/// this glibc registers with, say) would leave the host writing host CPU ids
/// into the area, so it stops the run by name.
fn adopt_rseq(cpu: u32) -> Option<Rseq> {
    let (offset, size) = glibc_rseq();
    if size == 0 {
        return None;
    }
    let rseq = Rseq {
        area: thread_pointer().wrapping_add_signed(offset),
        len: size.max(RSEQ_ORIG_SIZE),
        sig: RSEQ_SIG,
    };
    let unregistered = host(
        __NR_rseq,
        [
            rseq.area as u64,
            u64::from(rseq.len),
            RSEQ_FLAG_UNREGISTER as u64,
            u64::from(rseq.sig),
            0,
            0,
        ],
    );
    if unregistered != 0 {
        let cpu_id = crate::uaccess::read::<u32>(rseq.area + 4).ok();
        if registration_failed(cpu_id) {
            return None;
        }
        fatal(
            "the host refused to unregister glibc's rseq area, which glibc registered: the \
             host would keep writing host CPU ids into it (rseq takeover)",
        );
    }
    if write_cpu(rseq.area, cpu).is_err() {
        fatal("glibc's rseq area is not writable");
    }
    Some(rseq)
}

/// Whether a thread's rseq area, whose host unregistration was refused,
/// reads `cpu_id` (`cpu_id`, if readable) as glibc leaves it when its own
/// registration failed: then no host registration exists.
fn registration_failed(cpu_id: Option<u32>) -> bool {
    cpu_id == Some(RSEQ_CPU_ID_REGISTRATION_FAILED)
}

/// Take over the calling thread's host registrations as `task`'s: called on
/// the thread itself, once, before the guest runs on it (the main thread
/// from `__libc_start_main`, a managed thread from its trampoline).
pub(super) fn adopt(task: TaskId, cpu: u32) {
    let mut head = 0usize;
    let mut len = 0usize;
    // glibc registered the head from its own text; read it back.
    if host(
        __NR_get_robust_list,
        [0, &raw mut head as u64, &raw mut len as u64, 0, 0, 0],
    ) != 0
    {
        fatal("host robust-list query failed (get_robust_list)");
    }
    let rseq = adopt_rseq(cpu);
    arm_beacon();
    lock_state()
        .registrations
        .tasks
        .insert(task, Registrations { robust: head, rseq });
}

/// `rseq(area, len, flags, sig)` (kernel/rseq.c `sys_rseq`), for the calling
/// task. Unregistering names the registered area, length and signature
/// (`EINVAL`, `EINVAL`, `EPERM`) and leaves the area's CPU fields as the
/// kernel does. Registering while registered is `EINVAL` for another area or
/// length, `EPERM` for another signature, else `EBUSY`; a new registration
/// needs at least the original size, 32-byte alignment and a user range
/// (`EINVAL`, `EINVAL`, `EFAULT`), and its CPU fields are written before the
/// call returns (the kernel's notify-resume).
pub(crate) fn rseq(area: usize, len: u32, flags: i32, sig: u32) -> i64 {
    let einval = -i64::from(errno::EINVAL);
    let me = owner();
    let registered = lock_state()
        .registrations
        .tasks
        .get(&me)
        .and_then(|registrations| registrations.rseq);
    if flags & RSEQ_FLAG_UNREGISTER != 0 {
        if flags & !RSEQ_FLAG_UNREGISTER != 0 {
            return einval;
        }
        let Some(current) = registered.filter(|current| current.area == area) else {
            return einval;
        };
        if current.len != len {
            return einval;
        }
        if current.sig != sig {
            return -i64::from(errno::EPERM);
        }
        // `rseq_reset_rseq_cpu_node_id`: `cpu_id_start` 0, `cpu_id`
        // uninitialized.
        if write_fields(area, 0, RSEQ_CPU_ID_UNINITIALIZED).is_err() {
            return -i64::from(errno::EFAULT);
        }
        set_rseq(me, None);
        return 0;
    }
    if flags != 0 {
        return einval;
    }
    if let Some(current) = registered {
        if current.area != area || current.len != len {
            return einval;
        }
        if current.sig != sig {
            return -i64::from(errno::EPERM);
        }
        return -i64::from(errno::EBUSY);
    }
    if len < RSEQ_ORIG_SIZE || !area.is_multiple_of(RSEQ_ORIG_SIZE as usize) {
        return einval;
    }
    if !crate::uaccess::access_ok(area, len as usize) {
        return -i64::from(errno::EFAULT);
    }
    if write_cpu(area, super::sched::current_cpu()).is_err() {
        // The kernel's notify-resume would force SIGSEGV on this thread.
        crate::trap_fatal(
            "rseq registered an area the CPU fields cannot be written to: the kernel's \
             forced SIGSEGV is not modeled",
        );
    }
    set_rseq(me, Some(Rseq { area, len, sig }));
    0
}

/// A `sched_setaffinity` moved `task` to `cpu`: its rseq area, if it has one,
/// names the CPU from now on, as the kernel's notify-resume writes it on the
/// task's return to user space after the migration.
pub(super) fn migrated(task: TaskId, cpu: u32) {
    let area = lock_state()
        .registrations
        .tasks
        .get(&task)
        .and_then(|registrations| registrations.rseq)
        .map(|rseq| rseq.area);
    if let Some(area) = area
        && write_cpu(area, cpu).is_err()
    {
        // The kernel's notify-resume would force SIGSEGV on the task.
        crate::trap_fatal(
            "a migrated task's rseq area cannot be written: the kernel's forced SIGSEGV is not \
             modeled",
        );
    }
}

fn set_rseq(task: TaskId, rseq: Option<Rseq>) {
    lock_state()
        .registrations
        .tasks
        .entry(task)
        .or_default()
        .rseq = rseq;
}

#[unsafe(no_mangle)]
/// The main thread's adoption, from the C `__libc_start_main` wrapper of a
/// managed run, before guest constructors.
pub extern "C" fn patina_thread_registrations_adopt_main() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // The first task's CPU, 0, whatever the count: nothing has set the main
    // thread's affinity before its constructors run.
    adopt(MAIN_TASK, 0);
}

/// `set_robust_list(head, len)`: exactly a head's length, else `EINVAL`; the
/// head is not read until the task exits.
pub(crate) fn set_robust_list(head: usize, len: usize) -> i64 {
    if len != HEAD_BYTES {
        return -i64::from(errno::EINVAL);
    }
    lock_state()
        .registrations
        .tasks
        .entry(owner())
        .or_default()
        .robust = head;
    0
}

/// `get_robust_list(pid, head_ptr, len_ptr)` for the guest's own threads:
/// the head of the caller (pid 0) or of any live thread, by its thread id;
/// `ESRCH` for any other. Init is the privileged row's to answer
/// (`crate::sud::privileged`). The length is written before the head.
pub(crate) fn get_robust_list(pid: i32, head_ptr: usize, len_ptr: usize) -> i64 {
    let head = if pid == 0 {
        head_of(owner())
    } else if live_tid(pid) {
        head_of(task_of(pid).unwrap_or(MAIN_TASK))
    } else {
        return -i64::from(errno::ESRCH);
    };
    if crate::uaccess::write(len_ptr, &HEAD_BYTES).is_err()
        || crate::uaccess::write(head_ptr, &head).is_err()
    {
        return -i64::from(errno::EFAULT);
    }
    0
}

fn head_of(task: TaskId) -> usize {
    lock_state()
        .registrations
        .tasks
        .get(&task)
        .map_or(0, |registrations| registrations.robust)
}

/// The exiting task's robust list (`exit_robust_list`), walked before its
/// clear-child-tid word is cleared, as the kernel's `exit_mm_release` does;
/// then its registrations go. Outside the runtime lock: waking a waiter
/// takes it.
pub(super) fn exit(task: TaskId) {
    let removed = lock_state().registrations.tasks.remove(&task);
    let Some(Registrations { robust: head, .. }) = removed else {
        return;
    };
    if head != 0 {
        walk(head, tid_of(task) as u32);
    }
}

/// A robust list entry's pointer: the address and the PI bit.
fn entry(at: usize) -> Option<(usize, bool)> {
    let raw = crate::uaccess::read::<usize>(at).ok()?;
    Some((raw & !1, raw & 1 != 0))
}

/// `exit_robust_list`: every entry up to [`WALK_LIMIT`], then the pending one.
fn walk(head: usize, tid: u32) {
    let Some((mut at, mut pi)) = entry(head) else {
        return;
    };
    let Ok(offset) = crate::uaccess::read::<usize>(head + 8) else {
        return;
    };
    let Some((pending, pending_pi)) = entry(head + 16) else {
        return;
    };
    let mut limit = WALK_LIMIT;
    while at != head {
        let next = entry(at);
        if at != pending && owner_died(at.wrapping_add(offset), tid, pi, false).is_err() {
            return;
        }
        let Some((following, following_pi)) = next else {
            return;
        };
        (at, pi) = (following, following_pi);
        limit -= 1;
        if limit == 0 {
            break;
        }
    }
    if pending != 0 {
        let _ = owner_died(pending.wrapping_add(offset), tid, pending_pi, true);
    }
}

/// `handle_futex_death`: a word the exiting thread still owns keeps its
/// waiters bit and gains `FUTEX_OWNER_DIED`, and a waiter is woken (a PI
/// word's waiter is the PI state's to wake; there is none). A pending
/// operation's zero word wakes a waiter too. Both wakes go by the word's
/// shared key, which a `FUTEX_WAIT_PRIVATE` waiter's does not match. Only the
/// baton holder runs, so
/// the read-modify-write needs no atomic compare-and-exchange.
fn owner_died(word: usize, tid: u32, pi: bool, pending: bool) -> Result<(), ()> {
    if !word.is_multiple_of(4) {
        return Err(());
    }
    let value = crate::uaccess::read::<u32>(word).map_err(|_| ())?;
    if pending && !pi && value == 0 {
        futex_wake_shared(word, 1);
        return Ok(());
    }
    if value & FUTEX_TID_MASK != tid {
        return Ok(());
    }
    let died = (value & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
    crate::uaccess::write(word, &died).map_err(|_| ())?;
    if !pi && value & FUTEX_WAITERS != 0 {
        futex_wake_shared(word, 1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refused unregistration is benign only for an area glibc could not
    /// register; a live-looking CPU id, an unregistered one or an unreadable
    /// area is a host registration the takeover failed to remove.
    #[test]
    fn only_a_failed_glibc_registration_leaves_nothing_to_take_over() {
        assert!(registration_failed(Some(RSEQ_CPU_ID_REGISTRATION_FAILED)));
        for cpu_id in [Some(0), Some(7), Some(RSEQ_CPU_ID_UNINITIALIZED), None] {
            assert!(!registration_failed(cpu_id), "{cpu_id:?}");
        }
    }
}
