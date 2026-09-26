//! The registrations a thread makes with the kernel for user-space ABIs,
//! modeled per task: the robust-futex list head (`set_robust_list`,
//! `get_robust_list`, kernel/futex/syscalls.c; walked at thread exit,
//! kernel/futex/core.c `exit_robust_list`).
//!
//! glibc registers the head from its own text at every thread's start: ld.so
//! for the main thread, before the shim runs, and `start_thread` for each
//! managed thread, before the shim's trampoline. Both reach the host kernel
//! first. [`adopt`] reads the host's registration back as the task's virtual
//! one when the task starts (for a managed thread, before its creator's
//! `pthread_create` returns), so `get_robust_list` reports glibc's head as the
//! kernel would. From then on the guest's calls change only the virtual
//! registration, and the virtual kernel walks it when the task exits, marking
//! the futexes the task still owns `FUTEX_OWNER_DIED` and waking a waiter by
//! the word's shared key. The host keeps glibc's head, whose list stays empty: the
//! shim interposes glibc's robust mutexes, so glibc never links one into it.

use super::*;
use linux_raw_sys::errno;
use linux_raw_sys::general::__NR_get_robust_list;

/// `sizeof(struct robust_list_head)`: `next`, `futex_offset`, `list_op_pending`.
const HEAD_BYTES: usize = 24;
/// `ROBUST_LIST_LIMIT`: the most entries an exit walks.
const WALK_LIMIT: usize = 2048;
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

/// One task's registrations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Registrations {
    /// `current->robust_list`: the head's address, 0 for none.
    robust: usize,
}

/// Every task's registrations, by task.
#[derive(Default)]
pub(super) struct RegistrationRuntime {
    tasks: BTreeMap<TaskId, Registrations>,
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

/// Take over the calling thread's host registrations as `task`'s: called on
/// the thread itself, once, before the guest runs on it (the main thread
/// from `__libc_start_main`, a managed thread from its trampoline).
pub(super) fn adopt(task: TaskId) {
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
    lock_state()
        .registrations
        .tasks
        .insert(task, Registrations { robust: head });
}

/// The main thread's adoption, from the C `__libc_start_main` wrapper of a
/// managed run, before guest constructors.
#[unsafe(no_mangle)]
pub extern "C" fn patina_thread_registrations_adopt_main() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    adopt(MAIN_TASK);
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
    let Some(Registrations { robust: head }) = removed else {
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
    if word % 4 != 0 {
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
