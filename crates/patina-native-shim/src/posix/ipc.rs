//! glibc's System V IPC wrappers as doors into the one-process model
//! (`thread::ipc`): each forwards the caller's operands to the same dispatch
//! row the raw syscall reaches, through a thunk (`door_thunks.rs`) whose exit
//! delivers what the call made deliverable, so a wait a signal ends answers
//! as the raw call does (`EINTR`, never restarted). `msgsnd` and `msgrcv` are
//! glibc cancellation points and check for a pending cancel at entry.
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::{c_int, c_long, c_void};

use crate::sud::{Word, forward, forward_word};

#[unsafe(export_name = "patina_door_shmget")]
extern "C" fn shmget(key: libc::key_t, size: usize, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: shmget has no pointer operands.
    unsafe { forward(libc::SYS_shmget, &[key.word(), size.word(), flags.word()]) }
}

/// # Safety
/// `address` follows shmat's placement contract.
#[unsafe(export_name = "patina_door_shmat")]
unsafe extern "C" fn shmat(id: c_int, address: *const c_void, flags: c_int) -> *mut c_void {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the row maps the segment; the address is a placement, never read.
    let attached =
        unsafe { forward_word(libc::SYS_shmat, &[id.word(), address.word(), flags.word()]) };
    attached as usize as *mut c_void
}

/// # Safety
/// `address` follows shmdt's contract.
#[unsafe(export_name = "patina_door_shmdt")]
unsafe extern "C" fn shmdt(address: *const c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the row detaches the view at the address; it never reads it.
    unsafe { forward(libc::SYS_shmdt, &[address.word()]) }
}

/// # Safety
/// `buf` is NULL or valid for the command's `shmid_ds`.
#[unsafe(export_name = "patina_door_shmctl")]
unsafe extern "C" fn shmctl(id: c_int, cmd: c_int, buf: *mut libc::shmid_ds) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the libc caller supplies the command's control structure.
    unsafe { forward(libc::SYS_shmctl, &[id.word(), cmd.word(), buf.word()]) }
}

#[unsafe(export_name = "patina_door_semget")]
extern "C" fn semget(key: libc::key_t, count: c_int, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: semget has no pointer operands.
    unsafe { forward(libc::SYS_semget, &[key.word(), count.word(), flags.word()]) }
}

/// # Safety
/// `ops` is readable for `count` operations.
#[unsafe(export_name = "patina_door_semop")]
unsafe extern "C" fn semop(id: c_int, ops: *mut libc::sembuf, count: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the row copies the operations in through uaccess.
    unsafe { forward(libc::SYS_semop, &[id.word(), ops.word(), count.word()]) }
}

/// # Safety
/// `ops` is readable for `count` operations; `timeout` is NULL or readable.
#[unsafe(export_name = "patina_door_semtimedop")]
unsafe extern "C" fn semtimedop(
    id: c_int,
    ops: *mut libc::sembuf,
    count: usize,
    timeout: *const libc::timespec,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the row copies the operations and the timeout in through uaccess.
    unsafe {
        forward(
            libc::SYS_semtimedop,
            &[id.word(), ops.word(), count.word(), timeout.word()],
        )
    }
}

// The `semctl` commands, as glibc's wrapper reads them (sysdeps/unix/sysv/
// linux/semctl.c, which the 64-bit ABIs share).
const GETPID: c_int = 11;
const GETVAL: c_int = 12;
const GETALL: c_int = 13;
const GETNCNT: c_int = 14;
const GETZCNT: c_int = 15;
const SETVAL: c_int = 16;
const SETALL: c_int = 17;
const SEM_STAT: c_int = 18;
const SEM_INFO: c_int = 19;
const SEM_STAT_ANY: c_int = 20;

/// `semctl(id, num, cmd, ...)`. The thunk hands over the fourth argument
/// register, the `union semun` word (see `door_thunks.rs`); as glibc's
/// wrapper does, it is read only for the commands that take one, and any
/// other command is `EINVAL` without entering the kernel.
///
/// # Safety
/// `arg` is the command's `union semun` when the command takes one.
#[unsafe(export_name = "patina_door_semctl")]
unsafe extern "C" fn semctl(id: c_int, num: c_int, cmd: c_int, arg: usize) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let arg = match cmd {
        SETVAL
        | GETALL
        | SETALL
        | libc::IPC_STAT
        | libc::IPC_SET
        | SEM_STAT
        | SEM_STAT_ANY
        | libc::IPC_INFO
        | SEM_INFO => arg,
        libc::IPC_RMID | GETNCNT | GETPID | GETVAL | GETZCNT => 0,
        _ => return super::error(libc::EINVAL),
    };
    // SAFETY: the row reads the argument as the command means it, through uaccess.
    unsafe {
        forward(
            libc::SYS_semctl,
            &[id.word(), num.word(), cmd.word(), arg.word()],
        )
    }
}

#[unsafe(export_name = "patina_door_msgget")]
extern "C" fn msgget(key: libc::key_t, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: msgget has no pointer operands.
    unsafe { forward(libc::SYS_msgget, &[key.word(), flags.word()]) }
}

/// # Safety
/// `message` points to a `long` type followed by `size` bytes.
#[unsafe(export_name = "patina_door_msgsnd")]
unsafe extern "C" fn msgsnd(id: c_int, message: *const c_void, size: usize, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"msgsnd");
    // SAFETY: the row copies the message in.
    unsafe {
        forward(
            libc::SYS_msgsnd,
            &[id.word(), message.word(), size.word(), flags.word()],
        )
    }
}

/// # Safety
/// `message` is writable for a `long` type followed by `size` bytes.
#[unsafe(export_name = "patina_door_msgrcv")]
unsafe extern "C" fn msgrcv(
    id: c_int,
    message: *mut c_void,
    size: usize,
    kind: c_long,
    flags: c_int,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel(c"msgrcv");
    // SAFETY: the row copies the received message out.
    (unsafe {
        forward_word(
            libc::SYS_msgrcv,
            &[
                id.word(),
                message.word(),
                size.word(),
                kind.word(),
                flags.word(),
            ],
        )
    }) as isize
}

/// # Safety
/// `buf` is NULL or valid for the command's `msqid_ds`.
#[unsafe(export_name = "patina_door_msgctl")]
unsafe extern "C" fn msgctl(id: c_int, cmd: c_int, buf: *mut libc::msqid_ds) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: the libc caller supplies the command's control structure.
    unsafe { forward(libc::SYS_msgctl, &[id.word(), cmd.word(), buf.word()]) }
}
