//! Syscall-user-dispatch (SUD) dispatch table — Linux only.
//!
//! The C layer (`patina_posix.c`) arms SUD (`prctl(PR_SET_SYSCALL_USER_DISPATCH,
//! …)` with allowed region = glibc's executable segment, NULL selector) and
//! installs a `SIGSYS` handler. When guest code executes a raw `syscall`/`svc`
//! instruction outside glibc's text, the kernel rolls the instruction back and
//! delivers a synchronous, thread-directed `SIGSYS` at the exact faulting IP.
//! The C handler decodes the syscall number and its six argument registers from
//! the `ucontext`, then calls [`patina_sud_dispatch`], which routes the call
//! into the *same* `patina_*` entry points the C interposers use and returns the
//! value the handler writes back into the syscall's return register (raw ABI:
//! a negative value is `-errno`, there is no libc `errno` step).
//!
//! Soundness: the trap is synchronous — it *is* the guest's own effect boundary,
//! semantically identical to the guest having called an interposed `read()` — so
//! re-entering the deterministic runtime (taking `lock_state`, parking on the
//! baton) is exactly what every C interposer already does. See `SUD-DESIGN.md`
//! §4.2. The one invariant that must hold is that shim/runtime code never itself
//! traps while servicing a dispatch; [`with_dispatch_guard`] is the standalone
//! RED detector for a violation of it.
//!
//! This module is `x86_64`-first (the only arch with kernel SUD today); the
//! `aarch64` number table compiles so the dispatcher lights up unchanged when
//! generic-entry arm64 kernels ship, but it is dead at runtime there (the kernel
//! probe fails and the run is refused before exec — see the audit gate).

use std::cell::Cell;
use std::ffi::{c_char, c_int, c_long, c_void};

// The `patina_*` runtime entry points the C interposers call. Declaring them as
// externs (rather than reaching for module paths) routes SUD through the exact
// same symbols — there is no second implementation of any effect. Every one is a
// `#[no_mangle] extern "C"` definition elsewhere in this crate.
unsafe extern "C" {
    fn patina_errno() -> c_int;
    fn patina_clock_now(clock: u32, nanos: *mut u64) -> c_int;
    fn patina_sleep_until(clock: u32, deadline_nanos: u64) -> c_int;
    fn patina_open(path: *const c_char, flags: u32) -> c_int;
    fn patina_read(fd: c_int, destination: *mut c_void, length: usize) -> isize;
    fn patina_write(fd: c_int, source: *const c_void, length: usize) -> isize;
    fn patina_close(fd: c_int) -> c_int;
    fn patina_seek(fd: c_int, offset: i64, whence: u32) -> i64;
    fn patina_entropy(destination: *mut c_void, length: usize) -> c_int;
    fn patina_sched_yield() -> c_int;
    fn patina_thread_id() -> c_int;
    fn patina_exit(status: c_int) -> !;
    fn patina_futex_wait(addr: usize, expected: u32) -> c_int;
    fn patina_futex_wait_timed(
        addr: usize,
        expected: u32,
        clock: u32,
        absolute: c_int,
        timeout_nanos: u64,
    ) -> c_int;
    fn patina_futex_wake(addr: usize, count: c_int) -> c_int;
}

// Linux errno values used to shape raw-syscall returns (`-errno`). Fixed across
// the Linux ABIs Patina targets.
const EINVAL: i64 = 22;
const ENOSYS: i64 = 38;
const EIO: i64 = 5;

// Patina clock ids (see `patina_native.h`).
const PATINA_CLOCK_REALTIME: u32 = 0;
const PATINA_CLOCK_MONOTONIC: u32 = 1;

// Patina open flags (see `patina_native.h`).
const PATINA_O_READ: u32 = 1 << 0;
const PATINA_O_WRITE: u32 = 1 << 1;
const PATINA_O_CREATE: u32 = 1 << 2;
const PATINA_O_TRUNCATE: u32 = 1 << 3;
const PATINA_O_APPEND: u32 = 1 << 4;
const PATINA_O_EXCLUSIVE: u32 = 1 << 5;

// Kernel `open(2)` flag bits (octal), identical on x86_64 and aarch64 Linux.
const O_ACCMODE: u64 = 0o3;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;

const AT_FDCWD: i64 = -100;

// `mmap(2)` / memory-management constants.
const MAP_ANONYMOUS: u64 = 0x20;

// `clock_nanosleep(2)` absolute-deadline flag.
const TIMER_ABSTIME: u64 = 1;

// `futex(2)` op decode (mirrors the libc `syscall()` interposer in
// patina_posix.c so the raw and wrapped paths route identically).
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_PRIVATE_FLAG: u64 = 128;
const FUTEX_CLOCK_REALTIME: u64 = 256;

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Kernel `struct timespec` on 64-bit Linux (`time_t` and `long` are both 8
/// bytes). Read from and written to guest memory during dispatch.
#[repr(C)]
#[derive(Clone, Copy)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

/// Kernel `struct timeval` on 64-bit Linux.
#[repr(C)]
#[derive(Clone, Copy)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

thread_local! {
    /// Set while this thread is inside [`patina_sud_dispatch`]. A nested SIGSYS
    /// (i.e. a trap taken *while servicing a trap*) can only mean shim/runtime
    /// code executed a raw syscall — the one thing the audit instruction scan
    /// proves it never does. If the invariant were ever violated this flag turns
    /// the recursion into a loud, named abort instead of an unbounded SIGSYS
    /// storm. This is the standalone RED detector for the §4.2 soundness
    /// invariant ("shim never traps").
    static IN_DISPATCH: Cell<bool> = const { Cell::new(false) };
}

/// Run `body` with the reentry guard held. A re-entrant dispatch aborts loudly.
fn with_dispatch_guard<F: FnOnce() -> i64>(nr: i64, body: F) -> i64 {
    if IN_DISPATCH.with(Cell::get) {
        crate::sud_fatal(&format!(
            "SUD re-entered dispatch while servicing syscall {nr}: shim/runtime code executed a raw \
             syscall inside the SIGSYS handler (the instruction scan proves this cannot happen — a \
             reentry means the containment invariant is broken)"
        ));
    }
    IN_DISPATCH.with(|cell| cell.set(true));
    let result = body();
    IN_DISPATCH.with(|cell| cell.set(false));
    result
}

/// Shape a raw-syscall return from a `patina_*` `int` result: on error the raw
/// caller reads `-errno` from the return register (there is no libc `errno`
/// step), on success the value itself.
fn ret_i32(result: c_int) -> i64 {
    if result < 0 {
        // SAFETY: `patina_errno` is a plain thread-local read.
        -(unsafe { patina_errno() } as i64)
    } else {
        result as i64
    }
}

/// As [`ret_i32`] for an `intptr_t`-returning entry point (`read`/`write`).
fn ret_isize(result: isize) -> i64 {
    if result < 0 {
        // SAFETY: as above.
        -(unsafe { patina_errno() } as i64)
    } else {
        result as i64
    }
}

/// The syscall numbers slice 1 routes, selected per target arch at compile time.
/// x86_64 is the shipping arch; the aarch64 set compiles so the dispatcher is
/// arch-complete for when generic-entry arm64 kernels ship, and is inert at
/// runtime there (no kernel SUD ⇒ the run is refused before it can trap).
#[cfg(target_arch = "x86_64")]
mod nr {
    pub const READ: i64 = 0;
    pub const WRITE: i64 = 1;
    pub const CLOSE: i64 = 3;
    pub const LSEEK: i64 = 8;
    pub const MMAP: i64 = 9;
    pub const MPROTECT: i64 = 10;
    pub const MUNMAP: i64 = 11;
    pub const BRK: i64 = 12;
    pub const RT_SIGACTION: i64 = 13;
    pub const RT_SIGPROCMASK: i64 = 14;
    pub const MADVISE: i64 = 28;
    pub const NANOSLEEP: i64 = 35;
    pub const SCHED_YIELD: i64 = 24;
    pub const MREMAP: i64 = 25;
    pub const EXIT: i64 = 60;
    pub const GETTIMEOFDAY: i64 = 96;
    pub const SIGALTSTACK: i64 = 131;
    pub const GETTID: i64 = 186;
    pub const FUTEX: i64 = 202;
    pub const SET_ROBUST_LIST: i64 = 273;
    pub const CLOCK_GETTIME: i64 = 228;
    pub const CLOCK_GETRES: i64 = 229;
    pub const CLOCK_NANOSLEEP: i64 = 230;
    pub const EXIT_GROUP: i64 = 231;
    pub const OPENAT: i64 = 257;
    pub const GETRANDOM: i64 = 318;
    pub const MEMBARRIER: i64 = 324;
    pub const RSEQ: i64 = 334;
}

#[cfg(target_arch = "aarch64")]
mod nr {
    pub const READ: i64 = 63;
    pub const WRITE: i64 = 64;
    pub const CLOSE: i64 = 57;
    pub const LSEEK: i64 = 62;
    pub const MMAP: i64 = 222;
    pub const MPROTECT: i64 = 226;
    pub const MUNMAP: i64 = 215;
    pub const BRK: i64 = 214;
    pub const RT_SIGACTION: i64 = 134;
    pub const RT_SIGPROCMASK: i64 = 135;
    pub const MADVISE: i64 = 233;
    pub const NANOSLEEP: i64 = 101;
    pub const SCHED_YIELD: i64 = 124;
    pub const MREMAP: i64 = 216;
    pub const EXIT: i64 = 93;
    pub const GETTIMEOFDAY: i64 = 169;
    pub const SIGALTSTACK: i64 = 132;
    pub const GETTID: i64 = 178;
    pub const FUTEX: i64 = 98;
    pub const SET_ROBUST_LIST: i64 = 99;
    pub const CLOCK_GETTIME: i64 = 113;
    pub const CLOCK_GETRES: i64 = 114;
    pub const CLOCK_NANOSLEEP: i64 = 115;
    pub const EXIT_GROUP: i64 = 94;
    pub const OPENAT: i64 = 56;
    pub const GETRANDOM: i64 = 278;
    pub const MEMBARRIER: i64 = 283;
    pub const RSEQ: i64 = 293;
}

/// The SIGSYS dispatch entry point. The C handler passes the decoded syscall
/// number, its six argument registers, and the faulting instruction address
/// (already validated by the C handler to lie within the main executable's
/// text). The returned value is written verbatim into the syscall's return
/// register — raw ABI, so a negative value is `-errno`.
///
/// The exported name doubles as the audit's SUD marker: a binary whose symbol
/// table *defines* `patina_sud_dispatch` carries a dispatch-capable shim, which
/// is condition (a) of the `direct-syscall` audit downgrade (see
/// `patina-target`). It is `#[used]`/`#[no_mangle]` and referenced by the C
/// handler, so it is never dead-stripped.
///
/// # Safety
/// Called only from the C `SIGSYS` handler on the faulting managed thread, with
/// argument registers that are the guest's own — pointers are valid guest
/// addresses for the lifetime of the (synchronous) dispatch.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_sud_dispatch(
    nr: c_long,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    call_addr: usize,
) -> c_long {
    let _ = call_addr;
    // `c_long` is `i64` on the LP64 Linux targets this module compiles for, so it
    // matches the `i64` syscall-number table and dispatch signature directly.
    //
    // Thread-provenance invariant (SUD-DESIGN.md §4.2 invariant 1, restated): the
    // trapping thread is a managed task OR the pre-activation main thread —
    // identical thread-semantics to the interposer entries. The main thread gets
    // its managed TaskId lazily (`ensure_active`, on first thread-subsystem use),
    // so a raw syscall before any spawn runs with no CURRENT_TASK, exactly like an
    // interposed call would — the `patina_*` entries handle that today (the
    // UNMANAGED_TASK root fallback), and dispatch must not be stricter than the
    // boundary it mirrors (a hard managed-task assert here aborted every guest
    // whose first raw syscall preceded its first spawn). No dispatch-side check is
    // needed to hold the invariant: arming strictly follows `set_current_task` in
    // the trampoline, so an armed non-main thread always has a task; a foreign
    // host thread never executes the guest's inline syscall instructions (the C
    // handler already proved `call_addr` is in main-executable text); and shim/std
    // text contains zero raw syscalls (audit-proven), backstopped by the reentry
    // guard below.
    let args = [a0, a1, a2, a3, a4, a5];
    with_dispatch_guard(nr, || dispatch(nr, args))
}

fn dispatch(nr: i64, args: [u64; 6]) -> i64 {
    match nr {
        nr::CLOCK_GETTIME => sys_clock_gettime(args[0], args[1] as *mut Timespec),
        nr::CLOCK_GETRES => sys_clock_getres(args[0], args[1] as *mut Timespec),
        nr::GETTIMEOFDAY => sys_gettimeofday(args[0] as *mut Timeval),
        nr::NANOSLEEP => sys_nanosleep(args[0] as *const Timespec),
        nr::CLOCK_NANOSLEEP => sys_clock_nanosleep(args[0], args[1], args[2] as *const Timespec),
        nr::FUTEX => sys_futex(args),
        nr::READ => sys_read(args[0] as i64, args[1], args[2]),
        nr::WRITE => sys_write(args[0] as i64, args[1], args[2]),
        nr::OPENAT => sys_openat(args[0] as i64, args[1], args[2]),
        nr::CLOSE => sys_close(args[0] as i64),
        nr::LSEEK => sys_lseek(args[0] as i64, args[1] as i64, args[2]),
        nr::GETRANDOM => sys_getrandom(args[0], args[1], args[2]),
        nr::SCHED_YIELD => {
            // SAFETY: plain runtime entry, no pointers.
            ret_i32(unsafe { patina_sched_yield() })
        }
        nr::GETTID => {
            // SAFETY: as above.
            unsafe { patina_thread_id() as i64 }
        }
        // A raw `exit`/`exit_group` ends the run deterministically. Slice 1 folds
        // a lone-thread raw `exit(2)` onto whole-process exit (no managed guest
        // raw-exits a single thread — std threads return from the trampoline);
        // true per-thread raw exit is slice 2.
        nr::EXIT | nr::EXIT_GROUP => {
            // SAFETY: `patina_exit` terminates the process and never returns.
            unsafe { patina_exit((args[0] & 0xff) as c_int) }
        }
        // Process-local memory management: pass through to the host kernel via the
        // glibc `syscall(2)` vehicle (its kernel entry sits in glibc text, the
        // allowed region). Anonymous only — an fd-backed mapping would bypass the
        // deterministic FS and is refused loudly.
        nr::MMAP => sys_mmap(nr, args),
        nr::MUNMAP | nr::MPROTECT | nr::MADVISE | nr::MREMAP | nr::BRK => mem_passthrough(nr, args),
        // A kernel without these is a real configuration every libc/runtime
        // handles; passing them through would leak host-kernel-version behavior.
        nr::SET_ROBUST_LIST | nr::RSEQ | nr::MEMBARRIER => -ENOSYS,
        // No ambient signals exist in the simulation, so signal-mask/altstack ops
        // are deterministic success no-ops — EXCEPT `rt_sigaction` for SIGSYS,
        // which would replace the dispatch handler: that is fatal (§7.5 raw door).
        nr::RT_SIGPROCMASK | nr::SIGALTSTACK => 0,
        nr::RT_SIGACTION => sys_rt_sigaction(args[0] as i64),
        // Everything else — the process/escape class (clone/execve/ptrace/prctl/
        // seccomp/io_uring/…) and any un-tabled number — is fatal by default.
        _ => unmapped(nr, args),
    }
}

fn clock_from_raw(raw: u64) -> Option<u32> {
    // Mirror the C `clock_gettime` interposer: only REALTIME/MONOTONIC route.
    match raw {
        0 => Some(PATINA_CLOCK_REALTIME),
        1 => Some(PATINA_CLOCK_MONOTONIC),
        _ => None,
    }
}

fn sys_clock_gettime(clock_raw: u64, out: *mut Timespec) -> i64 {
    let Some(clock) = clock_from_raw(clock_raw) else {
        return -EINVAL;
    };
    if out.is_null() {
        return -EINVAL;
    }
    let mut nanos: u64 = 0;
    // SAFETY: `nanos` is local, writable storage.
    let rc = unsafe { patina_clock_now(clock, &mut nanos) };
    if rc != 0 {
        return ret_i32(rc);
    }
    // SAFETY: `out` is a guest pointer to `struct timespec` storage.
    unsafe {
        out.write(Timespec {
            tv_sec: (nanos / NANOS_PER_SEC) as i64,
            tv_nsec: (nanos % NANOS_PER_SEC) as i64,
        });
    }
    0
}

fn sys_clock_getres(clock_raw: u64, out: *mut Timespec) -> i64 {
    // Resolution of the virtual clock is 1ns; report it deterministically.
    if clock_from_raw(clock_raw).is_none() {
        return -EINVAL;
    }
    if !out.is_null() {
        // SAFETY: `out` is a guest `struct timespec` pointer.
        unsafe {
            out.write(Timespec {
                tv_sec: 0,
                tv_nsec: 1,
            });
        }
    }
    0
}

fn sys_gettimeofday(out: *mut Timeval) -> i64 {
    if out.is_null() {
        return 0;
    }
    let mut nanos: u64 = 0;
    // SAFETY: local storage.
    let rc = unsafe { patina_clock_now(PATINA_CLOCK_REALTIME, &mut nanos) };
    if rc != 0 {
        return ret_i32(rc);
    }
    // SAFETY: `out` is a guest `struct timeval` pointer.
    unsafe {
        out.write(Timeval {
            tv_sec: (nanos / NANOS_PER_SEC) as i64,
            tv_usec: ((nanos % NANOS_PER_SEC) / 1000) as i64,
        });
    }
    0
}

/// Read a `struct timespec` from guest memory and validate it, returning its
/// value in nanoseconds or an `-errno`.
fn read_timespec_nanos(ptr: *const Timespec) -> Result<u64, i64> {
    if ptr.is_null() {
        return Err(-EINVAL);
    }
    // SAFETY: `ptr` is a guest `struct timespec` pointer.
    let ts = unsafe { ptr.read() };
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= NANOS_PER_SEC as i64 {
        return Err(-EINVAL);
    }
    let seconds = ts.tv_sec as u64;
    if seconds > u64::MAX / NANOS_PER_SEC {
        return Err(-EINVAL);
    }
    Ok(seconds * NANOS_PER_SEC + ts.tv_nsec as u64)
}

fn sys_nanosleep(req: *const Timespec) -> i64 {
    // Relative CLOCK_MONOTONIC sleep. Convert to an absolute virtual deadline.
    let rel = match read_timespec_nanos(req) {
        Ok(nanos) => nanos,
        Err(errno) => return errno,
    };
    let mut now: u64 = 0;
    // SAFETY: local storage.
    let rc = unsafe { patina_clock_now(PATINA_CLOCK_MONOTONIC, &mut now) };
    if rc != 0 {
        return ret_i32(rc);
    }
    let deadline = now.saturating_add(rel);
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_sleep_until(PATINA_CLOCK_MONOTONIC, deadline) })
}

fn sys_clock_nanosleep(clock_raw: u64, flags: u64, req: *const Timespec) -> i64 {
    let Some(clock) = clock_from_raw(clock_raw) else {
        return -EINVAL;
    };
    let requested = match read_timespec_nanos(req) {
        Ok(nanos) => nanos,
        Err(errno) => return errno,
    };
    let deadline = if flags & TIMER_ABSTIME != 0 {
        requested
    } else {
        let mut now: u64 = 0;
        // SAFETY: local storage.
        let rc = unsafe { patina_clock_now(clock, &mut now) };
        if rc != 0 {
            return ret_i32(rc);
        }
        now.saturating_add(requested)
    };
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_sleep_until(clock, deadline) })
}

fn sys_futex(args: [u64; 6]) -> i64 {
    let uaddr = args[0] as usize;
    let futex_op = args[1];
    let val = args[2] as u32;
    let timeout = args[3] as *const Timespec;
    let op = futex_op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    if op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET {
        if timeout.is_null() {
            // SAFETY: no dereference of `uaddr` here; the runtime treats it as a key.
            return ret_i32(unsafe { patina_futex_wait(uaddr, val) });
        }
        // FUTEX_WAIT: relative CLOCK_MONOTONIC. FUTEX_WAIT_BITSET: absolute,
        // CLOCK_REALTIME iff FUTEX_CLOCK_REALTIME — mirrors the C `syscall()` path.
        let absolute = op == FUTEX_WAIT_BITSET;
        let clock = if absolute && futex_op & FUTEX_CLOCK_REALTIME != 0 {
            PATINA_CLOCK_REALTIME
        } else {
            PATINA_CLOCK_MONOTONIC
        };
        let timeout_nanos = match read_timespec_nanos(timeout) {
            Ok(nanos) => nanos,
            Err(errno) => return errno,
        };
        // SAFETY: `uaddr` is treated as a key by the runtime.
        return ret_i32(unsafe {
            patina_futex_wait_timed(uaddr, val, clock, absolute as c_int, timeout_nanos)
        });
    }
    if op == FUTEX_WAKE || op == FUTEX_WAKE_BITSET {
        // SAFETY: `uaddr` is a key; `val` is the wake count.
        return ret_i32(unsafe { patina_futex_wake(uaddr, val as c_int) });
    }
    -ENOSYS
}

fn sys_read(fd: i64, buf: u64, count: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: `buf`/`count` describe a guest buffer per the read(2) contract.
    ret_isize(unsafe { patina_read(fd as c_int, buf as *mut c_void, count as usize) })
}

fn sys_write(fd: i64, buf: u64, count: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: `buf`/`count` describe a guest buffer per the write(2) contract.
    ret_isize(unsafe { patina_write(fd as c_int, buf as *const c_void, count as usize) })
}

fn sys_close(fd: i64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // SAFETY: no pointers.
    ret_i32(unsafe { patina_close(fd as c_int) })
}

fn sys_lseek(fd: i64, offset: i64, whence: u64) -> i64 {
    if let Some(err) = fd_out_of_range(fd) {
        return err;
    }
    // patina_seek returns the new offset or -1; shape it to the raw convention.
    // SAFETY: no pointers.
    let result = unsafe { patina_seek(fd as c_int, offset, whence as u32) };
    if result < 0 {
        // SAFETY: plain thread-local read.
        -(unsafe { patina_errno() } as i64)
    } else {
        result
    }
}

/// Guard the fd against the negative/oversized values that cannot be Patina
/// virtual descriptors, so the cast into `c_int` never wraps.
fn fd_out_of_range(fd: i64) -> Option<i64> {
    if fd < 0 || fd > c_int::MAX as i64 {
        Some(-EINVAL)
    } else {
        None
    }
}

fn sys_openat(dirfd: i64, path: u64, flags: u64) -> i64 {
    // Slice 1: AT_FDCWD only. A real dirfd is slice 2 (dirfd-relative resolution).
    if dirfd != AT_FDCWD {
        return -EINVAL;
    }
    if path == 0 {
        return -EINVAL;
    }
    let mut patina_flags = match flags & O_ACCMODE {
        O_WRONLY => PATINA_O_WRITE,
        O_RDWR => PATINA_O_READ | PATINA_O_WRITE,
        // O_RDONLY == 0
        _ => PATINA_O_READ,
    };
    if flags & O_CREAT != 0 {
        patina_flags |= PATINA_O_CREATE;
    }
    if flags & O_TRUNC != 0 {
        patina_flags |= PATINA_O_TRUNCATE;
    }
    if flags & O_APPEND != 0 {
        patina_flags |= PATINA_O_APPEND;
    }
    if flags & O_EXCL != 0 {
        patina_flags |= PATINA_O_EXCLUSIVE;
    }
    // SAFETY: `path` is a guest NUL-terminated string pointer.
    ret_i32(unsafe { patina_open(path as *const c_char, patina_flags) })
}

fn sys_getrandom(buf: u64, len: u64, _flags: u64) -> i64 {
    // Deterministic entropy never blocks and has one source, so GRND_* flags are
    // irrelevant (mirrors the C getrandom/SYS_getrandom routes).
    // SAFETY: `buf`/`len` describe a guest buffer.
    let rc = unsafe { patina_entropy(buf as *mut c_void, len as usize) };
    if rc != 0 {
        // SAFETY: plain thread-local read.
        -(unsafe { patina_errno() } as i64)
    } else {
        len as i64
    }
}

fn sys_rt_sigaction(signum: i64) -> i64 {
    // SIGSYS registration by the guest would replace the dispatch handler:
    // containment over. Fatal (the raw door of the §7.5 SIGSYS hardening; the
    // symbol door is the interposed sigaction/signal in patina_posix.c).
    const SIGSYS: i64 = 31;
    if signum == SIGSYS {
        crate::sud_fatal(
            "SUD trapped rt_sigaction(SIGSYS): a guest may not re-register the syscall-dispatch \
             handler — doing so would disable deterministic containment",
        );
    }
    // No ambient signals exist, so registering any other handler is a
    // deterministic success no-op that records nothing (mirrors the allowlist
    // stance for bare sigaction/signal).
    0
}

fn sys_mmap(nr: i64, args: [u64; 6]) -> i64 {
    let flags = args[3];
    let fd = args[4] as i64;
    if flags & MAP_ANONYMOUS == 0 || fd != -1 {
        crate::sud_fatal(
            "SUD trapped a file-backed mmap: mapping a descriptor into memory bypasses the \
             deterministic filesystem. Only MAP_ANONYMOUS mappings (fd == -1) are process-local \
             and passed through",
        );
    }
    mem_passthrough(nr, args)
}

/// Pass a process-local memory syscall through to the host kernel via the glibc
/// `syscall(2)` vehicle. The wrapper returns `-1` and sets `errno` on failure;
/// reshape that into the raw `-errno` the syscall return register carries.
fn mem_passthrough(nr: i64, args: [u64; 6]) -> i64 {
    // SAFETY: process-local memory management; the arguments are the guest's own
    // and the vehicle is glibc's `syscall` wrapper resolved as a host alias.
    let result = unsafe {
        crate::sud_host_syscall(
            nr as c_long,
            args[0] as c_long,
            args[1] as c_long,
            args[2] as c_long,
            args[3] as c_long,
            args[4] as c_long,
            args[5] as c_long,
        )
    };
    if result == -1 {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .map(|e| e as i64)
            .unwrap_or(EIO);
        -errno
    } else {
        result as i64
    }
}

fn unmapped(nr: i64, args: [u64; 6]) -> i64 {
    crate::sud_fatal(&format!(
        "SUD trapped unsupported syscall {nr} (args {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}); guest raw \
         syscalls must map to a deterministic route. This is the process/escape class (clone, \
         execve, ptrace, prctl, seccomp, io_uring, …) or a number slice 1 does not yet route — see \
         `cargo patina audit`",
        args[0], args[1], args[2], args[3], args[4], args[5]
    ));
}
