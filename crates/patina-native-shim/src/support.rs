//! Shared errno, open-flag, and signal-safe synchronization primitives.

use super::*;

// POSIX errno values. The low-numbered codes below are identical on macOS and
// Linux, but several higher codes diverge (Darwin's BSD numbering vs Linux's
// asm-generic table). Those MUST be target-conditional: returning the macOS
// value on Linux hands the guest a *different* error — e.g. the macOS
// `EWOULDBLOCK` value 35 is Linux's `EDEADLK` ("Resource deadlock avoided"), so
// std's futex `EAGAIN` retry path (every contended mutex) was seen as a fatal
// deadlock. `EWOULDBLOCK == EAGAIN` on Linux (11).
pub(crate) const EACCES: c_int = 13;
#[cfg(target_os = "macos")]
pub(crate) const EALREADY: c_int = 37;
#[cfg(not(target_os = "macos"))]
pub(crate) const EALREADY: c_int = 114;
pub(crate) const EBADF: c_int = 9;
pub(crate) const EBUSY: c_int = 16;
#[cfg(target_os = "macos")]
pub(crate) const EDEADLK: c_int = 11;
#[cfg(not(target_os = "macos"))]
pub(crate) const EDEADLK: c_int = 35;
pub(crate) const EEXIST: c_int = 17;
pub(crate) const EINTR: c_int = 4;
pub(crate) const EINVAL: c_int = 22;
pub(crate) const EFAULT: c_int = 14;
pub(crate) const EIO: c_int = 5;
#[cfg(target_os = "linux")]
pub(crate) const ENOTTY: c_int = 25;
#[cfg(target_os = "linux")]
pub(crate) const ENOMEM: c_int = 12;
pub(crate) const EISDIR: c_int = 21;
pub(crate) const ENOENT: c_int = 2;
pub(crate) const ENOSPC: c_int = 28;
#[cfg(target_os = "macos")]
pub(crate) const ENOSYS: c_int = 78;
#[cfg(not(target_os = "macos"))]
pub(crate) const ENOSYS: c_int = 38;
pub(crate) const ENOTDIR: c_int = 20;
#[cfg(target_os = "macos")]
pub(crate) const ELOOP: c_int = 62;
#[cfg(not(target_os = "macos"))]
pub(crate) const ELOOP: c_int = 40;
#[cfg(target_os = "macos")]
pub(crate) const ENOTEMPTY: c_int = 66;
#[cfg(not(target_os = "macos"))]
pub(crate) const ENOTEMPTY: c_int = 39;
#[cfg(target_os = "macos")]
pub(crate) const EOVERFLOW: c_int = 84;
#[cfg(not(target_os = "macos"))]
pub(crate) const EOVERFLOW: c_int = 75;
pub(crate) const EPERM: c_int = 1;
pub(crate) const ESRCH: c_int = 3;
#[cfg(target_os = "macos")]
pub(crate) const EWOULDBLOCK: c_int = 35;
#[cfg(not(target_os = "macos"))]
pub(crate) const EWOULDBLOCK: c_int = 11;
#[cfg(target_os = "macos")]
pub(crate) const ENOTCONN: c_int = 57;
#[cfg(not(target_os = "macos"))]
pub(crate) const ENOTCONN: c_int = 107;
pub(crate) const EPIPE: c_int = 32;
/// `ENXIO` — the answer a non-blocking `open(fifo, O_WRONLY)` gets with no
/// reader, and a `SEEK_DATA`/`SEEK_HOLE` that finds nothing. Same value on
/// macOS and Linux.
pub(crate) const ENXIO: c_int = 6;
#[cfg(target_os = "macos")]
pub(crate) const ECONNRESET: c_int = 54;
#[cfg(not(target_os = "macos"))]
pub(crate) const ECONNRESET: c_int = 104;
#[cfg(target_os = "macos")]
pub(crate) const EISCONN: c_int = 56;
#[cfg(not(target_os = "macos"))]
pub(crate) const EISCONN: c_int = 106;
#[cfg(target_os = "macos")]
pub(crate) const ECONNREFUSED: c_int = 61;
#[cfg(not(target_os = "macos"))]
pub(crate) const ECONNREFUSED: c_int = 111;
#[cfg(target_os = "macos")]
pub(crate) const EOPNOTSUPP: c_int = 102;
#[cfg(not(target_os = "macos"))]
pub(crate) const EOPNOTSUPP: c_int = 95;
#[cfg(target_os = "macos")]
pub(crate) const ETIMEDOUT: c_int = 60;
#[cfg(target_os = "linux")]
pub(crate) const ETIMEDOUT: c_int = 110;

#[cfg(target_os = "macos")]
pub(crate) const ENOTSOCK: c_int = 38;
#[cfg(target_os = "linux")]
pub(crate) const ENOTSOCK: c_int = 88;
pub(crate) const EFBIG: c_int = 27;
/// `fallocate` on a descriptor that is neither a regular file nor a block
/// device (a socket, an eventfd, a character device); 19 on Linux and Darwin.
pub(crate) const ENODEV: c_int = 19;
pub(crate) const ERANGE: c_int = 34;
pub(crate) const E2BIG: c_int = 7;
pub(crate) const EXDEV: c_int = 18;

/// The modeled page size: what `sysconf(_SC_PAGESIZE)` answers (the C layer
/// pins it), so what every page-granular kernel rule reads.
#[cfg(target_os = "linux")]
pub(crate) const PAGE_SIZE: usize = 4096;
#[cfg(target_os = "macos")]
pub(crate) const ENAMETOOLONG: c_int = 63;
#[cfg(not(target_os = "macos"))]
pub(crate) const ENAMETOOLONG: c_int = 36;
#[cfg(target_os = "macos")]
pub(crate) const ENODATA: c_int = 96;
#[cfg(not(target_os = "macos"))]
pub(crate) const ENODATA: c_int = 61;
pub(crate) const ESPIPE: c_int = 29;
pub(crate) const MAX_CAPTURED_STDIO_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const HOST_IO_CHUNK: usize = 64 * 1024;

pub(crate) const O_READ: u32 = 1 << 0;
pub(crate) const O_WRITE: u32 = 1 << 1;
pub(crate) const O_CREATE: u32 = 1 << 2;
pub(crate) const O_TRUNCATE: u32 = 1 << 3;
pub(crate) const O_APPEND: u32 = 1 << 4;
pub(crate) const O_EXCLUSIVE: u32 = 1 << 5;
/// `O_NOFOLLOW`: refuse a trailing symlink instead of resolving it. Not a driver
/// flag — the deterministic filesystem never opens a symlink entry — but the
/// choice [`patina_openat`] makes when the path turns out to name one: `ELOOP`
/// with this bit, resolve-and-retry without it.
pub(crate) const O_NOFOLLOW: u32 = 1 << 6;
/// `O_NONBLOCK`: on a regular file or a directory this changes nothing (it is a
/// no-op on every Unix), so it is not a driver flag either. It matters for
/// exactly one modeled entry kind — a FIFO — where it turns the open's
/// rendezvous with the opposite end into an immediate answer.
pub(crate) const O_NONBLOCK: u32 = 1 << 7;
/// `O_PATH`: name a LOCATION without opening the file behind it. This one IS a
/// driver flag: it changes what the open costs (the path prefix's `x` walk and
/// nothing on the entry, where a plain read-only open of a directory pays `r`)
/// and what the descriptor can then do (`*at` resolution, `fstat`, `readlinkat`,
/// `dup`, `close` — never a read, a write, or a directory listing). The kernel
/// ignores the access mode under it, so it never travels with `O_READ`/`O_WRITE`.
pub(crate) const O_PATH: u32 = 1 << 8;
/// `O_CLOEXEC`: not a driver flag and not a status flag either — it is the
/// per-NUMBER `FD_CLOEXEC` bit of the descriptor the open mints, so it lives on
/// the table slot, never on the description.
pub(crate) const O_CLOEXEC: u32 = 1 << 9;
/// `O_DIRECTORY`: the entry must be a directory (`ENOTDIR` otherwise). Not a
/// driver flag — the resolver already knows the entry's kind, and a directory
/// is opened as one whether or not the caller asked.
pub(crate) const O_DIRECTORY: u32 = 1 << 11;
/// A status bit the table sets on every description `open(2)` mints (a file, a
/// directory opened for reading, the entropy device, a FIFO endpoint) and on
/// nothing else: a 64-bit Linux kernel forces `O_LARGEFILE` into those
/// descriptions' `F_GETFL`, and a pipe, socket or `O_PATH` handle never carries
/// it. Never accepted from a caller (`O_ALL` excludes it).
pub(crate) const O_OPENED: u32 = 1 << 10;
/// `O_NOCTTY`: the opened terminal must not become the caller's controlling
/// terminal. Nothing but a pseudoterminal's slave reads it (a no-op on every
/// other entry), and it is never status.
pub(crate) const O_NOCTTY: u32 = 1 << 12;
pub(crate) const O_ALL: u32 = O_READ
    | O_WRITE
    | O_CREATE
    | O_TRUNCATE
    | O_APPEND
    | O_EXCLUSIVE
    | O_NOFOLLOW
    | O_NONBLOCK
    | O_PATH
    | O_CLOEXEC
    | O_DIRECTORY
    | O_NOCTTY;
/// The status bits `F_SETFL` may change (the kernel ignores every other bit in
/// the argument, including the access mode).
pub(crate) const O_SETFL_MASK: u32 = O_APPEND | O_NONBLOCK;

/// A minimal spinlock the shim uses instead of `std::sync::Mutex`.
///
/// The shim interposes `pthread_mutex_*`, so its own `std::sync::Mutex` would
/// recurse straight back into the deterministic layer. A spinlock built on
/// atomics never touches pthread, and every critical section here is short and
/// almost always uncontended: only the managed thread that currently holds the
/// execution baton runs shim code, so contention is limited to brief handoffs.
pub(crate) struct SpinMutex<T> {
    /// The lock word: the holding thread's [`thread_token`], 0 while free.
    /// Taking the lock and naming its holder are one compare-exchange, so
    /// there is no instant at which the lock is held by nobody in particular.
    /// A contended acquire whose holder is the acquiring thread itself can
    /// never succeed:
    /// the only way one thread reaches a shim lock it already holds is a
    /// signal handler running over shim code (a fault in the shim, the guest's
    /// handler calling back into an interposer), and spinning there hangs the
    /// process where the kernel would have answered. [`SpinMutex::lock`] turns
    /// it into a named fatal instead.
    owner: AtomicUsize,
    value: UnsafeCell<T>,
}

/// A shim lock re-acquired by the thread that holds it (see [`SpinMutex`]).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SelfDeadlock;

/// This thread's identity for [`SpinMutex::owner`]: the address of one of its
/// thread-locals, never 0 and unique among LIVE threads (a thread that exits
/// can hand its address to a later one; a holder cannot exit while holding a
/// shim lock without the process aborting first).
fn thread_token() -> usize {
    thread_local! {
        static TOKEN: u8 = const { 0 };
    }
    TOKEN.with(|token| token as *const u8 as usize)
}

// SAFETY: the spinlock serializes all access to the interior value, so it is
// safe to share across threads whenever the value may be sent across them.
unsafe impl<T: Send> Sync for SpinMutex<T> {}
// SAFETY: as above; ownership can move across threads.
unsafe impl<T: Send> Send for SpinMutex<T> {}

impl<T> SpinMutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            owner: AtomicUsize::new(0),
            value: UnsafeCell::new(value),
        }
    }

    pub(crate) fn lock(&self) -> SpinGuard<'_, T> {
        self.acquire().unwrap_or_else(|SelfDeadlock| {
            // Nothing that takes a shim lock may run here — the lock this
            // thread re-entered may be any of them, the captured-stdio one
            // included — so the diagnostic goes straight to the host.
            let _ = host_write_all(
                2,
                b"patina native shim fatal: a shim lock was re-entered by the thread that \
                  holds it (a signal handler ran over shim code); failing closed\n",
            );
            host_abort()
        })
    }

    /// Attempt the lock without waiting, even if this thread already holds it.
    pub(crate) fn try_lock(&self) -> Option<SpinGuard<'_, T>> {
        self.owner
            .compare_exchange(0, thread_token(), Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        spin_depth_inc();
        Some(SpinGuard { mutex: self })
    }

    /// Take the lock, or report that this thread already holds it.
    pub(crate) fn acquire(&self) -> Result<SpinGuard<'_, T>, SelfDeadlock> {
        let me = thread_token();
        while let Err(holder) =
            self.owner
                .compare_exchange_weak(0, me, Ordering::Acquire, Ordering::Relaxed)
        {
            // The lock word names its holder from the instant it is taken, so
            // this thread reads its own token exactly while it holds the lock.
            if holder == me {
                return Err(SelfDeadlock);
            }
            while self.owner.load(Ordering::Relaxed) != 0 {
                std::hint::spin_loop();
            }
        }
        // Mark that this thread now holds a shim spinlock, so a reentrant lock
        // interposer (reached only via an allocator-internal allocation on the
        // scheduler path) forwards to the real host primitive instead of
        // deadlocking on this very lock. See `SPIN_DEPTH`.
        spin_depth_inc();
        Ok(SpinGuard { mutex: self })
    }
}

pub(crate) struct SpinGuard<'a, T> {
    mutex: &'a SpinMutex<T>,
}

impl<T> Deref for SpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: holding the guard guarantees exclusive access.
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> DerefMut for SpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: holding the guard guarantees exclusive access.
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Drop for SpinGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.owner.store(0, Ordering::Release);
        spin_depth_dec();
    }
}

#[cfg(test)]
mod spin_mutex_tests {
    use super::{SelfDeadlock, SpinMutex};

    #[test]
    fn a_lock_its_own_holder_takes_again_is_a_self_deadlock_not_a_spin() {
        let mutex = SpinMutex::new(0u8);
        let held = mutex.acquire().expect("a free lock is taken");
        assert_eq!(mutex.acquire().err(), Some(SelfDeadlock));
        drop(held);
        assert!(mutex.acquire().is_ok(), "released, it is free again");
    }

    #[test]
    fn a_lock_another_thread_released_is_no_self_deadlock() {
        let mutex = std::sync::Arc::new(SpinMutex::new(0u8));
        let other = std::sync::Arc::clone(&mutex);
        std::thread::spawn(move || drop(other.acquire().expect("taken elsewhere")))
            .join()
            .unwrap();
        let held = mutex.acquire().expect("free after the other thread");
        assert_eq!(mutex.acquire().err(), Some(SelfDeadlock));
        drop(held);
    }
}
