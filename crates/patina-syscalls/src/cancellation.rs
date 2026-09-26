//! glibc 2.39's thread cancellation points on Linux, and how a guest meets a
//! pending cancel at each: every one is a shim C wrapper, which the model
//! either acts at ([`ACTS_AT`]) or checks at its entry (`PATINA_CANCEL_POINT`,
//! a named stop when the caller has a cancel to act on), or an import the
//! pre-run audit refuses (a few act only where they wait:
//! [`ONLY_WHERE_IT_WAITS`]). `cargo-patina/tests/syscall_registry.rs` holds the
//! shim's C and the audit to this list.
//!
//! The list is glibc's own, read from its 2.39 source rather than from the
//! manual: the public symbols (fortified entries included) whose Linux
//! implementation issues a cancellable syscall (`SYSCALL_CANCEL`,
//! `__pthread_enable_asynccancel`), waits on a cancellable futex
//! (`__futex_abstimed_wait_cancelable64`: joins, condition variables,
//! semaphores, `aio_suspend`), or calls one of those (`sleep`, `sigwait`,
//! `waitpid`, `lockf`, `eventfd_read`, `system`, ...), plus
//! `pthread_testcancel`. The stdio functions are cancellation points only
//! where libio writes (`_IO_new_file_write` calls the cancellable `write`);
//! the shim's streams check at that write instead of at each function.

/// glibc 2.39's cancellation points on Linux (x86_64 and aarch64).
pub const GLIBC_CANCELLATION_POINTS: &[&str] = &[
    // A cancellable syscall.
    "accept",
    "accept4",
    "clock_nanosleep",
    "close",
    "connect",
    "copy_file_range",
    "creat",
    "creat64",
    "epoll_pwait",
    "epoll_pwait2",
    "epoll_wait",
    "fallocate",
    "fallocate64",
    // Only `F_SETLKW`/`F_OFD_SETLKW` are cancellable.
    "fcntl",
    "fcntl64",
    "fdatasync",
    "fsync",
    "getrandom",
    "mq_timedreceive",
    "mq_timedsend",
    "msgrcv",
    "msgsnd",
    "msync",
    "open",
    "open64",
    "open_by_handle_at",
    "openat",
    "openat64",
    "pause",
    "poll",
    "ppoll",
    "pread",
    "pread64",
    "preadv",
    "preadv2",
    "preadv64",
    "preadv64v2",
    "pselect",
    "pwrite",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "pwritev64",
    "pwritev64v2",
    "read",
    "readv",
    "recv",
    "recvfrom",
    "recvmmsg",
    "recvmsg",
    "select",
    "send",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "sigsuspend",
    "sigtimedwait",
    "splice",
    "sync_file_range",
    "tcdrain",
    "tee",
    "vmsplice",
    "wait4",
    "waitid",
    "write",
    "writev",
    // A call into one of those.
    "eventfd_read",
    "eventfd_write",
    "lockf",
    "lockf64",
    "mq_receive",
    "mq_send",
    "nanosleep",
    "sigpause",
    "sigwait",
    "sigwaitinfo",
    "sleep",
    "system",
    "thrd_sleep",
    "usleep",
    "wait",
    "wait3",
    "waitpid",
    // The fortified entries of those.
    "__open_2",
    "__open64_2",
    "__openat_2",
    "__openat64_2",
    "__poll_chk",
    "__ppoll_chk",
    "__pread_chk",
    "__pread64_chk",
    "__read_chk",
    "__recv_chk",
    "__recvfrom_chk",
    // A cancellable futex wait.
    "aio_suspend",
    "aio_suspend64",
    "cnd_timedwait",
    "cnd_wait",
    "pthread_clockjoin_np",
    "pthread_cond_clockwait",
    "pthread_cond_timedwait",
    "pthread_cond_wait",
    "pthread_join",
    "pthread_timedjoin_np",
    "sem_clockwait",
    "sem_timedwait",
    "sem_wait",
    "thrd_join",
    // The explicit one.
    "pthread_testcancel",
];

/// The cancellation points glibc acts at only where they wait: its
/// `pthread_join` of a thread that has ended returns without waiting and so
/// without acting (nptl `pthread_join_common.c`), and waits (and acts) where
/// it would otherwise answer `EDEADLK`. The model stops by name wherever a
/// thread with a cancel to act on would wait in one (a join wait is a
/// cancellable wait class) or meets that `EDEADLK`, and lets the rest return.
pub const ONLY_WHERE_IT_WAITS: &[&str] = &["pthread_join"];

/// The cancellation points the model acts at, as glibc does (a pending
/// cancel ends the thread at the entry, and one arriving while the thread
/// waits inside ends it there): the C wrappers bracket them with
/// `PATINA_CANCEL_ENTER`/`PATINA_CANCEL_LEAVE`, or test (`pthread_testcancel`).
pub const ACTS_AT: &[&str] = &[
    "clock_nanosleep",
    "nanosleep",
    "pthread_testcancel",
    "sleep",
];
