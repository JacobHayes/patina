//! Which argument registers each system call reads. The boundary record keeps only those
//! (`used_args`), and only those are checked for pointers into the runtime's region and for
//! hidden descriptors (rt `guest::names_runtime`, `sys::dispatch`): the other registers hold
//! whatever the program's code left there, which the kernel ignores and which differs between
//! hosts where the program's behaviour does not (a `cpuid` result on one x86 CPU model; on
//! arm64 the scratch value of the `memcpy` variant libc chose for the CPU).
//!
//! Two parts. `NARGS`: how many arguments each call has, from the kernel's syscall trace
//! events (`/sys/kernel/tracing/events/syscalls/sys_enter_*/format`, Linux 7.0); calls without
//! a trace event (`rt_sigreturn`, numbers the kernel does not know) keep all six. `dead`: the
//! arguments a call has but does not read for the values of its other arguments (a flag, a
//! command, a NULL pointer), from the kernel's code for each call the table passes, rewrites
//! or answers; for the multiplexed calls (`fcntl`, `ioctl`, `prctl`, `arch_prctl`) from the
//! command lists in `cmds`, which are also their allowlists.

use super::{nr, NR_COUNT};

/// Set by name: a call this architecture lacks has no slot.
const fn set(a: &mut [u8; NR_COUNT], nr: u64, n: u8) {
    if nr::present(nr) {
        a[nr as usize] = n;
    }
}

pub static NARGS: [u8; NR_COUNT] = {
    let mut a = [6u8; NR_COUNT];
    set(&mut a, nr::READ, 3);
    set(&mut a, nr::WRITE, 3);
    set(&mut a, nr::OPEN, 3);
    set(&mut a, nr::CLOSE, 1);
    set(&mut a, nr::STAT, 2);
    set(&mut a, nr::FSTAT, 2);
    set(&mut a, nr::LSTAT, 2);
    set(&mut a, nr::POLL, 3);
    set(&mut a, nr::LSEEK, 3);
    set(&mut a, nr::MPROTECT, 3);
    set(&mut a, nr::MUNMAP, 2);
    set(&mut a, nr::BRK, 1);
    set(&mut a, nr::RT_SIGACTION, 4);
    set(&mut a, nr::RT_SIGPROCMASK, 4);
    set(&mut a, nr::RT_SIGRETURN, 0);
    set(&mut a, nr::IOCTL, 3);
    set(&mut a, nr::PREAD64, 4);
    set(&mut a, nr::PWRITE64, 4);
    set(&mut a, nr::READV, 3);
    set(&mut a, nr::WRITEV, 3);
    set(&mut a, nr::ACCESS, 2);
    set(&mut a, nr::PIPE, 1);
    set(&mut a, nr::SELECT, 5);
    set(&mut a, nr::SCHED_YIELD, 0);
    set(&mut a, nr::MREMAP, 5);
    set(&mut a, nr::MSYNC, 3);
    set(&mut a, nr::MINCORE, 3);
    set(&mut a, nr::MADVISE, 3);
    set(&mut a, nr::SHMGET, 3);
    set(&mut a, nr::SHMAT, 3);
    set(&mut a, nr::SHMCTL, 3);
    set(&mut a, nr::DUP, 1);
    set(&mut a, nr::DUP2, 2);
    set(&mut a, nr::PAUSE, 0);
    set(&mut a, nr::NANOSLEEP, 2);
    set(&mut a, nr::GETITIMER, 2);
    set(&mut a, nr::ALARM, 1);
    set(&mut a, nr::SETITIMER, 3);
    set(&mut a, nr::GETPID, 0);
    set(&mut a, nr::SENDFILE, 4);
    set(&mut a, nr::SOCKET, 3);
    set(&mut a, nr::CONNECT, 3);
    set(&mut a, nr::ACCEPT, 3);
    set(&mut a, nr::SENDMSG, 3);
    set(&mut a, nr::RECVMSG, 3);
    set(&mut a, nr::SHUTDOWN, 2);
    set(&mut a, nr::BIND, 3);
    set(&mut a, nr::LISTEN, 2);
    set(&mut a, nr::GETSOCKNAME, 3);
    set(&mut a, nr::GETPEERNAME, 3);
    set(&mut a, nr::SOCKETPAIR, 4);
    set(&mut a, nr::SETSOCKOPT, 5);
    set(&mut a, nr::GETSOCKOPT, 5);
    set(&mut a, nr::CLONE, 5);
    set(&mut a, nr::FORK, 0);
    set(&mut a, nr::VFORK, 0);
    set(&mut a, nr::EXECVE, 3);
    set(&mut a, nr::EXIT, 1);
    set(&mut a, nr::WAIT4, 4);
    set(&mut a, nr::KILL, 2);
    set(&mut a, nr::UNAME, 1);
    set(&mut a, nr::SEMGET, 3);
    set(&mut a, nr::SEMOP, 3);
    set(&mut a, nr::SEMCTL, 4);
    set(&mut a, nr::SHMDT, 1);
    set(&mut a, nr::MSGGET, 2);
    set(&mut a, nr::MSGSND, 4);
    set(&mut a, nr::MSGRCV, 5);
    set(&mut a, nr::MSGCTL, 3);
    set(&mut a, nr::FCNTL, 3);
    set(&mut a, nr::FLOCK, 2);
    set(&mut a, nr::FSYNC, 1);
    set(&mut a, nr::FDATASYNC, 1);
    set(&mut a, nr::TRUNCATE, 2);
    set(&mut a, nr::FTRUNCATE, 2);
    set(&mut a, nr::GETDENTS, 3);
    set(&mut a, nr::GETCWD, 2);
    set(&mut a, nr::CHDIR, 1);
    set(&mut a, nr::FCHDIR, 1);
    set(&mut a, nr::RENAME, 2);
    set(&mut a, nr::MKDIR, 2);
    set(&mut a, nr::RMDIR, 1);
    set(&mut a, nr::CREAT, 2);
    set(&mut a, nr::LINK, 2);
    set(&mut a, nr::UNLINK, 1);
    set(&mut a, nr::SYMLINK, 2);
    set(&mut a, nr::READLINK, 3);
    set(&mut a, nr::CHMOD, 2);
    set(&mut a, nr::FCHMOD, 2);
    set(&mut a, nr::CHOWN, 3);
    set(&mut a, nr::FCHOWN, 3);
    set(&mut a, nr::LCHOWN, 3);
    set(&mut a, nr::UMASK, 1);
    set(&mut a, nr::GETTIMEOFDAY, 2);
    set(&mut a, nr::GETRLIMIT, 2);
    set(&mut a, nr::GETRUSAGE, 2);
    set(&mut a, nr::SYSINFO, 1);
    set(&mut a, nr::TIMES, 1);
    set(&mut a, nr::PTRACE, 4);
    set(&mut a, nr::GETUID, 0);
    set(&mut a, nr::SYSLOG, 3);
    set(&mut a, nr::GETGID, 0);
    set(&mut a, nr::SETUID, 1);
    set(&mut a, nr::SETGID, 1);
    set(&mut a, nr::GETEUID, 0);
    set(&mut a, nr::GETEGID, 0);
    set(&mut a, nr::SETPGID, 2);
    set(&mut a, nr::GETPPID, 0);
    set(&mut a, nr::GETPGRP, 0);
    set(&mut a, nr::SETSID, 0);
    set(&mut a, nr::SETREUID, 2);
    set(&mut a, nr::SETREGID, 2);
    set(&mut a, nr::GETGROUPS, 2);
    set(&mut a, nr::SETGROUPS, 2);
    set(&mut a, nr::SETRESUID, 3);
    set(&mut a, nr::GETRESUID, 3);
    set(&mut a, nr::SETRESGID, 3);
    set(&mut a, nr::GETRESGID, 3);
    set(&mut a, nr::GETPGID, 1);
    set(&mut a, nr::SETFSUID, 1);
    set(&mut a, nr::SETFSGID, 1);
    set(&mut a, nr::GETSID, 1);
    set(&mut a, nr::CAPGET, 2);
    set(&mut a, nr::CAPSET, 2);
    set(&mut a, nr::RT_SIGPENDING, 2);
    set(&mut a, nr::RT_SIGTIMEDWAIT, 4);
    set(&mut a, nr::RT_SIGQUEUEINFO, 3);
    set(&mut a, nr::RT_SIGSUSPEND, 2);
    set(&mut a, nr::SIGALTSTACK, 2);
    set(&mut a, nr::UTIME, 2);
    set(&mut a, nr::MKNOD, 3);
    set(&mut a, nr::PERSONALITY, 1);
    set(&mut a, nr::USTAT, 2);
    set(&mut a, nr::STATFS, 2);
    set(&mut a, nr::FSTATFS, 2);
    set(&mut a, nr::SYSFS, 3);
    set(&mut a, nr::GETPRIORITY, 2);
    set(&mut a, nr::SETPRIORITY, 3);
    set(&mut a, nr::SCHED_SETPARAM, 2);
    set(&mut a, nr::SCHED_GETPARAM, 2);
    set(&mut a, nr::SCHED_SETSCHEDULER, 3);
    set(&mut a, nr::SCHED_GETSCHEDULER, 1);
    set(&mut a, nr::SCHED_GET_PRIORITY_MAX, 1);
    set(&mut a, nr::SCHED_GET_PRIORITY_MIN, 1);
    set(&mut a, nr::SCHED_RR_GET_INTERVAL, 2);
    set(&mut a, nr::MLOCK, 2);
    set(&mut a, nr::MUNLOCK, 2);
    set(&mut a, nr::MLOCKALL, 1);
    set(&mut a, nr::MUNLOCKALL, 0);
    set(&mut a, nr::VHANGUP, 0);
    set(&mut a, nr::MODIFY_LDT, 3);
    set(&mut a, nr::PIVOT_ROOT, 2);
    set(&mut a, nr::PRCTL, 5);
    set(&mut a, nr::ARCH_PRCTL, 2);
    set(&mut a, nr::ADJTIMEX, 1);
    set(&mut a, nr::SETRLIMIT, 2);
    set(&mut a, nr::CHROOT, 1);
    set(&mut a, nr::SYNC, 0);
    set(&mut a, nr::ACCT, 1);
    set(&mut a, nr::SETTIMEOFDAY, 2);
    set(&mut a, nr::MOUNT, 5);
    set(&mut a, nr::UMOUNT2, 2);
    set(&mut a, nr::SWAPON, 2);
    set(&mut a, nr::SWAPOFF, 1);
    set(&mut a, nr::REBOOT, 4);
    set(&mut a, nr::SETHOSTNAME, 2);
    set(&mut a, nr::SETDOMAINNAME, 2);
    set(&mut a, nr::IOPL, 1);
    set(&mut a, nr::IOPERM, 3);
    set(&mut a, nr::INIT_MODULE, 3);
    set(&mut a, nr::DELETE_MODULE, 2);
    set(&mut a, nr::QUOTACTL, 4);
    set(&mut a, nr::GETTID, 0);
    set(&mut a, nr::READAHEAD, 3);
    set(&mut a, nr::SETXATTR, 5);
    set(&mut a, nr::LSETXATTR, 5);
    set(&mut a, nr::FSETXATTR, 5);
    set(&mut a, nr::GETXATTR, 4);
    set(&mut a, nr::LGETXATTR, 4);
    set(&mut a, nr::FGETXATTR, 4);
    set(&mut a, nr::LISTXATTR, 3);
    set(&mut a, nr::LLISTXATTR, 3);
    set(&mut a, nr::FLISTXATTR, 3);
    set(&mut a, nr::REMOVEXATTR, 2);
    set(&mut a, nr::LREMOVEXATTR, 2);
    set(&mut a, nr::FREMOVEXATTR, 2);
    set(&mut a, nr::TKILL, 2);
    set(&mut a, nr::TIME, 1);
    set(&mut a, nr::SCHED_SETAFFINITY, 3);
    set(&mut a, nr::SCHED_GETAFFINITY, 3);
    set(&mut a, nr::IO_SETUP, 2);
    set(&mut a, nr::IO_DESTROY, 1);
    set(&mut a, nr::IO_GETEVENTS, 5);
    set(&mut a, nr::IO_SUBMIT, 3);
    set(&mut a, nr::IO_CANCEL, 3);
    set(&mut a, nr::EPOLL_CREATE, 1);
    set(&mut a, nr::REMAP_FILE_PAGES, 5);
    set(&mut a, nr::GETDENTS64, 3);
    set(&mut a, nr::SET_TID_ADDRESS, 1);
    set(&mut a, nr::RESTART_SYSCALL, 0);
    set(&mut a, nr::SEMTIMEDOP, 4);
    set(&mut a, nr::FADVISE64, 4);
    set(&mut a, nr::TIMER_CREATE, 3);
    set(&mut a, nr::TIMER_SETTIME, 4);
    set(&mut a, nr::TIMER_GETTIME, 2);
    set(&mut a, nr::TIMER_GETOVERRUN, 1);
    set(&mut a, nr::TIMER_DELETE, 1);
    set(&mut a, nr::CLOCK_SETTIME, 2);
    set(&mut a, nr::CLOCK_GETTIME, 2);
    set(&mut a, nr::CLOCK_GETRES, 2);
    set(&mut a, nr::CLOCK_NANOSLEEP, 4);
    set(&mut a, nr::EXIT_GROUP, 1);
    set(&mut a, nr::EPOLL_WAIT, 4);
    set(&mut a, nr::EPOLL_CTL, 4);
    set(&mut a, nr::TGKILL, 3);
    set(&mut a, nr::UTIMES, 2);
    set(&mut a, nr::SET_MEMPOLICY, 3);
    set(&mut a, nr::GET_MEMPOLICY, 5);
    set(&mut a, nr::MQ_OPEN, 4);
    set(&mut a, nr::MQ_UNLINK, 1);
    set(&mut a, nr::MQ_TIMEDSEND, 5);
    set(&mut a, nr::MQ_TIMEDRECEIVE, 5);
    set(&mut a, nr::MQ_NOTIFY, 2);
    set(&mut a, nr::MQ_GETSETATTR, 3);
    set(&mut a, nr::KEXEC_LOAD, 4);
    set(&mut a, nr::WAITID, 5);
    set(&mut a, nr::ADD_KEY, 5);
    set(&mut a, nr::REQUEST_KEY, 4);
    set(&mut a, nr::KEYCTL, 5);
    set(&mut a, nr::IOPRIO_SET, 3);
    set(&mut a, nr::IOPRIO_GET, 2);
    set(&mut a, nr::INOTIFY_INIT, 0);
    set(&mut a, nr::INOTIFY_ADD_WATCH, 3);
    set(&mut a, nr::INOTIFY_RM_WATCH, 2);
    set(&mut a, nr::MIGRATE_PAGES, 4);
    set(&mut a, nr::OPENAT, 4);
    set(&mut a, nr::MKDIRAT, 3);
    set(&mut a, nr::MKNODAT, 4);
    set(&mut a, nr::FCHOWNAT, 5);
    set(&mut a, nr::FUTIMESAT, 3);
    set(&mut a, nr::NEWFSTATAT, 4);
    set(&mut a, nr::UNLINKAT, 3);
    set(&mut a, nr::RENAMEAT, 4);
    set(&mut a, nr::LINKAT, 5);
    set(&mut a, nr::SYMLINKAT, 3);
    set(&mut a, nr::READLINKAT, 4);
    set(&mut a, nr::FCHMODAT, 3);
    set(&mut a, nr::FACCESSAT, 3);
    set(&mut a, nr::PPOLL, 5);
    set(&mut a, nr::UNSHARE, 1);
    set(&mut a, nr::SET_ROBUST_LIST, 2);
    set(&mut a, nr::GET_ROBUST_LIST, 3);
    set(&mut a, nr::TEE, 4);
    set(&mut a, nr::SYNC_FILE_RANGE, 4);
    set(&mut a, nr::VMSPLICE, 4);
    set(&mut a, nr::UTIMENSAT, 4);
    set(&mut a, nr::SIGNALFD, 3);
    set(&mut a, nr::TIMERFD_CREATE, 2);
    set(&mut a, nr::EVENTFD, 1);
    set(&mut a, nr::FALLOCATE, 4);
    set(&mut a, nr::TIMERFD_SETTIME, 4);
    set(&mut a, nr::TIMERFD_GETTIME, 2);
    set(&mut a, nr::ACCEPT4, 4);
    set(&mut a, nr::SIGNALFD4, 4);
    set(&mut a, nr::EVENTFD2, 2);
    set(&mut a, nr::EPOLL_CREATE1, 1);
    set(&mut a, nr::DUP3, 3);
    set(&mut a, nr::PIPE2, 2);
    set(&mut a, nr::INOTIFY_INIT1, 1);
    set(&mut a, nr::PREADV, 5);
    set(&mut a, nr::PWRITEV, 5);
    set(&mut a, nr::RT_TGSIGQUEUEINFO, 4);
    set(&mut a, nr::PERF_EVENT_OPEN, 5);
    set(&mut a, nr::RECVMMSG, 5);
    set(&mut a, nr::FANOTIFY_INIT, 2);
    set(&mut a, nr::FANOTIFY_MARK, 5);
    set(&mut a, nr::PRLIMIT64, 4);
    set(&mut a, nr::NAME_TO_HANDLE_AT, 5);
    set(&mut a, nr::OPEN_BY_HANDLE_AT, 3);
    set(&mut a, nr::CLOCK_ADJTIME, 2);
    set(&mut a, nr::SYNCFS, 1);
    set(&mut a, nr::SENDMMSG, 4);
    set(&mut a, nr::SETNS, 2);
    set(&mut a, nr::GETCPU, 3);
    set(&mut a, nr::KCMP, 5);
    set(&mut a, nr::FINIT_MODULE, 3);
    set(&mut a, nr::SCHED_SETATTR, 3);
    set(&mut a, nr::SCHED_GETATTR, 4);
    set(&mut a, nr::RENAMEAT2, 5);
    set(&mut a, nr::SECCOMP, 3);
    set(&mut a, nr::GETRANDOM, 3);
    set(&mut a, nr::MEMFD_CREATE, 2);
    set(&mut a, nr::KEXEC_FILE_LOAD, 5);
    set(&mut a, nr::BPF, 3);
    set(&mut a, nr::EXECVEAT, 5);
    set(&mut a, nr::USERFAULTFD, 1);
    set(&mut a, nr::MEMBARRIER, 3);
    set(&mut a, nr::MLOCK2, 3);
    set(&mut a, nr::PKEY_MPROTECT, 4);
    set(&mut a, nr::PKEY_ALLOC, 2);
    set(&mut a, nr::PKEY_FREE, 1);
    set(&mut a, nr::STATX, 5);
    set(&mut a, nr::RSEQ, 4);
    set(&mut a, nr::URETPROBE, 0);
    set(&mut a, nr::UPROBE, 0);
    set(&mut a, nr::PIDFD_SEND_SIGNAL, 4);
    set(&mut a, nr::IO_URING_SETUP, 2);
    set(&mut a, nr::IO_URING_REGISTER, 4);
    set(&mut a, nr::OPEN_TREE, 3);
    set(&mut a, nr::MOVE_MOUNT, 5);
    set(&mut a, nr::FSOPEN, 2);
    set(&mut a, nr::FSCONFIG, 5);
    set(&mut a, nr::FSMOUNT, 3);
    set(&mut a, nr::FSPICK, 3);
    set(&mut a, nr::PIDFD_OPEN, 2);
    set(&mut a, nr::CLONE3, 2);
    set(&mut a, nr::CLOSE_RANGE, 3);
    set(&mut a, nr::OPENAT2, 4);
    set(&mut a, nr::PIDFD_GETFD, 3);
    set(&mut a, nr::FACCESSAT2, 4);
    set(&mut a, nr::PROCESS_MADVISE, 5);
    set(&mut a, nr::MOUNT_SETATTR, 5);
    set(&mut a, nr::QUOTACTL_FD, 4);
    set(&mut a, nr::LANDLOCK_CREATE_RULESET, 3);
    set(&mut a, nr::LANDLOCK_ADD_RULE, 4);
    set(&mut a, nr::LANDLOCK_RESTRICT_SELF, 2);
    set(&mut a, nr::MEMFD_SECRET, 1);
    set(&mut a, nr::PROCESS_MRELEASE, 2);
    set(&mut a, nr::FUTEX_WAITV, 5);
    set(&mut a, nr::SET_MEMPOLICY_HOME_NODE, 4);
    set(&mut a, nr::CACHESTAT, 4);
    set(&mut a, nr::FCHMODAT2, 4);
    set(&mut a, nr::MAP_SHADOW_STACK, 3);
    set(&mut a, nr::FUTEX_WAKE, 4);
    set(&mut a, nr::FUTEX_REQUEUE, 4);
    set(&mut a, nr::STATMOUNT, 4);
    set(&mut a, nr::LISTMOUNT, 4);
    set(&mut a, nr::LSM_GET_SELF_ATTR, 4);
    set(&mut a, nr::LSM_SET_SELF_ATTR, 4);
    set(&mut a, nr::LSM_LIST_MODULES, 3);
    set(&mut a, nr::MSEAL, 3);
    set(&mut a, nr::LISTXATTRAT, 5);
    set(&mut a, nr::REMOVEXATTRAT, 4);
    set(&mut a, nr::OPEN_TREE_ATTR, 5);
    set(&mut a, nr::FILE_GETATTR, 5);
    set(&mut a, nr::FILE_SETATTR, 5);
    set(&mut a, nr::LISTNS, 4);
    a
};

/// Bit `i` set: call `nr` reads argument `i`, given the values in `a`.
pub fn live(nr: u64, a: &[u64; 6]) -> u8 {
    let n = if (nr as usize) < NR_COUNT {
        NARGS[nr as usize]
    } else if nr == crate::sdk::SYSCALL {
        3
    } else {
        6
    };
    (((1u16 << n) - 1) as u8) & !dead(nr, a)
}

/// The arguments of call `nr` it reads (`live`); the rest are zero.
pub fn used_args(nr: u64, args: &[u64; 6]) -> [u64; 6] {
    let m = live(nr, args);
    let mut r = [0u64; 6];
    for (i, v) in r.iter_mut().enumerate() {
        if m & (1 << i) != 0 {
            *v = args[i];
        }
    }
    r
}

const fn bit(i: usize) -> u8 {
    1 << i
}

/// Arguments `from..6`.
const fn from(i: usize) -> u8 {
    !((1u8 << i) - 1)
}

const O_CREAT: u64 = 0o100;
/// `__O_TMPFILE` (`O_TMPFILE` is it with `O_DIRECTORY`); the same value on x86_64 and arm64.
const O_TMPFILE_BIT: u64 = 0o20_000_000;
const S_IFMT: u64 = 0o170_000;
const S_IFCHR: u64 = 0o020_000;
const S_IFBLK: u64 = 0o060_000;
const MAP_ANONYMOUS: u64 = 0x20;
const MREMAP_FIXED: u64 = 2;
const MREMAP_DONTUNMAP: u64 = 4;
const EPOLL_CTL_DEL: u64 = 2;
const TIMER_ABSTIME: u64 = 1;
const CLONE_SETTLS: u64 = 0x8_0000;
const CLONE_PARENT_SETTID: u64 = 0x10_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x20_0000;
const CLONE_CHILD_SETTID: u64 = 0x100_0000;
const CLONE_PIDFD: u64 = 0x1000;
/// `clone`'s argument order: x86_64 `(flags, stack, ptid, ctid, tls)`, arm64
/// (`CONFIG_CLONE_BACKWARDS`) `(flags, stack, ptid, tls, ctid)`.
#[cfg(target_arch = "x86_64")]
const CLONE_CTID: usize = 3;
#[cfg(target_arch = "x86_64")]
const CLONE_TLS: usize = 4;
#[cfg(target_arch = "aarch64")]
const CLONE_CTID: usize = 4;
#[cfg(target_arch = "aarch64")]
const CLONE_TLS: usize = 3;

/// The arguments call `nr` has but does not read, for the values of the others in `a`.
fn dead(nr: u64, a: &[u64; 6]) -> u8 {
    if let Some((first, uses)) = super::cmds::args_of(nr, a) {
        let mut d = from(first + uses.len());
        if nr == nr::PRCTL
            && a[0] == super::cmds::PR_SET_VMA
            && a[1] != super::cmds::PR_SET_VMA_ANON_NAME
        {
            d |= from(2); // any other sub-option is EINVAL before the rest is read
        }
        return d;
    }
    match nr {
        // The new address only with MREMAP_FIXED or MREMAP_DONTUNMAP (`vrm_implies_new_addr`).
        nr::MREMAP if a[3] & (MREMAP_FIXED | MREMAP_DONTUNMAP) == 0 => bit(4),
        // The descriptor of an anonymous mapping (`ksys_mmap_pgoff`); the offset is still
        // checked (alignment, overflow).
        nr::MMAP if a[3] & MAP_ANONYMOUS != 0 => bit(4),
        // The mode only when creating (`WILL_CREATE`: O_CREAT or __O_TMPFILE).
        nr::OPEN if a[1] & (O_CREAT | O_TMPFILE_BIT) == 0 => bit(2),
        nr::OPENAT if a[2] & (O_CREAT | O_TMPFILE_BIT) == 0 => bit(3),
        // The device number only for a character or block device (`filename_mknodat`).
        nr::MKNOD if !matches!(a[1] & S_IFMT, S_IFCHR | S_IFBLK) => bit(2),
        nr::MKNODAT if !matches!(a[2] & S_IFMT, S_IFCHR | S_IFBLK) => bit(3),
        // The event is not read for EPOLL_CTL_DEL (`ep_op_has_event`).
        nr::EPOLL_CTL if a[1] as u32 as u64 == EPOLL_CTL_DEL => bit(3),
        // The signal set's size only with a set (`set_user_sigmask`).
        nr::PPOLL if a[3] == 0 => bit(4),
        nr::EPOLL_PWAIT | nr::EPOLL_PWAIT2 if a[4] == 0 => bit(5),
        // The address length only with an address (`__sys_sendto`, `__sys_recvfrom`, `do_accept`).
        nr::SENDTO | nr::RECVFROM if a[4] == 0 => bit(5),
        nr::ACCEPT | nr::ACCEPT4 if a[1] == 0 => bit(2),
        // No remaining time for an absolute sleep (`clock_nanosleep` clears `rmtp`).
        nr::CLOCK_NANOSLEEP if a[1] & TIMER_ABSTIME != 0 => bit(3),
        // The high half of the offset: on a 64-bit kernel `pos_from_hilo` shifts it out.
        nr::PREADV | nr::PWRITEV | nr::PREADV2 | nr::PWRITEV2 => bit(4),
        // The third argument is named `unused`.
        nr::GETCPU => bit(2),
        nr::CLONE => {
            let f = a[0];
            let mut d = 0;
            if f & (CLONE_PARENT_SETTID | CLONE_PIDFD) == 0 {
                d |= bit(2);
            }
            if f & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) == 0 {
                d |= bit(CLONE_CTID);
            }
            if f & CLONE_SETTLS == 0 {
                d |= bit(CLONE_TLS);
            }
            d
        }
        nr::FUTEX => futex_dead(a[1]),
        crate::sdk::SYSCALL => match a[0] {
            crate::sdk::OP_ASSERT..=crate::sdk::OP_DECLARE => 0,
            crate::sdk::OP_COMPUTE_HELLO => bit(2),
            // HELLO and anything else read only the operation.
            _ => from(1),
        },
        _ => 0,
    }
}

/// `futex(uaddr, op, val, timeout or val2, uaddr2, val3)` by command (`do_futex`, and
/// `futex_cmd_has_timeout` for the timeout). The PI commands are refused, reading nothing more.
fn futex_dead(op: u64) -> u8 {
    match op & 0x7f {
        0 => from(4),          // FUTEX_WAIT: uaddr, val, timeout
        1 => from(3),          // FUTEX_WAKE: uaddr, val
        3 => bit(5),           // FUTEX_REQUEUE: uaddr, val, val2, uaddr2
        4 | 5 => 0,            // FUTEX_CMP_REQUEUE, FUTEX_WAKE_OP: all six
        9 => bit(4),           // FUTEX_WAIT_BITSET: uaddr, val, timeout, val3
        10 => bit(3) | bit(4), // FUTEX_WAKE_BITSET: uaddr, val, val3
        _ => from(2),          // refused (PI) or unknown: ENOSYS
    }
}
