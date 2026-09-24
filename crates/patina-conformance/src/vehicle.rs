//! The three vehicles a scenario issues its system calls through.
//!
//! A scenario is written once against [`crate::probe::Probe`]; the vehicle
//! decides HOW the kernel (or patina's dispatcher) is reached:
//!
//! * `libc` — the glibc symbol of the same name (`openat`, `fstatat`, …). Under
//!   patina this is the C interposer layer.
//! * `syscall` — glibc's `syscall(2)` wrapper with the registry row's number.
//!   Under patina this is the shim's `syscall` interposer.
//! * `raw` — an inline-asm `syscall` instruction (x86_64 only). Under patina
//!   this is the SUD dispatcher.
//!
//! Rows are the registry's typed [`Syscall`] identities, so a number never
//! comes from a second table and a row the architecture lacks does not exist
//! to be issued. Every vehicle returns the kernel convention: `>= 0` on
//! success, `-errno` on failure.

use patina_dst_syscalls::Syscall;
use std::ffi::c_long;

/// Six register-sized arguments, the kernel ABI's maximum.
pub type Args = [i64; 6];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vehicle {
    Libc,
    Syscall,
    #[cfg(target_arch = "x86_64")]
    Raw,
}

impl Vehicle {
    /// Every vehicle this architecture has.
    pub const ALL: &'static [Vehicle] = &[
        Vehicle::Libc,
        Vehicle::Syscall,
        #[cfg(target_arch = "x86_64")]
        Vehicle::Raw,
    ];

    pub fn parse(text: &str) -> Option<Vehicle> {
        Vehicle::ALL
            .iter()
            .copied()
            .find(|vehicle| vehicle.name() == text)
    }

    pub fn name(self) -> &'static str {
        match self {
            Vehicle::Libc => "libc",
            Vehicle::Syscall => "syscall",
            #[cfg(target_arch = "x86_64")]
            Vehicle::Raw => "raw",
        }
    }

    /// Issue `row` with `args`; kernel-style result (`-errno` on failure).
    pub fn call(self, row: Syscall, args: Args) -> i64 {
        match self {
            Vehicle::Libc => libc_door(row, args),
            Vehicle::Syscall => fold_errno(syscall_door(row, args)),
            #[cfg(target_arch = "x86_64")]
            Vehicle::Raw => raw_syscall(row.number(), args),
        }
    }
}

pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Fold a libc-style result (`-1` + errno) into the kernel convention.
pub fn fold_errno(result: i64) -> i64 {
    if result == -1 {
        -(errno() as i64)
    } else {
        result
    }
}

/// glibc's `syscall(2)` with the row's number.
fn syscall_door(row: Syscall, a: Args) -> i64 {
    // SAFETY: the scenario owns every pointer it passes in `a`.
    unsafe {
        libc::syscall(
            row.number() as c_long,
            a[0] as c_long,
            a[1] as c_long,
            a[2] as c_long,
            a[3] as c_long,
            a[4] as c_long,
            a[5] as c_long,
        ) as i64
    }
}

// glibc exports `futimesat` (deprecated, still a strong symbol) and
// `getdents64`; the libc crate declares neither.
unsafe extern "C" {
    pub(crate) fn futimesat(
        dirfd: libc::c_int,
        path: *const libc::c_char,
        times: *const libc::timeval,
    ) -> libc::c_int;
    fn getdents64(fd: libc::c_int, buffer: *mut libc::c_void, length: libc::size_t) -> isize;
}

/// The glibc symbol of the same name, folded to the kernel result convention.
/// A row glibc has no wrapper for is spelled `syscall(2)`, the same door glibc
/// itself would use.
fn libc_door(row: Syscall, a: Args) -> i64 {
    use libc::*;
    // SAFETY: the scenario owns every pointer it passes in `a`.
    let result: i64 = unsafe {
        match row {
            Syscall::N_read => read(a[0] as c_int, a[1] as *mut c_void, a[2] as size_t) as i64,
            Syscall::N_write => write(a[0] as c_int, a[1] as *const c_void, a[2] as size_t) as i64,
            Syscall::N_openat => openat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as c_int,
                a[3] as c_uint,
            ) as i64,
            Syscall::N_close => close(a[0] as c_int) as i64,
            Syscall::N_lseek => lseek(a[0] as c_int, a[1] as off_t, a[2] as c_int) as i64,
            Syscall::N_fstat => fstat(a[0] as c_int, a[1] as *mut stat) as i64,
            Syscall::N_newfstatat => fstatat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as *mut stat,
                a[3] as c_int,
            ) as i64,
            Syscall::N_statx => statx(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as c_int,
                a[3] as c_uint,
                a[4] as *mut statx,
            ) as i64,
            Syscall::N_getdents64 => {
                getdents64(a[0] as c_int, a[1] as *mut c_void, a[2] as size_t) as i64
            }
            Syscall::N_mkdirat => {
                mkdirat(a[0] as c_int, a[1] as *const c_char, a[2] as mode_t) as i64
            }
            Syscall::N_unlinkat => {
                unlinkat(a[0] as c_int, a[1] as *const c_char, a[2] as c_int) as i64
            }
            Syscall::N_renameat => renameat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as c_int,
                a[3] as *const c_char,
            ) as i64,
            Syscall::N_symlinkat => {
                symlinkat(a[0] as *const c_char, a[1] as c_int, a[2] as *const c_char) as i64
            }
            Syscall::N_readlinkat => readlinkat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as *mut c_char,
                a[3] as size_t,
            ) as i64,
            Syscall::N_linkat => linkat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as c_int,
                a[3] as *const c_char,
                a[4] as c_int,
            ) as i64,
            Syscall::N_pipe2 => pipe2(a[0] as *mut c_int, a[1] as c_int) as i64,
            Syscall::N_dup => dup(a[0] as c_int) as i64,
            Syscall::N_dup3 => dup3(a[0] as c_int, a[1] as c_int, a[2] as c_int) as i64,
            Syscall::N_close_range => {
                close_range(a[0] as c_uint, a[1] as c_uint, a[2] as c_int) as i64
            }
            Syscall::N_fcntl => fcntl(a[0] as c_int, a[1] as c_int, a[2] as c_long) as i64,
            Syscall::N_flock => flock(a[0] as c_int, a[1] as c_int) as i64,
            Syscall::N_clock_gettime => {
                clock_gettime(a[0] as clockid_t, a[1] as *mut timespec) as i64
            }
            Syscall::N_gettimeofday => {
                gettimeofday(a[0] as *mut timeval, a[1] as *mut timezone) as i64
            }
            Syscall::N_nanosleep => {
                nanosleep(a[0] as *const timespec, a[1] as *mut timespec) as i64
            }
            Syscall::N_clock_nanosleep => {
                // The one wrapper that returns the errno instead of -1 + errno.
                let code = clock_nanosleep(
                    a[0] as clockid_t,
                    a[1] as c_int,
                    a[2] as *const timespec,
                    a[3] as *mut timespec,
                );
                return if code == 0 { 0 } else { -(code as i64) };
            }
            Syscall::N_getrandom => {
                getrandom(a[0] as *mut c_void, a[1] as size_t, a[2] as c_uint) as i64
            }
            Syscall::N_socket => socket(a[0] as c_int, a[1] as c_int, a[2] as c_int) as i64,
            Syscall::N_bind => {
                bind(a[0] as c_int, a[1] as *const sockaddr, a[2] as socklen_t) as i64
            }
            Syscall::N_listen => listen(a[0] as c_int, a[1] as c_int) as i64,
            Syscall::N_connect => {
                connect(a[0] as c_int, a[1] as *const sockaddr, a[2] as socklen_t) as i64
            }
            Syscall::N_accept4 => accept4(
                a[0] as c_int,
                a[1] as *mut sockaddr,
                a[2] as *mut socklen_t,
                a[3] as c_int,
            ) as i64,
            Syscall::N_sendto => sendto(
                a[0] as c_int,
                a[1] as *const c_void,
                a[2] as size_t,
                a[3] as c_int,
                a[4] as *const sockaddr,
                a[5] as socklen_t,
            ) as i64,
            Syscall::N_recvfrom => recvfrom(
                a[0] as c_int,
                a[1] as *mut c_void,
                a[2] as size_t,
                a[3] as c_int,
                a[4] as *mut sockaddr,
                a[5] as *mut socklen_t,
            ) as i64,
            Syscall::N_getsockname => {
                getsockname(a[0] as c_int, a[1] as *mut sockaddr, a[2] as *mut socklen_t) as i64
            }
            Syscall::N_getpeername => {
                getpeername(a[0] as c_int, a[1] as *mut sockaddr, a[2] as *mut socklen_t) as i64
            }
            Syscall::N_shutdown => shutdown(a[0] as c_int, a[1] as c_int) as i64,
            Syscall::N_setsockopt => setsockopt(
                a[0] as c_int,
                a[1] as c_int,
                a[2] as c_int,
                a[3] as *const c_void,
                a[4] as socklen_t,
            ) as i64,
            Syscall::N_getsockopt => getsockopt(
                a[0] as c_int,
                a[1] as c_int,
                a[2] as c_int,
                a[3] as *mut c_void,
                a[4] as *mut socklen_t,
            ) as i64,
            Syscall::N_socketpair => socketpair(
                a[0] as c_int,
                a[1] as c_int,
                a[2] as c_int,
                a[3] as *mut c_int,
            ) as i64,
            Syscall::N_epoll_create1 => epoll_create1(a[0] as c_int) as i64,
            Syscall::N_epoll_ctl => epoll_ctl(
                a[0] as c_int,
                a[1] as c_int,
                a[2] as c_int,
                a[3] as *mut epoll_event,
            ) as i64,
            Syscall::N_eventfd2 => eventfd(a[0] as c_uint, a[1] as c_int) as i64,
            Syscall::N_ppoll => ppoll(
                a[0] as *mut pollfd,
                a[1] as nfds_t,
                a[2] as *const timespec,
                a[3] as *const sigset_t,
            ) as i64,
            Syscall::N_sigaltstack => {
                sigaltstack(a[0] as *const stack_t, a[1] as *mut stack_t) as i64
            }
            Syscall::N_kill => kill(a[0] as pid_t, a[1] as c_int) as i64,
            Syscall::N_getpid => getpid() as i64,
            Syscall::N_getppid => getppid() as i64,
            Syscall::N_getuid => getuid() as i64,
            Syscall::N_getgid => getgid() as i64,
            Syscall::N_prctl => prctl(
                a[0] as c_int,
                a[1] as c_ulong,
                a[2] as c_ulong,
                a[3] as c_ulong,
                a[4] as c_ulong,
            ) as i64,
            Syscall::N_waitid => waitid(
                a[0] as idtype_t,
                a[1] as id_t,
                a[2] as *mut siginfo_t,
                a[3] as c_int,
            ) as i64,
            // getcwd(3) answers a pointer; the kernel row answers a length. The
            // probe API records success as 0 on every vehicle, so the libc
            // spelling folds the pointer to 0 here.
            Syscall::N_getcwd => {
                if getcwd(a[0] as *mut c_char, a[1] as size_t).is_null() {
                    -1
                } else {
                    0
                }
            }
            Syscall::N_chdir => chdir(a[0] as *const c_char) as i64,
            Syscall::N_fchdir => fchdir(a[0] as c_int) as i64,
            // umask(2) never fails and its result is the previous mask; no
            // errno fold applies.
            Syscall::N_umask => return i64::from(umask(a[0] as mode_t)),
            Syscall::N_mknodat => mknodat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as mode_t,
                a[3] as dev_t,
            ) as i64,
            Syscall::N_faccessat => faccessat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as c_int,
                a[3] as c_int,
            ) as i64,
            // glibc's utimensat refuses a null path (EINVAL) and spells the
            // kernel's descriptor shape as futimens(3), so that is the libc
            // spelling of utimensat(fd, NULL, times, 0).
            Syscall::N_utimensat if a[1] == 0 && a[3] == 0 => {
                futimens(a[0] as c_int, a[2] as *const timespec) as i64
            }
            Syscall::N_utimensat => utimensat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as *const timespec,
                a[3] as c_int,
            ) as i64,
            Syscall::N_fchown => fchown(a[0] as c_int, a[1] as uid_t, a[2] as gid_t) as i64,
            Syscall::N_fchownat => fchownat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as uid_t,
                a[3] as gid_t,
                a[4] as c_int,
            ) as i64,
            Syscall::N_truncate => truncate(a[0] as *const c_char, a[1] as off_t) as i64,
            Syscall::N_ftruncate => ftruncate(a[0] as c_int, a[1] as off_t) as i64,
            Syscall::N_fallocate => {
                fallocate(a[0] as c_int, a[1] as c_int, a[2] as off_t, a[3] as off_t) as i64
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::N_dup2 => dup2(a[0] as c_int, a[1] as c_int) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_epoll_wait => epoll_wait(
                a[0] as c_int,
                a[1] as *mut epoll_event,
                a[2] as c_int,
                a[3] as c_int,
            ) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_pause => pause() as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_access => access(a[0] as *const c_char, a[1] as c_int) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_utime => utime(a[0] as *const c_char, a[1] as *const utimbuf) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_utimes => utimes(a[0] as *const c_char, a[1] as *const timeval) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_futimesat => {
                futimesat(a[0] as c_int, a[1] as *const c_char, a[2] as *const timeval) as i64
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::N_chown => chown(a[0] as *const c_char, a[1] as uid_t, a[2] as gid_t) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_lchown => lchown(a[0] as *const c_char, a[1] as uid_t, a[2] as gid_t) as i64,
            // No glibc wrapper: the futex word, the signal rows (glibc's
            // wrappers take its own struct layouts), tkill/tgkill, the thread
            // and process-lifecycle rows (`_exit(2)` is not interposed, so its
            // import would be refused), faccessat2 (glibc's faccessat emulates
            // the flags over it), removed numbers, and numbers past the
            // virtual ABI level.
            Syscall::N_futex
            | Syscall::N_rt_sigaction
            | Syscall::N_rt_sigprocmask
            | Syscall::N_rt_sigpending
            | Syscall::N_rt_sigtimedwait
            | Syscall::N_rt_sigsuspend
            | Syscall::N_rt_sigqueueinfo
            | Syscall::N_rt_tgsigqueueinfo
            | Syscall::N_signalfd4
            | Syscall::N_tkill
            | Syscall::N_tgkill
            | Syscall::N_gettid
            | Syscall::N_getpgid
            | Syscall::N_getsid
            | Syscall::N_set_tid_address
            | Syscall::N_wait4
            | Syscall::N_clone
            | Syscall::N_clone3
            | Syscall::N_execve
            | Syscall::N_execveat
            | Syscall::N_exit
            | Syscall::N_exit_group
            | Syscall::N_faccessat2
            | Syscall::N_nfsservctl
            | Syscall::N_lookup_dcookie
            | Syscall::N_fchroot => syscall_door(row, a),
            #[cfg(target_arch = "x86_64")]
            Syscall::N_signalfd
            | Syscall::N_fork
            | Syscall::N__sysctl
            | Syscall::N_vserver
            | Syscall::N_security
            | Syscall::N_tuxcall
            | Syscall::N_afs_syscall
            | Syscall::N_getpmsg
            | Syscall::N_putpmsg
            | Syscall::N_epoll_ctl_old
            | Syscall::N_epoll_wait_old
            | Syscall::N_create_module
            | Syscall::N_query_module
            | Syscall::N_get_kernel_syms
            | Syscall::N_uselib => syscall_door(row, a),
            other => panic!("{}: no libc spelling in the probe API", other.name()),
        }
    };
    fold_errno(result)
}

/// The inline `syscall` instruction: the exact direct-syscall class the
/// import audit cannot see, trapped by SUD under patina.
#[cfg(target_arch = "x86_64")]
fn raw_syscall(nr: u32, a: Args) -> i64 {
    let ret: i64;
    // SAFETY: the scenario owns every pointer it passes in `a`; the kernel
    // clobbers rcx and r11.
    unsafe {
        std::arch::asm!("syscall", inlateout("rax") i64::from(nr) => ret, in("rdi") a[0],
             in("rsi") a[1], in("rdx") a[2], in("r10") a[3], in("r8") a[4], in("r9") a[5],
             out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

/// The errno vocabulary scenarios observe, by name (arch-independent and
/// readable in a report). Unknown numbers print as `E#n`.
pub fn errno_name(code: i32) -> String {
    let name = match code {
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::EINTR => "EINTR",
        libc::EIO => "EIO",
        libc::ENXIO => "ENXIO",
        libc::E2BIG => "E2BIG",
        libc::ECHILD => "ECHILD",
        libc::EBADF => "EBADF",
        libc::EAGAIN => "EAGAIN",
        libc::ENOMEM => "ENOMEM",
        libc::EACCES => "EACCES",
        libc::EFAULT => "EFAULT",
        libc::EBUSY => "EBUSY",
        libc::EEXIST => "EEXIST",
        libc::EXDEV => "EXDEV",
        libc::ENODEV => "ENODEV",
        libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR",
        libc::EINVAL => "EINVAL",
        libc::ENFILE => "ENFILE",
        libc::EMFILE => "EMFILE",
        libc::ENOTTY => "ENOTTY",
        libc::EFBIG => "EFBIG",
        libc::ENOSPC => "ENOSPC",
        libc::ESPIPE => "ESPIPE",
        libc::EROFS => "EROFS",
        libc::EMLINK => "EMLINK",
        libc::EPIPE => "EPIPE",
        libc::ERANGE => "ERANGE",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ENOSYS => "ENOSYS",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::ELOOP => "ELOOP",
        libc::ENOTSOCK => "ENOTSOCK",
        libc::EDESTADDRREQ => "EDESTADDRREQ",
        libc::EMSGSIZE => "EMSGSIZE",
        libc::EPROTOTYPE => "EPROTOTYPE",
        libc::ENOPROTOOPT => "ENOPROTOOPT",
        libc::EPROTONOSUPPORT => "EPROTONOSUPPORT",
        libc::ESOCKTNOSUPPORT => "ESOCKTNOSUPPORT",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::EADDRINUSE => "EADDRINUSE",
        libc::EADDRNOTAVAIL => "EADDRNOTAVAIL",
        libc::ENETUNREACH => "ENETUNREACH",
        libc::ECONNABORTED => "ECONNABORTED",
        libc::ECONNRESET => "ECONNRESET",
        libc::ENOBUFS => "ENOBUFS",
        libc::EISCONN => "EISCONN",
        libc::ENOTCONN => "ENOTCONN",
        libc::ETIMEDOUT => "ETIMEDOUT",
        libc::ECONNREFUSED => "ECONNREFUSED",
        libc::EHOSTUNREACH => "EHOSTUNREACH",
        libc::EALREADY => "EALREADY",
        libc::EINPROGRESS => "EINPROGRESS",
        libc::EOVERFLOW => "EOVERFLOW",
        libc::ENODATA => "ENODATA",
        _ => return format!("E#{code}"),
    };
    name.to_string()
}
