//! The three vehicles a probe issues its system calls through.
//!
//! A probe body is written once against [`Vehicle::call`]; the vehicle decides
//! HOW the kernel (or patina's dispatcher) is reached:
//!
//! * `libc` — the glibc symbol of the same name (`openat`, `fstatat`, …). Under
//!   patina this is the C interposer layer.
//! * `syscall` — glibc's `syscall(2)` wrapper with the number from `libc::SYS_*`.
//!   Under patina this is the shim's `syscall` interposer.
//! * `raw` — an inline-asm `syscall` instruction, x86_64 Linux only until the
//!   arm64 `svc` variant lands. Under patina this is the SUD dispatcher.
//!
//! Every vehicle returns the kernel convention: `>= 0` on success, `-errno` on
//! failure. The libc vehicle folds `-1 + errno` into that shape so probes and the
//! recorder never branch on the vehicle.

#![allow(deprecated)]

use std::ffi::c_long;

/// Six register-sized arguments, the kernel ABI's maximum.
pub type Args = [i64; 6];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vehicle {
    Libc,
    Syscall,
    Raw,
}

impl Vehicle {
    pub const ALL: [Vehicle; 3] = [Vehicle::Libc, Vehicle::Syscall, Vehicle::Raw];

    pub fn parse(text: &str) -> Option<Vehicle> {
        match text {
            "libc" => Some(Vehicle::Libc),
            "syscall" => Some(Vehicle::Syscall),
            "raw" => Some(Vehicle::Raw),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Vehicle::Libc => "libc",
            Vehicle::Syscall => "syscall",
            Vehicle::Raw => "raw",
        }
    }

    /// Whether this build can issue calls through the vehicle at all. `raw` is
    /// compiled only for x86_64 Linux; a probe asked for it elsewhere exits with
    /// [`crate::probe::EXIT_VEHICLE_UNAVAILABLE`] so the runner counts a skip,
    /// never a pass.
    pub fn available(self) -> bool {
        match self {
            Vehicle::Raw => cfg!(all(target_os = "linux", target_arch = "x86_64")),
            Vehicle::Libc | Vehicle::Syscall => true,
        }
    }

    /// Issue `sys` with `args`; kernel-style result (`-errno` on failure).
    pub fn call(self, sys: Sys, args: Args) -> i64 {
        match self {
            Vehicle::Libc => libc_symbol(sys, args),
            Vehicle::Syscall => {
                let (nr, args) = sys.require_number_and_args(args);
                let result = unsafe {
                    libc::syscall(
                        nr,
                        args[0] as c_long,
                        args[1] as c_long,
                        args[2] as c_long,
                        args[3] as c_long,
                        args[4] as c_long,
                        args[5] as c_long,
                    )
                };
                if result == -1 {
                    -(errno() as i64)
                } else {
                    result as i64
                }
            }
            Vehicle::Raw => {
                let (nr, args) = sys.require_number_and_args(args);
                // c_long is i64 on every arch the raw vehicle exists for.
                #[allow(clippy::unnecessary_cast)]
                raw::syscall6(nr as i64, args)
            }
        }
    }
}

/// The rows the initial probe set covers. `name` is the kernel's spelling (the
/// registry key); `number_and_args` maps to the arch's number, injecting the
/// arguments the arch's only spelling needs (aarch64 has no `epoll_wait`, only
/// `epoll_pwait` with a NULL sigmask).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Sys {
    Read,
    Write,
    Openat,
    Close,
    Lseek,
    Fstat,
    Newfstatat,
    Statx,
    Getdents64,
    Mkdirat,
    Unlinkat,
    Renameat,
    Symlinkat,
    Readlinkat,
    Linkat,
    Pipe2,
    Dup,
    Dup2,
    Dup3,
    CloseRange,
    Fcntl,
    Flock,
    ClockGettime,
    Gettimeofday,
    Nanosleep,
    ClockNanosleep,
    Getrandom,
    Socket,
    Bind,
    Listen,
    Connect,
    Accept4,
    Sendto,
    Recvfrom,
    Getsockname,
    Getpeername,
    Shutdown,
    Setsockopt,
    Getsockopt,
    EpollCreate1,
    EpollCtl,
    EpollWait,
    Eventfd2,
    Ppoll,
    Futex,
    RtSigaction,
    RtSigprocmask,
    RtSigpending,
    RtSigtimedwait,
    RtSigsuspend,
    Sigaltstack,
    Kill,
    Tkill,
    Tgkill,
    Signalfd,
    Signalfd4,
    RtSigqueueinfo,
    RtTgsigqueueinfo,
    Getpid,
    Gettid,
    Getppid,
    Getpgid,
    Getsid,
    Getuid,
    Getgid,
    SetTidAddress,
    Prctl,
    Wait4,
    Waitid,
    Clone,
    Clone3,
    Fork,
    Vfork,
    Execve,
    Execveat,
    Exit,
    ExitGroup,
    Pause,
    Socketpair,
    Getcwd,
    Chdir,
    Fchdir,
    Umask,
    Mknodat,
    Access,
    Faccessat,
    Faccessat2,
    Utimensat,
    Utime,
    Utimes,
    Futimesat,
    Chown,
    Fchown,
    Lchown,
    Fchownat,
    Truncate,
    Ftruncate,
    Fallocate,
    Sysctl,
    Nfsservctl,
    Vserver,
    Security,
    Tuxcall,
    AfsSyscall,
    Getpmsg,
    Putpmsg,
    EpollCtlOld,
    EpollWaitOld,
    LookupDcookie,
    CreateModule,
    QueryModule,
    GetKernelSyms,
    Uselib,
    /// A number past the virtual ABI level (registry `since` 7.3 > 6.8): the
    /// probe asserts its absence, not its semantics.
    Fchroot,
}

impl Sys {
    pub fn name(self) -> &'static str {
        match self {
            Sys::Read => "read",
            Sys::Write => "write",
            Sys::Openat => "openat",
            Sys::Close => "close",
            Sys::Lseek => "lseek",
            Sys::Fstat => "fstat",
            Sys::Newfstatat => "newfstatat",
            Sys::Statx => "statx",
            Sys::Getdents64 => "getdents64",
            Sys::Mkdirat => "mkdirat",
            Sys::Unlinkat => "unlinkat",
            Sys::Renameat => "renameat",
            Sys::Symlinkat => "symlinkat",
            Sys::Readlinkat => "readlinkat",
            Sys::Linkat => "linkat",
            Sys::Pipe2 => "pipe2",
            Sys::Dup => "dup",
            Sys::Dup2 => "dup2",
            Sys::Dup3 => "dup3",
            Sys::CloseRange => "close_range",
            Sys::Fcntl => "fcntl",
            Sys::Flock => "flock",
            Sys::ClockGettime => "clock_gettime",
            Sys::Gettimeofday => "gettimeofday",
            Sys::Nanosleep => "nanosleep",
            Sys::ClockNanosleep => "clock_nanosleep",
            Sys::Getrandom => "getrandom",
            Sys::Socket => "socket",
            Sys::Bind => "bind",
            Sys::Listen => "listen",
            Sys::Connect => "connect",
            Sys::Accept4 => "accept4",
            Sys::Sendto => "sendto",
            Sys::Recvfrom => "recvfrom",
            Sys::Getsockname => "getsockname",
            Sys::Getpeername => "getpeername",
            Sys::Shutdown => "shutdown",
            Sys::Setsockopt => "setsockopt",
            Sys::Getsockopt => "getsockopt",
            Sys::EpollCreate1 => "epoll_create1",
            Sys::EpollCtl => "epoll_ctl",
            Sys::EpollWait => "epoll_wait",
            Sys::Eventfd2 => "eventfd2",
            Sys::Ppoll => "ppoll",
            Sys::Futex => "futex",
            Sys::RtSigaction => "rt_sigaction",
            Sys::RtSigprocmask => "rt_sigprocmask",
            Sys::RtSigpending => "rt_sigpending",
            Sys::RtSigtimedwait => "rt_sigtimedwait",
            Sys::RtSigsuspend => "rt_sigsuspend",
            Sys::Sigaltstack => "sigaltstack",
            Sys::Kill => "kill",
            Sys::Tkill => "tkill",
            Sys::Tgkill => "tgkill",
            Sys::Signalfd => "signalfd",
            Sys::Signalfd4 => "signalfd4",
            Sys::RtSigqueueinfo => "rt_sigqueueinfo",
            Sys::RtTgsigqueueinfo => "rt_tgsigqueueinfo",
            Sys::Getpid => "getpid",
            Sys::Gettid => "gettid",
            Sys::Getppid => "getppid",
            Sys::Getpgid => "getpgid",
            Sys::Getsid => "getsid",
            Sys::Getuid => "getuid",
            Sys::Getgid => "getgid",
            Sys::SetTidAddress => "set_tid_address",
            Sys::Prctl => "prctl",
            Sys::Wait4 => "wait4",
            Sys::Waitid => "waitid",
            Sys::Clone => "clone",
            Sys::Clone3 => "clone3",
            Sys::Fork => "fork",
            Sys::Vfork => "vfork",
            Sys::Execve => "execve",
            Sys::Execveat => "execveat",
            Sys::Exit => "exit",
            Sys::ExitGroup => "exit_group",
            Sys::Pause => "pause",
            Sys::Socketpair => "socketpair",
            Sys::Getcwd => "getcwd",
            Sys::Chdir => "chdir",
            Sys::Fchdir => "fchdir",
            Sys::Umask => "umask",
            Sys::Mknodat => "mknodat",
            Sys::Access => "access",
            Sys::Faccessat => "faccessat",
            Sys::Faccessat2 => "faccessat2",
            Sys::Utimensat => "utimensat",
            Sys::Utime => "utime",
            Sys::Utimes => "utimes",
            Sys::Futimesat => "futimesat",
            Sys::Chown => "chown",
            Sys::Fchown => "fchown",
            Sys::Lchown => "lchown",
            Sys::Fchownat => "fchownat",
            Sys::Truncate => "truncate",
            Sys::Ftruncate => "ftruncate",
            Sys::Fallocate => "fallocate",
            Sys::Sysctl => "_sysctl",
            Sys::Nfsservctl => "nfsservctl",
            Sys::Vserver => "vserver",
            Sys::Security => "security",
            Sys::Tuxcall => "tuxcall",
            Sys::AfsSyscall => "afs_syscall",
            Sys::Getpmsg => "getpmsg",
            Sys::Putpmsg => "putpmsg",
            Sys::EpollCtlOld => "epoll_ctl_old",
            Sys::EpollWaitOld => "epoll_wait_old",
            Sys::LookupDcookie => "lookup_dcookie",
            Sys::CreateModule => "create_module",
            Sys::QueryModule => "query_module",
            Sys::GetKernelSyms => "get_kernel_syms",
            Sys::Uselib => "uselib",
            Sys::Fchroot => "fchroot",
        }
    }

    /// Whether this row has a callable number on this architecture. Absence is
    /// not an observed ENOSYS: no kernel call can be issued for such a row.
    pub fn has_number(self) -> bool {
        self.number_and_args([0; 6]).is_some()
    }

    fn require_number_and_args(self, args: Args) -> (c_long, Args) {
        self.number_and_args(args).unwrap_or_else(|| {
            panic!(
                "{}: no syscall number on {}",
                self.name(),
                std::env::consts::ARCH
            )
        })
    }

    /// The syscall number on this arch, plus the argument vector the number's
    /// spelling wants.
    fn number_and_args(self, args: Args) -> Option<(c_long, Args)> {
        let nr = match self {
            Sys::Read => libc::SYS_read,
            Sys::Write => libc::SYS_write,
            Sys::Openat => libc::SYS_openat,
            Sys::Close => libc::SYS_close,
            Sys::Lseek => libc::SYS_lseek,
            Sys::Fstat => libc::SYS_fstat,
            Sys::Newfstatat => libc::SYS_newfstatat,
            Sys::Statx => libc::SYS_statx,
            Sys::Getdents64 => libc::SYS_getdents64,
            Sys::Mkdirat => libc::SYS_mkdirat,
            Sys::Unlinkat => libc::SYS_unlinkat,
            Sys::Renameat => libc::SYS_renameat,
            Sys::Symlinkat => libc::SYS_symlinkat,
            Sys::Readlinkat => libc::SYS_readlinkat,
            Sys::Linkat => libc::SYS_linkat,
            Sys::Pipe2 => libc::SYS_pipe2,
            Sys::Dup => libc::SYS_dup,
            Sys::Dup2 => {
                #[cfg(target_arch = "x86_64")]
                {
                    libc::SYS_dup2
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    // Generic-table arches carry only dup3; dup2's distinct
                    // equal-number semantics are asserted by the probe on
                    // x86_64 alone, so the shape here is dup3(old, new, 0).
                    return Some((libc::SYS_dup3, [args[0], args[1], 0, 0, 0, 0]));
                }
            }
            Sys::Dup3 => libc::SYS_dup3,
            Sys::CloseRange => libc::SYS_close_range,
            Sys::Fcntl => libc::SYS_fcntl,
            Sys::Flock => libc::SYS_flock,
            Sys::ClockGettime => libc::SYS_clock_gettime,
            Sys::Gettimeofday => libc::SYS_gettimeofday,
            Sys::Nanosleep => libc::SYS_nanosleep,
            Sys::ClockNanosleep => libc::SYS_clock_nanosleep,
            Sys::Getrandom => libc::SYS_getrandom,
            Sys::Socket => libc::SYS_socket,
            Sys::Bind => libc::SYS_bind,
            Sys::Listen => libc::SYS_listen,
            Sys::Connect => libc::SYS_connect,
            Sys::Accept4 => libc::SYS_accept4,
            Sys::Sendto => libc::SYS_sendto,
            Sys::Recvfrom => libc::SYS_recvfrom,
            Sys::Getsockname => libc::SYS_getsockname,
            Sys::Getpeername => libc::SYS_getpeername,
            Sys::Shutdown => libc::SYS_shutdown,
            Sys::Setsockopt => libc::SYS_setsockopt,
            Sys::Getsockopt => libc::SYS_getsockopt,
            Sys::EpollCreate1 => libc::SYS_epoll_create1,
            Sys::EpollCtl => libc::SYS_epoll_ctl,
            Sys::EpollWait => {
                #[cfg(target_arch = "x86_64")]
                {
                    libc::SYS_epoll_wait
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    // Generic-table arches carry only epoll_pwait; a NULL sigmask
                    // (args[4]) with a zero size (args[5]) is the epoll_wait shape.
                    return Some((
                        libc::SYS_epoll_pwait,
                        [args[0], args[1], args[2], args[3], 0, 0],
                    ));
                }
            }
            Sys::Eventfd2 => libc::SYS_eventfd2,
            Sys::Ppoll => libc::SYS_ppoll,
            Sys::Futex => libc::SYS_futex,
            Sys::RtSigaction => libc::SYS_rt_sigaction,
            Sys::RtSigprocmask => libc::SYS_rt_sigprocmask,
            Sys::RtSigpending => libc::SYS_rt_sigpending,
            Sys::RtSigtimedwait => libc::SYS_rt_sigtimedwait,
            Sys::RtSigsuspend => libc::SYS_rt_sigsuspend,
            Sys::Sigaltstack => libc::SYS_sigaltstack,
            Sys::Kill => libc::SYS_kill,
            Sys::Tkill => libc::SYS_tkill,
            Sys::Tgkill => libc::SYS_tgkill,
            Sys::Signalfd4 => libc::SYS_signalfd4,
            Sys::RtSigqueueinfo => libc::SYS_rt_sigqueueinfo,
            Sys::RtTgsigqueueinfo => libc::SYS_rt_tgsigqueueinfo,
            Sys::Getpid => libc::SYS_getpid,
            Sys::Gettid => libc::SYS_gettid,
            Sys::Getppid => libc::SYS_getppid,
            Sys::Getpgid => libc::SYS_getpgid,
            Sys::Getsid => libc::SYS_getsid,
            Sys::Getuid => libc::SYS_getuid,
            Sys::Getgid => libc::SYS_getgid,
            Sys::SetTidAddress => libc::SYS_set_tid_address,
            Sys::Prctl => libc::SYS_prctl,
            Sys::Wait4 => libc::SYS_wait4,
            Sys::Waitid => libc::SYS_waitid,
            Sys::Clone => libc::SYS_clone,
            Sys::Clone3 => libc::SYS_clone3,
            Sys::Execve => libc::SYS_execve,
            Sys::Execveat => libc::SYS_execveat,
            Sys::Exit => libc::SYS_exit,
            Sys::ExitGroup => libc::SYS_exit_group,
            Sys::Socketpair => libc::SYS_socketpair,
            Sys::Getcwd => libc::SYS_getcwd,
            Sys::Chdir => libc::SYS_chdir,
            Sys::Fchdir => libc::SYS_fchdir,
            Sys::Umask => libc::SYS_umask,
            Sys::Mknodat => libc::SYS_mknodat,
            Sys::Faccessat => libc::SYS_faccessat,
            Sys::Faccessat2 => libc::SYS_faccessat2,
            Sys::Utimensat => libc::SYS_utimensat,
            Sys::Fchown => libc::SYS_fchown,
            Sys::Fchownat => libc::SYS_fchownat,
            Sys::Truncate => libc::SYS_truncate,
            Sys::Ftruncate => libc::SYS_ftruncate,
            Sys::Fallocate => libc::SYS_fallocate,
            Sys::Nfsservctl => libc::SYS_nfsservctl,
            Sys::LookupDcookie => libc::SYS_lookup_dcookie,
            // These x86_64 legacy rows have no number on the
            // generic (arm64) table; the probes issue them on x86_64 only.
            Sys::Access
            | Sys::Utime
            | Sys::Utimes
            | Sys::Futimesat
            | Sys::Chown
            | Sys::Lchown
            | Sys::Pause
            | Sys::Signalfd
            | Sys::Fork
            | Sys::Vfork
            | Sys::Sysctl
            | Sys::Vserver
            | Sys::Security
            | Sys::Tuxcall
            | Sys::AfsSyscall
            | Sys::Getpmsg
            | Sys::Putpmsg
            | Sys::EpollCtlOld
            | Sys::EpollWaitOld
            | Sys::CreateModule
            | Sys::QueryModule
            | Sys::GetKernelSyms
            | Sys::Uselib => {
                #[cfg(target_arch = "x86_64")]
                {
                    match self {
                        Sys::Access => libc::SYS_access,
                        Sys::Utime => libc::SYS_utime,
                        Sys::Utimes => libc::SYS_utimes,
                        Sys::Futimesat => libc::SYS_futimesat,
                        Sys::Chown => libc::SYS_chown,
                        Sys::Pause => libc::SYS_pause,
                        Sys::Lchown => libc::SYS_lchown,
                        Sys::Signalfd => libc::SYS_signalfd,
                        Sys::Fork => libc::SYS_fork,
                        Sys::Vfork => libc::SYS_vfork,
                        Sys::Sysctl => libc::SYS__sysctl,
                        Sys::Vserver => libc::SYS_vserver,
                        Sys::Security => libc::SYS_security,
                        Sys::Tuxcall => libc::SYS_tuxcall,
                        Sys::AfsSyscall => libc::SYS_afs_syscall,
                        Sys::Getpmsg => libc::SYS_getpmsg,
                        Sys::Putpmsg => libc::SYS_putpmsg,
                        Sys::EpollCtlOld => libc::SYS_epoll_ctl_old,
                        Sys::EpollWaitOld => libc::SYS_epoll_wait_old,
                        Sys::CreateModule => libc::SYS_create_module,
                        Sys::QueryModule => libc::SYS_query_module,
                        Sys::GetKernelSyms => libc::SYS_get_kernel_syms,
                        Sys::Uselib => libc::SYS_uselib,
                        _ => unreachable!(),
                    }
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    return None;
                }
            }
            // libc 0.2.189 predates the number; it is 472 in the vendored
            // x86_64 table and the generic (arm64) table alike.
            Sys::Fchroot => 472,
        };
        Some((nr, args))
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

// glibc exports `futimesat` (deprecated, still a strong symbol); the libc
// crate does not declare it.
unsafe extern "C" {
    fn futimesat(
        dirfd: libc::c_int,
        path: *const libc::c_char,
        times: *const libc::timeval,
    ) -> libc::c_int;
}

/// The glibc symbol of the same name, folded to the kernel result convention.
fn libc_symbol(sys: Sys, a: Args) -> i64 {
    use libc::*;
    let result: i64 = unsafe {
        match sys {
            Sys::Read => read(a[0] as c_int, a[1] as *mut c_void, a[2] as size_t) as i64,
            Sys::Write => write(a[0] as c_int, a[1] as *const c_void, a[2] as size_t) as i64,
            Sys::Openat => openat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as c_int,
                a[3] as c_uint,
            ) as i64,
            Sys::Close => close(a[0] as c_int) as i64,
            Sys::Lseek => lseek(a[0] as c_int, a[1] as off_t, a[2] as c_int) as i64,
            Sys::Fstat => fstat(a[0] as c_int, a[1] as *mut stat) as i64,
            Sys::Newfstatat => fstatat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as *mut stat,
                a[3] as c_int,
            ) as i64,
            Sys::Statx => statx(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as c_int,
                a[3] as c_uint,
                a[4] as *mut statx,
            ) as i64,
            // Rows whose libc symbol the shim does not interpose today are NOT
            // named here: a reference in this shared table would put the symbol in
            // every probe binary and the pre-run audit would refuse all of them.
            // The one probe that exercises such a row registers its own libc
            // spelling (`Probe::register_libc`), scoping the audit refusal to it.
            Sys::Getdents64 | Sys::Ppoll => panic!(
                "{}: no libc spelling in the shared table; the probe registers one",
                sys.name()
            ),
            Sys::Mkdirat => mkdirat(a[0] as c_int, a[1] as *const c_char, a[2] as mode_t) as i64,
            Sys::Unlinkat => unlinkat(a[0] as c_int, a[1] as *const c_char, a[2] as c_int) as i64,
            Sys::Renameat => renameat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as c_int,
                a[3] as *const c_char,
            ) as i64,
            Sys::Symlinkat => {
                symlinkat(a[0] as *const c_char, a[1] as c_int, a[2] as *const c_char) as i64
            }
            Sys::Readlinkat => readlinkat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as *mut c_char,
                a[3] as size_t,
            ) as i64,
            Sys::Linkat => linkat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as c_int,
                a[3] as *const c_char,
                a[4] as c_int,
            ) as i64,
            Sys::Pipe2 => pipe2(a[0] as *mut c_int, a[1] as c_int) as i64,
            Sys::Dup => dup(a[0] as c_int) as i64,
            Sys::Dup2 => dup2(a[0] as c_int, a[1] as c_int) as i64,
            Sys::Dup3 => dup3(a[0] as c_int, a[1] as c_int, a[2] as c_int) as i64,
            Sys::CloseRange => close_range(a[0] as c_uint, a[1] as c_uint, a[2] as c_int) as i64,
            Sys::Fcntl => fcntl(a[0] as c_int, a[1] as c_int, a[2] as c_long) as i64,
            Sys::Flock => flock(a[0] as c_int, a[1] as c_int) as i64,
            Sys::ClockGettime => clock_gettime(a[0] as clockid_t, a[1] as *mut timespec) as i64,
            Sys::Gettimeofday => gettimeofday(a[0] as *mut timeval, a[1] as *mut timezone) as i64,
            Sys::Nanosleep => nanosleep(a[0] as *const timespec, a[1] as *mut timespec) as i64,
            Sys::ClockNanosleep => {
                // The one wrapper that returns the errno instead of -1 + errno.
                let code = clock_nanosleep(
                    a[0] as clockid_t,
                    a[1] as c_int,
                    a[2] as *const timespec,
                    a[3] as *mut timespec,
                );
                return if code == 0 { 0 } else { -(code as i64) };
            }
            Sys::Getrandom => getrandom(a[0] as *mut c_void, a[1] as size_t, a[2] as c_uint) as i64,
            Sys::Socket => socket(a[0] as c_int, a[1] as c_int, a[2] as c_int) as i64,
            Sys::Bind => bind(a[0] as c_int, a[1] as *const sockaddr, a[2] as socklen_t) as i64,
            Sys::Listen => listen(a[0] as c_int, a[1] as c_int) as i64,
            Sys::Connect => {
                connect(a[0] as c_int, a[1] as *const sockaddr, a[2] as socklen_t) as i64
            }
            Sys::Accept4 => accept4(
                a[0] as c_int,
                a[1] as *mut sockaddr,
                a[2] as *mut socklen_t,
                a[3] as c_int,
            ) as i64,
            Sys::Sendto => sendto(
                a[0] as c_int,
                a[1] as *const c_void,
                a[2] as size_t,
                a[3] as c_int,
                a[4] as *const sockaddr,
                a[5] as socklen_t,
            ) as i64,
            Sys::Recvfrom => recvfrom(
                a[0] as c_int,
                a[1] as *mut c_void,
                a[2] as size_t,
                a[3] as c_int,
                a[4] as *mut sockaddr,
                a[5] as *mut socklen_t,
            ) as i64,
            Sys::Getsockname => {
                getsockname(a[0] as c_int, a[1] as *mut sockaddr, a[2] as *mut socklen_t) as i64
            }
            Sys::Getpeername => {
                getpeername(a[0] as c_int, a[1] as *mut sockaddr, a[2] as *mut socklen_t) as i64
            }
            Sys::Shutdown => shutdown(a[0] as c_int, a[1] as c_int) as i64,
            Sys::Setsockopt => setsockopt(
                a[0] as c_int,
                a[1] as c_int,
                a[2] as c_int,
                a[3] as *const c_void,
                a[4] as socklen_t,
            ) as i64,
            Sys::Getsockopt => getsockopt(
                a[0] as c_int,
                a[1] as c_int,
                a[2] as c_int,
                a[3] as *mut c_void,
                a[4] as *mut socklen_t,
            ) as i64,
            Sys::EpollCreate1 => epoll_create1(a[0] as c_int) as i64,
            Sys::EpollCtl => epoll_ctl(
                a[0] as c_int,
                a[1] as c_int,
                a[2] as c_int,
                a[3] as *mut epoll_event,
            ) as i64,
            Sys::EpollWait => epoll_wait(
                a[0] as c_int,
                a[1] as *mut epoll_event,
                a[2] as c_int,
                a[3] as c_int,
            ) as i64,
            Sys::Eventfd2 => eventfd(a[0] as c_uint, a[1] as c_int) as i64,
            // glibc has no futex wrapper symbol; the libc vehicle's spelling IS
            // syscall(SYS_futex), exactly what Rust std's futex-backed locks use.
            Sys::Futex => syscall(
                SYS_futex,
                a[0] as c_long,
                a[1] as c_long,
                a[2] as c_long,
                a[3] as c_long,
                a[4] as c_long,
                a[5] as c_long,
            ) as i64,
            Sys::RtSigaction => syscall(
                SYS_rt_sigaction,
                a[0] as c_long,
                a[1] as c_long,
                a[2] as c_long,
                a[3] as c_long,
            ) as i64,
            Sys::RtSigprocmask => syscall(
                SYS_rt_sigprocmask,
                a[0] as c_long,
                a[1] as c_long,
                a[2] as c_long,
                a[3] as c_long,
            ) as i64,
            Sys::RtSigpending => syscall(SYS_rt_sigpending, a[0] as c_long, a[1] as c_long) as i64,
            Sys::RtSigtimedwait => syscall(
                SYS_rt_sigtimedwait,
                a[0] as c_long,
                a[1] as c_long,
                a[2] as c_long,
                a[3] as c_long,
            ) as i64,
            Sys::RtSigsuspend => syscall(SYS_rt_sigsuspend, a[0] as c_long, a[1] as c_long) as i64,
            Sys::Sigaltstack => sigaltstack(a[0] as *const stack_t, a[1] as *mut stack_t) as i64,
            Sys::Kill => kill(a[0] as pid_t, a[1] as c_int) as i64,
            Sys::Pause => pause() as i64,
            Sys::Socketpair => socketpair(
                a[0] as c_int,
                a[1] as c_int,
                a[2] as c_int,
                a[3] as *mut c_int,
            ) as i64,
            // glibc has no wrappers for these Linux-only signal/thread rows.
            Sys::Tkill => syscall(SYS_tkill, a[0] as c_long, a[1] as c_long) as i64,
            Sys::Tgkill => {
                syscall(SYS_tgkill, a[0] as c_long, a[1] as c_long, a[2] as c_long) as i64
            }
            Sys::Signalfd => syscall(
                sys.require_number_and_args(a).0,
                a[0] as c_long,
                a[1] as c_long,
                a[2] as c_long,
            ) as i64,
            Sys::Signalfd4 => syscall(
                SYS_signalfd4,
                a[0] as c_long,
                a[1] as c_long,
                a[2] as c_long,
                a[3] as c_long,
            ) as i64,
            Sys::RtSigqueueinfo => syscall(
                SYS_rt_sigqueueinfo,
                a[0] as c_long,
                a[1] as c_long,
                a[2] as c_long,
            ) as i64,
            Sys::RtTgsigqueueinfo => syscall(
                SYS_rt_tgsigqueueinfo,
                a[0] as c_long,
                a[1] as c_long,
                a[2] as c_long,
                a[3] as c_long,
            ) as i64,
            Sys::Getpid => getpid() as i64,
            Sys::Gettid => syscall(SYS_gettid) as i64,
            Sys::Getppid => getppid() as i64,
            Sys::Getpgid => syscall(SYS_getpgid, a[0] as c_long) as i64,
            Sys::Getsid => syscall(SYS_getsid, a[0] as c_long) as i64,
            Sys::Getuid => getuid() as i64,
            Sys::Getgid => getgid() as i64,
            Sys::SetTidAddress => syscall(SYS_set_tid_address, a[0] as c_long) as i64,
            Sys::Prctl => prctl(
                a[0] as c_int,
                a[1] as c_ulong,
                a[2] as c_ulong,
                a[3] as c_ulong,
                a[4] as c_ulong,
            ) as i64,
            Sys::Wait4 => syscall(
                SYS_wait4,
                a[0] as c_long,
                a[1] as c_long,
                a[2] as c_long,
                a[3] as c_long,
            ) as i64,
            Sys::Waitid => waitid(
                a[0] as idtype_t,
                a[1] as id_t,
                a[2] as *mut siginfo_t,
                a[3] as c_int,
            ) as i64,
            // `_exit(2)` is exit_group's only wrapper and is not interposed
            // (its import would be refused), so the libc spelling of exit_group
            // is syscall(2), like exit's.
            Sys::Clone
            | Sys::Clone3
            | Sys::Fork
            | Sys::Vfork
            | Sys::Execve
            | Sys::Execveat
            | Sys::Exit
            | Sys::ExitGroup
            | Sys::Sysctl
            | Sys::Nfsservctl
            | Sys::Vserver
            | Sys::Security
            | Sys::Tuxcall
            | Sys::AfsSyscall
            | Sys::Getpmsg
            | Sys::Putpmsg
            | Sys::EpollCtlOld
            | Sys::EpollWaitOld
            | Sys::LookupDcookie
            | Sys::CreateModule
            | Sys::QueryModule
            | Sys::GetKernelSyms
            | Sys::Uselib => syscall(
                sys.require_number_and_args(a).0,
                a[0] as c_long,
                a[1] as c_long,
                a[2] as c_long,
                a[3] as c_long,
                a[4] as c_long,
                a[5] as c_long,
            ) as i64,
            // getcwd(3) answers a pointer; the kernel row answers a length. The
            // probe API records success as 0 on every vehicle, so the libc
            // spelling folds the pointer to 0 here.
            Sys::Getcwd => {
                if getcwd(a[0] as *mut c_char, a[1] as size_t).is_null() {
                    -1
                } else {
                    0
                }
            }
            Sys::Chdir => chdir(a[0] as *const c_char) as i64,
            Sys::Fchdir => fchdir(a[0] as c_int) as i64,
            // umask(2) never fails and its result is the previous mask; no
            // errno fold applies (a mask of 0o777 - 1 is never -1 as i64).
            Sys::Umask => return i64::from(umask(a[0] as mode_t)),
            Sys::Mknodat => mknodat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as mode_t,
                a[3] as dev_t,
            ) as i64,
            Sys::Access => access(a[0] as *const c_char, a[1] as c_int) as i64,
            Sys::Faccessat => faccessat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as c_int,
                a[3] as c_int,
            ) as i64,
            // glibc has no faccessat2 wrapper (its faccessat emulates the flags
            // over this number); the libc spelling is syscall(2).
            Sys::Faccessat2 => syscall(
                SYS_faccessat2,
                a[0] as c_long,
                a[1] as c_long,
                a[2] as c_long,
                a[3] as c_long,
                a[4] as c_long,
                a[5] as c_long,
            ) as i64,
            // glibc's utimensat refuses a null path (EINVAL) and spells the
            // kernel's descriptor shape as futimens(3), so that is the libc
            // spelling of utimensat(fd, NULL, times, 0).
            Sys::Utimensat if a[1] == 0 && a[3] == 0 => {
                futimens(a[0] as c_int, a[2] as *const timespec) as i64
            }
            Sys::Utimensat => utimensat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as *const timespec,
                a[3] as c_int,
            ) as i64,
            Sys::Utime => utime(a[0] as *const c_char, a[1] as *const utimbuf) as i64,
            Sys::Utimes => utimes(a[0] as *const c_char, a[1] as *const timeval) as i64,
            Sys::Futimesat => {
                futimesat(a[0] as c_int, a[1] as *const c_char, a[2] as *const timeval) as i64
            }
            Sys::Chown => chown(a[0] as *const c_char, a[1] as uid_t, a[2] as gid_t) as i64,
            Sys::Fchown => fchown(a[0] as c_int, a[1] as uid_t, a[2] as gid_t) as i64,
            Sys::Lchown => lchown(a[0] as *const c_char, a[1] as uid_t, a[2] as gid_t) as i64,
            Sys::Fchownat => fchownat(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as uid_t,
                a[3] as gid_t,
                a[4] as c_int,
            ) as i64,
            Sys::Truncate => truncate(a[0] as *const c_char, a[1] as off_t) as i64,
            Sys::Ftruncate => ftruncate(a[0] as c_int, a[1] as off_t) as i64,
            Sys::Fallocate => {
                fallocate(a[0] as c_int, a[1] as c_int, a[2] as off_t, a[3] as off_t) as i64
            }
            // No glibc wrapper exists for a number this new; the libc spelling
            // is syscall(2), the same door glibc itself would use.
            Sys::Fchroot => syscall(
                472,
                a[0] as c_long,
                a[1] as c_long,
                a[2] as c_long,
                a[3] as c_long,
                a[4] as c_long,
                a[5] as c_long,
            ) as i64,
        }
    };
    if result == -1 {
        -(errno() as i64)
    } else {
        result
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod raw {
    use super::Args;
    use std::arch::asm;

    /// The inline `syscall` instruction: the exact direct-syscall class the
    /// import audit cannot see, trapped by SUD under patina.
    pub fn syscall6(nr: i64, a: Args) -> i64 {
        let ret: i64;
        unsafe {
            asm!("syscall", inlateout("rax") nr => ret, in("rdi") a[0], in("rsi") a[1],
                 in("rdx") a[2], in("r10") a[3], in("r8") a[4], in("r9") a[5],
                 out("rcx") _, out("r11") _, options(nostack));
        }
        ret
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod raw {
    use super::Args;

    /// Unreachable: [`super::Vehicle::available`] refuses `raw` before any call.
    pub fn syscall6(_nr: i64, _a: Args) -> i64 {
        unreachable!("the raw vehicle is x86_64 Linux only; Vehicle::available gates it")
    }
}

/// The errno vocabulary the probes observe, by name (arch-independent and
/// readable in the expectation files). Unknown numbers print as `E#n`.
pub fn errno_name(code: i32) -> String {
    let name = match code {
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::ESRCH => "ESRCH",
        libc::EINTR => "EINTR",
        libc::EIO => "EIO",
        libc::ENXIO => "ENXIO",
        libc::E2BIG => "E2BIG",
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

#[cfg(test)]
mod tests {
    use super::{Sys, Vehicle};

    /// Class detector: architecture-unavailable rows must never borrow another
    /// architecture's number or manufacture an ENOSYS observation. The kernel
    /// tables, not a second availability map, decide which cases are callable.
    #[test]
    fn legacy_rows_match_architecture_table_and_refuse_before_dispatch() {
        for sys in [
            Sys::Signalfd,
            Sys::Fork,
            Sys::Vfork,
            Sys::Sysctl,
            Sys::Vserver,
            Sys::Security,
            Sys::Tuxcall,
            Sys::AfsSyscall,
            Sys::Getpmsg,
            Sys::Putpmsg,
            Sys::EpollCtlOld,
            Sys::EpollWaitOld,
            Sys::CreateModule,
            Sys::QueryModule,
            Sys::GetKernelSyms,
            Sys::Uselib,
            // Positive ARM controls: removed rows can still have real numbers.
            Sys::Nfsservctl,
            Sys::LookupDcookie,
            Sys::Signalfd4,
        ] {
            let nr = match crate::associations::syscall(sys.name()) {
                Some(crate::associations::Association::Native(id)) => {
                    Some(id.number() as std::ffi::c_long)
                }
                #[cfg(target_arch = "aarch64")]
                Some(crate::associations::Association::ArchitectureUnavailable) => None,
                None => panic!("{}: missing typed vehicle association", sys.name()),
            };
            assert_eq!(
                sys.number_and_args([0; 6]).map(|(nr, _)| nr),
                nr,
                "{}",
                sys.name()
            );
            assert_eq!(sys.has_number(), nr.is_some(), "{}", sys.name());
            if nr.is_none() {
                for vehicle in Vehicle::ALL {
                    let refused = std::panic::catch_unwind(|| vehicle.call(sys, [0; 6]));
                    let error = refused.expect_err("unavailable row reached dispatch");
                    let message = error.downcast_ref::<String>().expect("named refusal");
                    assert!(
                        message.contains(&format!("{}: no syscall number on", sys.name())),
                        "{message}"
                    );
                }
            }
        }
    }
}
