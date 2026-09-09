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
                let (nr, args) = sys.number_and_args(args);
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
                let (nr, args) = sys.number_and_args(args);
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
    Getpid,
    Getuid,
    Getgid,
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
            Sys::Getpid => "getpid",
            Sys::Getuid => "getuid",
            Sys::Getgid => "getgid",
        }
    }

    /// The syscall number on this arch, plus the argument vector the number's
    /// spelling wants.
    fn number_and_args(self, args: Args) -> (c_long, Args) {
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
                    return (
                        libc::SYS_epoll_pwait,
                        [args[0], args[1], args[2], args[3], 0, 0],
                    );
                }
            }
            Sys::Eventfd2 => libc::SYS_eventfd2,
            Sys::Ppoll => libc::SYS_ppoll,
            Sys::Futex => libc::SYS_futex,
            Sys::Getpid => libc::SYS_getpid,
            Sys::Getuid => libc::SYS_getuid,
            Sys::Getgid => libc::SYS_getgid,
        };
        (nr, args)
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
            Sys::Getpid => getpid() as i64,
            Sys::Getuid => getuid() as i64,
            Sys::Getgid => getgid() as i64,
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
