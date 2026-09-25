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

    /// The vehicles that issue the row's number: a scenario whose rows glibc
    /// has no wrapper for, where the libc spelling would be `syscall(2)`
    /// again.
    pub const KERNEL: &'static [Vehicle] = &[
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
            Syscall::N_accept => {
                accept(a[0] as c_int, a[1] as *mut sockaddr, a[2] as *mut socklen_t) as i64
            }
            Syscall::N_sendmsg => {
                sendmsg(a[0] as c_int, a[1] as *const msghdr, a[2] as c_int) as i64
            }
            Syscall::N_recvmsg => recvmsg(a[0] as c_int, a[1] as *mut msghdr, a[2] as c_int) as i64,
            // glibc's pselect takes the mask itself where the kernel row takes
            // a pointer to `{mask, size}`; it always passes the kernel's size.
            Syscall::N_pselect6 => {
                let pair = a[5] as *const [usize; 2];
                let mask = if pair.is_null() { 0 } else { (*pair)[0] };
                pselect(
                    a[0] as c_int,
                    a[1] as *mut fd_set,
                    a[2] as *mut fd_set,
                    a[3] as *mut fd_set,
                    a[4] as *const timespec,
                    mask as *const sigset_t,
                ) as i64
            }
            // glibc's epoll_pwait passes the kernel's sigset size itself.
            Syscall::N_epoll_pwait => epoll_pwait(
                a[0] as c_int,
                a[1] as *mut epoll_event,
                a[2] as c_int,
                a[3] as c_int,
                a[4] as *const sigset_t,
            ) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_poll => poll(a[0] as *mut pollfd, a[1] as nfds_t, a[2] as c_int) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_select => select(
                a[0] as c_int,
                a[1] as *mut fd_set,
                a[2] as *mut fd_set,
                a[3] as *mut fd_set,
                a[4] as *mut timeval,
            ) as i64,
            Syscall::N_sendmmsg => sendmmsg(
                a[0] as c_int,
                a[1] as *mut mmsghdr,
                a[2] as c_uint,
                a[3] as c_int,
            ) as i64,
            Syscall::N_recvmmsg => recvmmsg(
                a[0] as c_int,
                a[1] as *mut mmsghdr,
                a[2] as c_uint,
                a[3] as c_int,
                a[4] as *mut timespec,
            ) as i64,
            // Readiness rows whose glibc wrapper the shim does not define
            // (`epoll_pwait2`, `epoll_create`) or that glibc no longer issues
            // (`eventfd`, which its wrapper spells `eventfd2`): the libc
            // spelling is glibc's `syscall(2)` until the shim defines the
            // wrapper.
            Syscall::N_epoll_pwait2 => syscall_door(row, a),
            #[cfg(target_arch = "x86_64")]
            Syscall::N_epoll_create | Syscall::N_eventfd => syscall_door(row, a),
            // fanotify: glibc wraps both rows, the shim defines neither (they
            // are named traps).
            Syscall::N_fanotify_init | Syscall::N_fanotify_mark => syscall_door(row, a),
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
            Syscall::N_fchmod => fchmod(a[0] as c_int, a[1] as mode_t) as i64,
            // The kernel row carries no flags; glibc's fchmodat with flags 0
            // issues exactly it.
            Syscall::N_fchmodat => {
                fchmodat(a[0] as c_int, a[1] as *const c_char, a[2] as mode_t, 0) as i64
            }
            Syscall::N_renameat2 => renameat2(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as c_int,
                a[3] as *const c_char,
                a[4] as c_uint,
            ) as i64,
            Syscall::N_pread64 => pread64(
                a[0] as c_int,
                a[1] as *mut c_void,
                a[2] as size_t,
                a[3] as off64_t,
            ) as i64,
            Syscall::N_pwrite64 => pwrite64(
                a[0] as c_int,
                a[1] as *const c_void,
                a[2] as size_t,
                a[3] as off64_t,
            ) as i64,
            Syscall::N_readv => readv(a[0] as c_int, a[1] as *const iovec, a[2] as c_int) as i64,
            Syscall::N_writev => writev(a[0] as c_int, a[1] as *const iovec, a[2] as c_int) as i64,
            Syscall::N_copy_file_range => copy_file_range(
                a[0] as c_int,
                a[1] as *mut off64_t,
                a[2] as c_int,
                a[3] as *mut off64_t,
                a[4] as size_t,
                a[5] as c_uint,
            ) as i64,
            Syscall::N_sendfile => sendfile(
                a[0] as c_int,
                a[1] as c_int,
                a[2] as *mut off_t,
                a[3] as size_t,
            ) as i64,
            Syscall::N_setxattr => setxattr(
                a[0] as *const c_char,
                a[1] as *const c_char,
                a[2] as *const c_void,
                a[3] as size_t,
                a[4] as c_int,
            ) as i64,
            Syscall::N_lsetxattr => lsetxattr(
                a[0] as *const c_char,
                a[1] as *const c_char,
                a[2] as *const c_void,
                a[3] as size_t,
                a[4] as c_int,
            ) as i64,
            Syscall::N_fsetxattr => fsetxattr(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as *const c_void,
                a[3] as size_t,
                a[4] as c_int,
            ) as i64,
            Syscall::N_getxattr => getxattr(
                a[0] as *const c_char,
                a[1] as *const c_char,
                a[2] as *mut c_void,
                a[3] as size_t,
            ) as i64,
            Syscall::N_lgetxattr => lgetxattr(
                a[0] as *const c_char,
                a[1] as *const c_char,
                a[2] as *mut c_void,
                a[3] as size_t,
            ) as i64,
            Syscall::N_fgetxattr => fgetxattr(
                a[0] as c_int,
                a[1] as *const c_char,
                a[2] as *mut c_void,
                a[3] as size_t,
            ) as i64,
            Syscall::N_listxattr => {
                listxattr(a[0] as *const c_char, a[1] as *mut c_char, a[2] as size_t) as i64
            }
            Syscall::N_llistxattr => {
                llistxattr(a[0] as *const c_char, a[1] as *mut c_char, a[2] as size_t) as i64
            }
            Syscall::N_flistxattr => {
                flistxattr(a[0] as c_int, a[1] as *mut c_char, a[2] as size_t) as i64
            }
            Syscall::N_removexattr => {
                removexattr(a[0] as *const c_char, a[1] as *const c_char) as i64
            }
            Syscall::N_lremovexattr => {
                lremovexattr(a[0] as *const c_char, a[1] as *const c_char) as i64
            }
            Syscall::N_fremovexattr => fremovexattr(a[0] as c_int, a[1] as *const c_char) as i64,
            // The kernel rows split the position into (pos_l, pos_h); on a
            // 64-bit kernel pos_l is the whole position and pos_h is ignored.
            Syscall::N_preadv => preadv(
                a[0] as c_int,
                a[1] as *const iovec,
                a[2] as c_int,
                a[3] as off_t,
            ) as i64,
            Syscall::N_pwritev => pwritev(
                a[0] as c_int,
                a[1] as *const iovec,
                a[2] as c_int,
                a[3] as off_t,
            ) as i64,
            Syscall::N_fsync => fsync(a[0] as c_int) as i64,
            Syscall::N_fdatasync => fdatasync(a[0] as c_int) as i64,
            Syscall::N_ioctl => ioctl(a[0] as c_int, a[1] as c_ulong, a[2] as *mut c_void) as i64,
            Syscall::N_statfs => statfs(a[0] as *const c_char, a[1] as *mut statfs) as i64,
            Syscall::N_fstatfs => fstatfs(a[0] as c_int, a[1] as *mut statfs) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_pipe => pipe(a[0] as *mut c_int) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_open => open(a[0] as *const c_char, a[1] as c_int, a[2] as c_uint) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_creat => creat(a[0] as *const c_char, a[1] as mode_t) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_stat => stat(a[0] as *const c_char, a[1] as *mut stat) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_lstat => lstat(a[0] as *const c_char, a[1] as *mut stat) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_rename => rename(a[0] as *const c_char, a[1] as *const c_char) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_mkdir => mkdir(a[0] as *const c_char, a[1] as mode_t) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_rmdir => rmdir(a[0] as *const c_char) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_link => link(a[0] as *const c_char, a[1] as *const c_char) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_unlink => unlink(a[0] as *const c_char) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_symlink => symlink(a[0] as *const c_char, a[1] as *const c_char) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_readlink => {
                readlink(a[0] as *const c_char, a[1] as *mut c_char, a[2] as size_t) as i64
            }
            #[cfg(target_arch = "x86_64")]
            Syscall::N_chmod => chmod(a[0] as *const c_char, a[1] as mode_t) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_mknod => mknod(a[0] as *const c_char, a[1] as mode_t, a[2] as dev_t) as i64,
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
            // The memory rows whose glibc symbol a shim-linked probe may
            // import: the shim defines `mmap`/`munmap`/`msync`/`mremap`/
            // `mprotect` and the `mlock` family, and the import audit admits
            // `madvise` as process-local memory. `MAP_FAILED` is the pointer
            // -1, which folds like `-1`.
            Syscall::N_mmap => mmap(
                a[0] as *mut c_void,
                a[1] as size_t,
                a[2] as c_int,
                a[3] as c_int,
                a[4] as c_int,
                a[5] as off_t,
            ) as i64,
            Syscall::N_munmap => munmap(a[0] as *mut c_void, a[1] as size_t) as i64,
            Syscall::N_mprotect => {
                mprotect(a[0] as *mut c_void, a[1] as size_t, a[2] as c_int) as i64
            }
            Syscall::N_madvise => {
                madvise(a[0] as *mut c_void, a[1] as size_t, a[2] as c_int) as i64
            }
            Syscall::N_msync => msync(a[0] as *mut c_void, a[1] as size_t, a[2] as c_int) as i64,
            Syscall::N_mlock => mlock(a[0] as *const c_void, a[1] as size_t) as i64,
            Syscall::N_mlock2 => {
                mlock2(a[0] as *const c_void, a[1] as size_t, a[2] as c_uint) as i64
            }
            Syscall::N_munlock => munlock(a[0] as *const c_void, a[1] as size_t) as i64,
            Syscall::N_mlockall => mlockall(a[0] as c_int) as i64,
            Syscall::N_munlockall => munlockall() as i64,
            Syscall::N_mremap => mremap(
                a[0] as *mut c_void,
                a[1] as size_t,
                a[2] as size_t,
                a[3] as c_int,
                a[4] as *mut c_void,
            ) as i64,
            Syscall::N_memfd_create => memfd_create(a[0] as *const c_char, a[1] as c_uint) as i64,
            // Memory and IPC rows whose glibc wrapper the shim does not define
            // (`brk`, `mincore`, SysV shm/sem/msg, the kernel rows under
            // glibc's `mq_*`, `pkey_*`, `remap_file_pages`, `pidfd_open`,
            // `process_madvise`) or that glibc does not wrap at all
            // (`membarrier`, `memfd_secret`, `map_shadow_stack`, the NUMA
            // rows libnuma wraps): importing such a wrapper would
            // make the pre-run import audit refuse the whole probe binary, so
            // the libc spelling is glibc's own `syscall(2)` until the shim
            // defines it. A scenario made only of such rows runs through
            // `Vehicle::KERNEL`, not `syscall(2)` twice.
            Syscall::N_brk
            | Syscall::N_mincore
            | Syscall::N_shmget
            | Syscall::N_shmat
            | Syscall::N_shmdt
            | Syscall::N_shmctl
            | Syscall::N_semget
            | Syscall::N_semop
            | Syscall::N_semtimedop
            | Syscall::N_semctl
            | Syscall::N_msgget
            | Syscall::N_msgsnd
            | Syscall::N_msgrcv
            | Syscall::N_msgctl
            | Syscall::N_mq_open
            | Syscall::N_mq_unlink
            | Syscall::N_mq_timedsend
            | Syscall::N_mq_timedreceive
            | Syscall::N_mq_notify
            | Syscall::N_mq_getsetattr
            | Syscall::N_memfd_secret
            | Syscall::N_membarrier
            | Syscall::N_remap_file_pages
            | Syscall::N_pkey_mprotect
            | Syscall::N_pkey_alloc
            | Syscall::N_pkey_free
            | Syscall::N_map_shadow_stack
            | Syscall::N_pidfd_open
            | Syscall::N_process_madvise
            | Syscall::N_mbind
            | Syscall::N_set_mempolicy
            | Syscall::N_get_mempolicy
            | Syscall::N_migrate_pages
            | Syscall::N_move_pages
            | Syscall::N_set_mempolicy_home_node => syscall_door(row, a),
            // No glibc wrapper: the futex word, the signal rows (glibc's
            // wrappers take its own struct layouts), tkill/tgkill, the thread
            // and process-lifecycle rows (`_exit(2)` is not interposed, so its
            // import would be refused), faccessat2 (glibc's faccessat emulates
            // the flags over it) and removed numbers.
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
            | Syscall::N_lookup_dcookie => syscall_door(row, a),
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
            // fchmodat2, whose flags glibc's fchmodat emulates over it, and
            // rows whose glibc wrapper the shim does not define and no
            // scenario reaches through `WRAPPERS` (a symbol row that is
            // `Absent`, or none): the probe binary importing such a wrapper
            // would be refused whole by the pre-run import audit, so until the
            // shim defines it the libc spelling is glibc's own `syscall(2)`,
            // and the symbol stays in the coverage report.
            Syscall::N_fchmodat2
            | Syscall::N_sync
            | Syscall::N_syncfs
            | Syscall::N_sync_file_range
            | Syscall::N_preadv2
            | Syscall::N_pwritev2
            | Syscall::N_inotify_init1
            | Syscall::N_inotify_add_watch => syscall_door(row, a),
            // The time, identity, scheduling and limit rows whose glibc
            // symbol the shim defines: the libc spelling is that wrapper
            // (`setuid`/`setgid`/`setgroups`/`setsid`/`setpgid` are the
            // shim's deny-traps; `sched_getaffinity` answers 0 where the row
            // answers the bytes it wrote, which its probe method folds).
            Syscall::N_uname => uname(a[0] as *mut utsname) as i64,
            Syscall::N_sysinfo => sysinfo(a[0] as *mut sysinfo) as i64,
            Syscall::N_getrusage => getrusage(a[0] as c_int, a[1] as *mut rusage) as i64,
            Syscall::N_getrlimit => {
                getrlimit(a[0] as __rlimit_resource_t, a[1] as *mut rlimit) as i64
            }
            Syscall::N_setrlimit => {
                setrlimit(a[0] as __rlimit_resource_t, a[1] as *const rlimit) as i64
            }
            Syscall::N_sched_getaffinity => {
                sched_getaffinity(a[0] as pid_t, a[1] as size_t, a[2] as *mut cpu_set_t) as i64
            }
            Syscall::N_sched_setaffinity => {
                sched_setaffinity(a[0] as pid_t, a[1] as size_t, a[2] as *const cpu_set_t) as i64
            }
            Syscall::N_sched_yield => sched_yield() as i64,
            Syscall::N_geteuid => geteuid() as i64,
            Syscall::N_getegid => getegid() as i64,
            Syscall::N_setuid => setuid(a[0] as uid_t) as i64,
            Syscall::N_setgid => setgid(a[0] as gid_t) as i64,
            Syscall::N_setgroups => setgroups(a[0] as size_t, a[1] as *const gid_t) as i64,
            Syscall::N_setsid => setsid() as i64,
            Syscall::N_setpgid => setpgid(a[0] as pid_t, a[1] as pid_t) as i64,
            #[cfg(target_arch = "x86_64")]
            Syscall::N_time => time(a[0] as *mut time_t) as i64,
            // The time, identity, scheduling and limit rows whose glibc
            // wrapper the shim does not define (importing it would make the
            // pre-run import audit refuse the whole probe binary) or that
            // glibc does not wrap (`timer_*` ids and `getpriority`'s raw
            // answer differ from glibc's wrappers; `clock_getres`'s symbol row
            // is `Absent`): the libc spelling is glibc's own `syscall(2)`.
            Syscall::N_clock_getres
            | Syscall::N_getitimer
            | Syscall::N_setitimer
            | Syscall::N_timer_create
            | Syscall::N_timer_settime
            | Syscall::N_timer_gettime
            | Syscall::N_timer_getoverrun
            | Syscall::N_timer_delete
            | Syscall::N_timerfd_create
            | Syscall::N_timerfd_settime
            | Syscall::N_timerfd_gettime
            | Syscall::N_times
            | Syscall::N_settimeofday
            | Syscall::N_clock_settime
            | Syscall::N_adjtimex
            | Syscall::N_clock_adjtime
            | Syscall::N_syslog
            | Syscall::N_personality
            | Syscall::N_prlimit64
            | Syscall::N_getpriority
            | Syscall::N_setpriority
            | Syscall::N_ioprio_get
            | Syscall::N_ioprio_set
            | Syscall::N_sched_getscheduler
            | Syscall::N_sched_setscheduler
            | Syscall::N_sched_getparam
            | Syscall::N_sched_setparam
            | Syscall::N_sched_get_priority_max
            | Syscall::N_sched_get_priority_min
            | Syscall::N_sched_rr_get_interval
            | Syscall::N_sched_getattr
            | Syscall::N_sched_setattr
            | Syscall::N_getcpu
            | Syscall::N_getresuid
            | Syscall::N_getresgid
            | Syscall::N_setreuid
            | Syscall::N_setregid
            | Syscall::N_setresuid
            | Syscall::N_setresgid
            | Syscall::N_setfsuid
            | Syscall::N_setfsgid
            | Syscall::N_getgroups
            | Syscall::N_capget
            | Syscall::N_capset
            | Syscall::N_sethostname
            | Syscall::N_setdomainname => syscall_door(row, a),
            #[cfg(target_arch = "x86_64")]
            Syscall::N_alarm | Syscall::N_getpgrp | Syscall::N_sysfs => syscall_door(row, a),
            // Legacy rows glibc has no wrapper for (`getdents`; `ustat`, whose
            // wrapper glibc 2.28 dropped).
            #[cfg(target_arch = "x86_64")]
            Syscall::N_getdents | Syscall::N_ustat => syscall_door(row, a),
            // `chroot` is the shim's own definition (a deny-trap).
            Syscall::N_chroot => chroot(a[0] as *const c_char) as i64,
            // Privileged rows glibc has no wrapper for, in scenarios whose
            // libc leg goes through the wrappers of their other rows
            // (`WRAPPERS`): glibc's own spelling is `syscall(2)`.
            Syscall::N_finit_module
            | Syscall::N_kexec_load
            | Syscall::N_kexec_file_load
            | Syscall::N_quotactl_fd => syscall_door(row, a),
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
        libc::EDOM => "EDOM",
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
        libc::EIDRM => "EIDRM",
        libc::ENOMSG => "ENOMSG",
        libc::ECANCELED => "ECANCELED",
        _ => return format!("E#{code}"),
    };
    name.to_string()
}

/// glibc's wrappers for privileged rows. The
/// shim defines none of them (registry `Absent`), so the probe binary cannot
/// import them (the pre-run audit would refuse the whole binary): the libc
/// vehicle reaches each through `dlsym` at its row's first call
/// (`Probe::call`), and under patina that lookup answers NULL.
const WRAPPERS: &[(Syscall, &str)] = &[
    (Syscall::N_mount, "mount"),
    (Syscall::N_umount2, "umount2"),
    (Syscall::N_open_tree, "open_tree"),
    (Syscall::N_fsopen, "fsopen"),
    (Syscall::N_fspick, "fspick"),
    (Syscall::N_fsmount, "fsmount"),
    (Syscall::N_fsconfig, "fsconfig"),
    (Syscall::N_move_mount, "move_mount"),
    (Syscall::N_mount_setattr, "mount_setattr"),
    (Syscall::N_acct, "acct"),
    (Syscall::N_vhangup, "vhangup"),
    (Syscall::N_swapon, "swapon"),
    (Syscall::N_swapoff, "swapoff"),
    (Syscall::N_reboot, "reboot"),
    (Syscall::N_init_module, "init_module"),
    (Syscall::N_delete_module, "delete_module"),
    (Syscall::N_pivot_root, "pivot_root"),
    (Syscall::N_quotactl, "quotactl"),
    (Syscall::N_unshare, "unshare"),
    (Syscall::N_setns, "setns"),
    (Syscall::N_ptrace, "ptrace"),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_iopl, "iopl"),
    #[cfg(target_arch = "x86_64")]
    (Syscall::N_ioperm, "ioperm"),
];

/// The glibc wrapper the libc vehicle reaches `row` through, if it has one.
pub fn wrapper(row: Syscall) -> Option<&'static str> {
    WRAPPERS
        .iter()
        .find(|(wrapped, _)| *wrapped == row)
        .map(|(_, symbol)| *symbol)
}

/// Call glibc's wrapper for `row`, found at `address`, with the row's
/// arguments in the wrapper's own types; the kernel result convention.
///
/// # Safety
///
/// `address` is glibc's definition of `wrapper(row)`, and the caller owns
/// every pointer in `a`.
pub unsafe fn wrapper_door(row: Syscall, address: *mut std::ffi::c_void, a: Args) -> i64 {
    use libc::*;
    /// Call `address` as `unsafe extern "C" fn(params) -> ret`.
    macro_rules! call {
        (($($param:ty),*) -> $ret:ty, $($arg:expr),*) => {{
            // SAFETY: the caller's contract: `address` is this wrapper.
            let wrapper = unsafe {
                std::mem::transmute::<*mut c_void, unsafe extern "C" fn($($param),*) -> $ret>(
                    address,
                )
            };
            // SAFETY: the caller's contract: it owns every pointer passed.
            let result = unsafe { wrapper($($arg as $param),*) };
            result as i64
        }};
    }
    let result = match row {
        Syscall::N_mount => call!(
            (*const c_char, *const c_char, *const c_char, c_ulong, *const c_void) -> c_int,
            a[0], a[1], a[2], a[3], a[4]
        ),
        Syscall::N_umount2 => call!((*const c_char, c_int) -> c_int, a[0], a[1]),
        Syscall::N_open_tree => call!((c_int, *const c_char, c_uint) -> c_int, a[0], a[1], a[2]),
        Syscall::N_fsopen => call!((*const c_char, c_uint) -> c_int, a[0], a[1]),
        Syscall::N_fspick => call!((c_int, *const c_char, c_uint) -> c_int, a[0], a[1], a[2]),
        Syscall::N_fsmount => call!((c_int, c_uint, c_uint) -> c_int, a[0], a[1], a[2]),
        Syscall::N_fsconfig => call!(
            (c_int, c_uint, *const c_char, *const c_void, c_int) -> c_int,
            a[0], a[1], a[2], a[3], a[4]
        ),
        Syscall::N_move_mount => call!(
            (c_int, *const c_char, c_int, *const c_char, c_uint) -> c_int,
            a[0], a[1], a[2], a[3], a[4]
        ),
        Syscall::N_mount_setattr => call!(
            (c_int, *const c_char, c_uint, *mut c_void, size_t) -> c_int,
            a[0], a[1], a[2], a[3], a[4]
        ),
        Syscall::N_acct => call!((*const c_char) -> c_int, a[0]),
        Syscall::N_vhangup => call!(() -> c_int,),
        Syscall::N_swapon => call!((*const c_char, c_int) -> c_int, a[0], a[1]),
        Syscall::N_swapoff => call!((*const c_char) -> c_int, a[0]),
        // glibc's `reboot(howto)` passes both magic numbers itself: the
        // row's command is its one argument.
        Syscall::N_reboot => call!((c_int) -> c_int, a[2]),
        Syscall::N_init_module => call!(
            (*mut c_void, c_ulong, *const c_char) -> c_int,
            a[0], a[1], a[2]
        ),
        Syscall::N_delete_module => call!((*const c_char, c_uint) -> c_int, a[0], a[1]),
        Syscall::N_pivot_root => call!((*const c_char, *const c_char) -> c_int, a[0], a[1]),
        Syscall::N_quotactl => call!(
            (c_int, *const c_char, c_int, *mut c_char) -> c_int,
            a[0], a[1], a[2], a[3]
        ),
        Syscall::N_unshare => call!((c_int) -> c_int, a[0]),
        Syscall::N_setns => call!((c_int, c_int) -> c_int, a[0], a[1]),
        // `long ptrace(enum __ptrace_request, ...)`: pid, address and data
        // are its variadic arguments.
        Syscall::N_ptrace => {
            // SAFETY: the caller's contract: `address` is glibc's ptrace.
            let ptrace = unsafe {
                std::mem::transmute::<*mut c_void, unsafe extern "C" fn(c_uint, ...) -> c_long>(
                    address,
                )
            };
            // SAFETY: the caller's contract: it owns every pointer passed.
            unsafe {
                ptrace(
                    a[0] as c_uint,
                    a[1] as pid_t,
                    a[2] as *mut c_void,
                    a[3] as *mut c_void,
                )
            }
        }
        #[cfg(target_arch = "x86_64")]
        Syscall::N_iopl => call!((c_int) -> c_int, a[0]),
        #[cfg(target_arch = "x86_64")]
        Syscall::N_ioperm => call!((c_ulong, c_ulong, c_int) -> c_int, a[0], a[1], a[2]),
        other => panic!("{}: no glibc wrapper", other.name()),
    };
    fold_errno(result)
}
