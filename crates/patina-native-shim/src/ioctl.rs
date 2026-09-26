//! `ioctl(2)`'s generic descriptor requests, one entry both doors call.
//!
//! The kernel resolves the number with `fdget` (an `O_PATH` descriptor is
//! `EBADF`, like an empty slot) and then answers the requests every descriptor
//! understands (`fs/ioctl.c do_vfs_ioctl`): `FIOCLEX`/`FIONCLEX` set and clear
//! the number's `FD_CLOEXEC`, `FIONBIO` reads an `int` through the argument
//! (`EFAULT` for NULL) and sets or clears the description's `O_NONBLOCK`, and
//! `FIONREAD` on a regular file is its size minus the position, as an `int`
//! (negative past the end). On Linux the rest of `do_vfs_ioctl`'s requests
//! (and `file_ioctl`'s, for a regular file) are answered next, for every
//! descriptor kind at once ([`vfs`]), before the file's own ioctl, or stop
//! the run by name where the model ends. Everything else goes to the
//! object: a pipe's `FIONREAD` is the bytes queued in it, a socket's
//! (`SIOCINQ`) what a receive would take now, and a socket answers the
//! interface requests (`SIOCGIF*`, `thread::net::iface`); a userfaultfd, a
//! namespace file and the entropy device have ioctls of their own; any
//! other request, and `FIONREAD` on a directory or a descriptor with no such
//! answer, is `ENOTTY`.
//!
//! `request` is the platform's own request number: the C door passes its
//! libc's, the SUD row the Linux kernel's; on Linux only its low 32 bits
//! count, as the kernel reads an `unsigned int`.

use std::ffi::{c_int, c_void};

use patina_dst_abi::{Fd, SeekWhence};

#[cfg(target_os = "linux")]
use crate::EINVAL;
use crate::fdtable::FdKind;
use crate::{
    fail, fdget, patina_fd_set_nonblocking, patina_fd_setfd, set_errno, thread, uaccess,
    with_context,
};

/// The generic requests, in the platform's numbering (`asm-generic/ioctls.h`,
/// identical on every Linux architecture the shim runs on; `<sys/filio.h>` on
/// Darwin).
#[cfg(target_os = "linux")]
pub(crate) mod request {
    pub(crate) const FIONREAD: u64 = 0x541B;
    pub(crate) const FIONBIO: u64 = 0x5421;
    pub(crate) const FIONCLEX: u64 = 0x5450;
    pub(crate) const FIOCLEX: u64 = 0x5451;
}

#[cfg(target_os = "macos")]
pub(crate) mod request {
    pub(crate) const FIONREAD: u64 = 0x4004_667F;
    pub(crate) const FIONBIO: u64 = 0x8004_667E;
    pub(crate) const FIONCLEX: u64 = 0x2000_6602;
    pub(crate) const FIOCLEX: u64 = 0x2000_6601;
}

use request::{FIOCLEX, FIONBIO, FIONCLEX, FIONREAD};

const ENOTTY: c_int = 25;

/// Write an `int` answer through the guest's argument (`EFAULT` for memory
/// that cannot take it).
fn put_int(arg: *mut c_void, value: i32) -> c_int {
    match uaccess::write(arg as usize, &value) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// `FIONREAD` on a regular file: its size minus the description's position,
/// truncated to an `int` exactly as `put_user` into an `int *` does.
fn file_fionread(handle: Fd, arg: *mut c_void) -> c_int {
    let size = match with_context(|context| context.fs_fd_metadata(handle)) {
        Ok(metadata) => metadata.len,
        Err(errno) => return fail(errno),
    };
    let position = match with_context(|context| context.fs_seek(handle, 0, SeekWhence::Current)) {
        Ok(position) => position,
        Err(errno) => return fail(errno),
    };
    put_int(arg, size.wrapping_sub(position) as i32)
}

/// `ioctl(fd, request, arg)`.
///
/// # Safety
/// `arg`, when the request reads or writes through it and it is non-null,
/// must point to the guest's `int`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_ioctl(raw_fd: c_int, request: u64, arg: *mut c_void) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // The kernel reads the request as an `unsigned int`: the C `ioctl`'s
    // `unsigned long` (a sign-extended `int` request among them) loses its
    // upper half here, as the SUD row's does.
    #[cfg(target_os = "linux")]
    let request = u64::from(request as u32);
    let resolved = match fdget(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    #[cfg(target_os = "linux")]
    if let Some(answer) = vfs::answer(raw_fd, &resolved, request, arg) {
        return answer;
    }
    match request {
        FIOCLEX => patina_fd_setfd(raw_fd, 1),
        FIONCLEX => patina_fd_setfd(raw_fd, 0),
        FIONBIO => match uaccess::read::<i32>(arg as usize) {
            Ok(on) => patina_fd_set_nonblocking(raw_fd, c_int::from(on != 0)),
            Err(errno) => fail(errno),
        },
        FIONREAD => match resolved.kind {
            FdKind::File => file_fionread(Fd(resolved.handle), arg),
            FdKind::Pipe => match thread::pipe_queued(resolved.handle) {
                Some(queued) => put_int(arg, i32::try_from(queued).unwrap_or(i32::MAX)),
                None => fail(ENOTTY),
            },
            FdKind::Dir | FdKind::OPath | FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => {
                fail(ENOTTY)
            }
            // Not a regular file: the request goes to the device's own
            // ioctl (`random_ioctl`), which refuses what it does not know.
            #[cfg(target_os = "linux")]
            FdKind::Urandom => fail(EINVAL),
            #[cfg(target_os = "macos")]
            FdKind::Urandom => fail(ENOTTY),
            // `SIOCINQ`: what a receive would take now.
            FdKind::Socket => match thread::net::socket_pending(resolved.handle) {
                Ok(pending) => put_int(arg, pending),
                Err(errno) => fail(errno),
            },
            #[cfg(target_os = "linux")]
            FdKind::EventFd
            | FdKind::TimerFd
            | FdKind::Epoll
            | FdKind::SignalFd
            | FdKind::Pidfd
            | FdKind::LandlockRuleset
            | FdKind::NamespacePath => fail(ENOTTY),
            // A namespace file's nsfs inode is an empty regular file.
            #[cfg(target_os = "linux")]
            FdKind::Namespace => put_int(arg, 0),
            // Not a regular file: the request goes to the descriptor's own
            // ioctl, which knows no `FIONREAD`.
            #[cfg(target_os = "linux")]
            FdKind::Userfaultfd => uffd_answer(crate::mem::userfaultfd::ioctl(
                resolved.handle,
                request,
                arg as usize,
            )),
            // An mqueue inode is a regular file: its size less the position.
            #[cfg(target_os = "linux")]
            FdKind::MessageQueue => match thread::ipc::mq_unread(resolved.handle) {
                Some(unread) => put_int(arg, unread),
                None => fail(ENOTTY),
            },
            #[cfg(target_os = "macos")]
            FdKind::Kqueue => fail(ENOTTY),
        },
        // The interface requests a socket answers over the virtual
        // interface table.
        #[cfg(target_os = "linux")]
        _ if resolved.kind == FdKind::Socket => {
            let family = thread::net::socket_family(resolved.handle).unwrap_or(0);
            match thread::net::iface::ioctl(family, request, arg as usize) {
                Some(Ok(())) => {
                    set_errno(0);
                    0
                }
                Some(Err(errno)) => fail(errno),
                None => fail(ENOTTY),
            }
        }
        // A namespace file's own requests (`ns_ioctl`) are not modeled;
        // it answers any other `ENOTTY`.
        #[cfg(target_os = "linux")]
        _ if resolved.kind == FdKind::Namespace && crate::nsfs::is_ns_ioctl(request) => {
            crate::trap_fatal(&format!(
                "ioctl: namespace request {request:#x} on a namespace file is not modeled; \
                 failing closed"
            ))
        }
        // Every other request goes to the userfaultfd's own ioctl.
        #[cfg(target_os = "linux")]
        _ if resolved.kind == FdKind::Userfaultfd => uffd_answer(crate::mem::userfaultfd::ioctl(
            resolved.handle,
            request,
            arg as usize,
        )),
        // The entropy device's own ioctl (`random_ioctl`): its `RND*`
        // requests (type 'R') read or feed the input pool, which is not
        // modeled; any other is `EINVAL`.
        #[cfg(target_os = "linux")]
        _ if resolved.kind == FdKind::Urandom => {
            if (request >> 8) & 0xff == u64::from(b'R') {
                crate::trap_fatal(&format!(
                    "ioctl: entropy-pool request {request:#x} on /dev/urandom is not modeled; \
                     failing closed"
                ))
            }
            fail(EINVAL)
        }
        _ => fail(ENOTTY),
    }
}

/// `do_vfs_ioctl`'s requests past `FIOCLEX`/`FIONCLEX`/`FIONBIO`/`FIONREAD`,
/// which the kernel answers for every descriptor before the file's own
/// ioctl, and `file_ioctl`'s, which it answers for a regular file. Each is
/// answered as the pinned 6.8 answers it, or stops the run by name where
/// the model ends; a request the inode does not take goes on to the file's
/// own ioctl (`None`).
#[cfg(target_os = "linux")]
mod vfs {
    use std::ffi::{c_int, c_void};

    use crate::fdtable::{FdKind, Resolved};
    use crate::registry::Capability;
    use crate::{EOPNOTSUPP, EPERM, fail, set_errno, uaccess};

    use super::{ENOTTY, put_int};

    const FIBMAP: u64 = 0x1;
    const FIGETBSZ: u64 = 0x2;
    const FIOASYNC: u64 = 0x5452;
    const FIOQSIZE: u64 = 0x5460;
    const FIFREEZE: u64 = 0xc004_5877;
    const FITHAW: u64 = 0xc004_5878;
    const FS_IOC_FIEMAP: u64 = 0xc020_660b;
    const FICLONE: u64 = 0x4004_9409;
    const FICLONERANGE: u64 = 0x4020_940d;
    const FIDEDUPERANGE: u64 = 0xc018_9436;
    const FS_IOC_GETFLAGS: u64 = 0x8008_6601;
    const FS_IOC_SETFLAGS: u64 = 0x4008_6602;
    const FS_IOC_FSGETXATTR: u64 = 0x801c_581f;
    const FS_IOC_FSSETXATTR: u64 = 0x401c_5820;
    /// `_IOW('X', nr, struct space_resv)`: the preallocation requests
    /// (include/linux/falloc.h), `struct space_resv` being 48 bytes.
    const fn space_resv(nr: u64) -> u64 {
        (1 << 30) | (48 << 16) | ((b'X' as u64) << 8) | nr
    }
    const FS_IOC_RESVSP: u64 = space_resv(40);
    const FS_IOC_UNRESVSP: u64 = space_resv(41);
    const FS_IOC_RESVSP64: u64 = space_resv(42);
    const FS_IOC_UNRESVSP64: u64 = space_resv(43);
    const FS_IOC_ZERO_RANGE: u64 = space_resv(57);

    /// What the inode behind a description offers these requests.
    enum Inode {
        /// A regular file or directory on the volume: ext4's, with extent
        /// maps and file attributes.
        Volume { directory: bool },
        /// A regular file elsewhere (a memfd, secret memory, a queue, a
        /// namespace file); a memfd's shmem inode has file attributes.
        Regular { attributes: bool },
        /// Neither: a pipe, a socket, a device, an anonymous inode; `fasync`
        /// where the file has one (pipes, sockets, the entropy device).
        Special { fasync: bool },
        /// A captured standard stream, which has no modeled inode.
        Stream,
    }

    fn inode(resolved: &Resolved) -> Inode {
        match resolved.kind {
            FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => Inode::Stream,
            FdKind::Dir => Inode::Volume { directory: true },
            FdKind::File if crate::mem::secret(resolved.handle) => {
                Inode::Regular { attributes: false }
            }
            FdKind::File if crate::mem::anonymous(resolved.handle).is_some() => {
                Inode::Regular { attributes: true }
            }
            FdKind::File => Inode::Volume { directory: false },
            FdKind::MessageQueue | FdKind::Namespace => Inode::Regular { attributes: false },
            FdKind::Pipe | FdKind::Socket | FdKind::Urandom => Inode::Special { fasync: true },
            FdKind::EventFd
            | FdKind::Epoll
            | FdKind::SignalFd
            | FdKind::TimerFd
            | FdKind::Pidfd
            | FdKind::LandlockRuleset
            | FdKind::Userfaultfd => Inode::Special { fasync: false },
            // `fdget` refused these before any request is looked at.
            FdKind::OPath | FdKind::NamespacePath => Inode::Special { fasync: false },
        }
    }

    fn stop(what: &str, request: u64) -> ! {
        crate::trap_fatal(&format!(
            "ioctl: {what} (request {request:#x}) is not modeled; failing closed"
        ))
    }

    /// Whether the caller holds `capability`; holding it would take the
    /// request past the refusal the model answers.
    fn capable(capability: Capability) -> bool {
        crate::identity::credential().capable(capability)
    }

    /// The answer to `request` on `resolved`, or `None` for one that goes on
    /// to the file's own ioctl.
    pub(super) fn answer(
        raw_fd: c_int,
        resolved: &Resolved,
        request: u64,
        arg: *mut c_void,
    ) -> Option<c_int> {
        let inode = inode(resolved);
        Some(match request {
            // `ioctl_fioasync`: the model never sets `FASYNC`, so turning it
            // off changes nothing; turning it on needs the file's `fasync`,
            // and would deliver SIGIO.
            FIOASYNC => match uaccess::read::<i32>(arg as usize) {
                Err(errno) => fail(errno),
                Ok(0) => {
                    set_errno(0);
                    0
                }
                Ok(_) => match inode {
                    Inode::Special { fasync: true } | Inode::Stream => {
                        stop("FIOASYNC turning on SIGIO delivery", request)
                    }
                    Inode::Volume { .. } | Inode::Regular { .. } | Inode::Special { .. } => {
                        fail(ENOTTY)
                    }
                },
            },
            // `inode_get_bytes` of a regular file or directory, a `loff_t`.
            FIOQSIZE => match inode {
                Inode::Stream => stop("FIOQSIZE on a captured standard stream", request),
                Inode::Special { .. } => fail(ENOTTY),
                Inode::Volume { .. } | Inode::Regular { .. } => match bytes(raw_fd, resolved) {
                    Ok(bytes) => match uaccess::write(arg as usize, &bytes) {
                        Ok(()) => {
                            set_errno(0);
                            0
                        }
                        Err(errno) => fail(errno),
                    },
                    Err(errno) => fail(errno),
                },
            },
            // The superblock's block size, as `statfs` reports it.
            FIGETBSZ => match inode {
                Inode::Stream => stop("FIGETBSZ on a captured standard stream", request),
                _ => match crate::volume::block_size(raw_fd) {
                    Ok(size) => put_int(arg, size),
                    Err(errno) => fail(errno),
                },
            },
            FIFREEZE | FITHAW if capable(Capability::SysAdmin) => {
                stop("freezing or thawing a filesystem", request)
            }
            FIFREEZE | FITHAW => fail(EPERM),
            // `ioctl_fiemap`: only the volume's inodes map extents.
            FS_IOC_FIEMAP => match inode {
                Inode::Volume { .. } | Inode::Stream => stop("FS_IOC_FIEMAP", request),
                Inode::Regular { .. } | Inode::Special { .. } => fail(EOPNOTSUPP),
            },
            FICLONE | FICLONERANGE | FIDEDUPERANGE => {
                stop("cloning or deduplicating a file range", request)
            }
            // `vfs_fileattr_get`/`set`: an inode without attributes hands the
            // request to the file's own ioctl.
            FS_IOC_GETFLAGS | FS_IOC_SETFLAGS | FS_IOC_FSGETXATTR | FS_IOC_FSSETXATTR => {
                match inode {
                    Inode::Volume { .. } | Inode::Regular { attributes: true } | Inode::Stream => {
                        stop("file attributes", request)
                    }
                    Inode::Regular { attributes: false } | Inode::Special { .. } => return None,
                }
            }
            // `file_ioctl`, a regular file's: `ioctl_fibmap` needs
            // `CAP_SYS_RAWIO` first; the preallocation requests are
            // `fallocate` by another name.
            FIBMAP | FS_IOC_RESVSP | FS_IOC_UNRESVSP | FS_IOC_RESVSP64 | FS_IOC_UNRESVSP64
            | FS_IOC_ZERO_RANGE => match inode {
                Inode::Volume { directory: false } | Inode::Regular { .. }
                    if request == FIBMAP && !capable(Capability::SysRawio) =>
                {
                    fail(EPERM)
                }
                Inode::Volume { directory: false } | Inode::Regular { .. } | Inode::Stream => {
                    stop("a regular file's block map or preallocation", request)
                }
                Inode::Volume { directory: true } | Inode::Special { .. } => return None,
            },
            _ => return None,
        })
    }

    /// The bytes an inode holds (`inode_get_bytes`): what `fstat`'s
    /// `st_blocks` counts, in bytes; a queue's and a namespace file's inode
    /// holds none.
    fn bytes(raw_fd: c_int, resolved: &Resolved) -> Result<i64, c_int> {
        if matches!(resolved.kind, FdKind::MessageQueue | FdKind::Namespace) {
            return Ok(0);
        }
        let mut metadata = std::mem::MaybeUninit::<crate::PatinaMetadata>::uninit();
        // SAFETY: the out-pointer is writable local storage.
        if unsafe { crate::patina_fd_metadata_full(raw_fd, metadata.as_mut_ptr()) } != 0 {
            return Err(crate::patina_errno());
        }
        // SAFETY: a 0 answer wrote the record.
        let length = unsafe { metadata.assume_init() }.length;
        Ok(length.div_ceil(4096) as i64 * 4096)
    }
}

/// A userfaultfd request's answer as the C door reports it.
#[cfg(target_os = "linux")]
fn uffd_answer(answer: Result<c_int, c_int>) -> c_int {
    match answer {
        Ok(value) => {
            set_errno(0);
            value
        }
        Err(errno) => fail(errno),
    }
}
