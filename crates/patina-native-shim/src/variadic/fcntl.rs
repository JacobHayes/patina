//! Typed fcntl arguments and platform flags/record-lock layouts.
#![deny(clippy::undocumented_unsafe_blocks)]

use core::ffi::{VaList, c_int, c_void};

#[cfg(target_os = "linux")]
mod linux {
    use core::ffi::c_int;
    use linux_raw_sys::general as k;
    pub(super) const F_GETOWN_EX: c_int = k::F_GETOWN_EX as c_int;
    pub(super) const F_SETOWN_EX: c_int = k::F_SETOWN_EX as c_int;
    pub(super) const F_SETSIG: c_int = k::F_SETSIG as c_int;
    pub(super) const F_GETSIG: c_int = k::F_GETSIG as c_int;
}

/// # Safety
/// The optional argument has the promoted type required by `command`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcntl(fd: c_int, command: c_int, args: ...) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel_fcntl(command, c"fcntl");
    // SAFETY: the public fcntl contract supplies the command's argument.
    unsafe { dispatch(fd, command, args) }
}

/// # Safety
/// The optional argument has the promoted type required by `command`.
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcntl64(fd: c_int, command: c_int, args: ...) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    super::cancel_fcntl(command, c"fcntl64");
    // SAFETY: off_t and off64_t share their 64-bit layout on supported targets.
    unsafe { dispatch(fd, command, args) }
}

unsafe fn dispatch(fd: c_int, command: c_int, mut args: VaList<'_>) -> c_int {
    use libc::{F_DUPFD, F_DUPFD_CLOEXEC, F_SETFD, F_SETFL};
    let mutated = super::fault(1);
    let lock_command = record_command(command);
    #[allow(unused_mut)]
    let mut pointer = lock_command.is_some();
    #[allow(unused_mut)]
    let mut integer = matches!(command, F_SETFD | F_SETFL | F_DUPFD | F_DUPFD_CLOEXEC);
    #[cfg(target_os = "linux")]
    {
        pointer |= command == linux::F_GETOWN_EX;
        integer |= matches!(command, libc::F_SETPIPE_SZ | libc::F_ADD_SEALS);
    }
    // Only commands whose modeled path consumes a payload read one. In
    // particular, owner setters refuse by name without touching their payload.
    // SAFETY: the command selects the caller's promoted C type.
    let (argument, pointer) = unsafe {
        if pointer {
            (0, args.next_arg::<*mut c_void>())
        } else if integer {
            let value = args.next_arg::<c_int>();
            (
                if mutated {
                    args.next_arg::<c_int>()
                } else {
                    value
                },
                core::ptr::null_mut(),
            )
        } else {
            (0, core::ptr::null_mut())
        }
    };
    if let Some(command) = lock_command {
        return record_lock(fd, command, pointer.cast());
    }
    #[cfg(target_os = "linux")]
    if command == linux::F_GETOWN_EX {
        return super::model_result(crate::patina_fcntl_owner_get(fd, 1, pointer));
    }
    let result = match command {
        libc::F_GETFD => {
            let result = super::model_result(crate::patina_fd_getfd(fd));
            return if result < 0 {
                result
            } else if result != 0 {
                libc::FD_CLOEXEC
            } else {
                0
            };
        }
        F_SETFD => crate::patina_fd_setfd(fd, c_int::from(argument & libc::FD_CLOEXEC != 0)),
        libc::F_GETFL => {
            let result = super::model_result(crate::patina_fd_getfl(fd));
            return if result < 0 {
                result
            } else {
                getfl_to_posix(result as u32)
            };
        }
        F_SETFL => crate::patina_fd_setfl(fd, setfl_from_posix(argument)),
        F_DUPFD => crate::patina_dupfd(fd, argument, 0),
        F_DUPFD_CLOEXEC => crate::patina_dupfd(fd, argument, 1),
        #[cfg(target_os = "linux")]
        libc::F_GETPIPE_SZ => crate::thread::patina_pipe_size(fd),
        #[cfg(target_os = "linux")]
        libc::F_SETPIPE_SZ => crate::thread::patina_pipe_set_size(fd, argument),
        #[cfg(target_os = "linux")]
        libc::F_ADD_SEALS => crate::mem::patina_add_seals(fd, argument as u32),
        #[cfg(target_os = "linux")]
        libc::F_GET_SEALS => crate::mem::patina_get_seals(fd),
        libc::F_SETOWN => crate::patina_fcntl_owner(fd),
        #[cfg(target_os = "linux")]
        linux::F_SETOWN_EX | linux::F_SETSIG => crate::patina_fcntl_owner(fd),
        #[cfg(target_os = "linux")]
        libc::F_GETOWN | linux::F_GETSIG => {
            crate::patina_fcntl_owner_get(fd, 0, core::ptr::null_mut())
        }
        #[cfg(target_os = "macos")]
        libc::F_FULLFSYNC => crate::patina_fsync(fd),
        _ => {
            return super::error(if crate::patina_fd_kind(fd) < 0 {
                libc::EBADF
            } else {
                libc::EINVAL
            });
        }
    };
    super::model_result(result)
}

fn getfl_to_posix(status: u32) -> c_int {
    let mut flags = match (status & crate::O_READ != 0, status & crate::O_WRITE != 0) {
        (true, true) => libc::O_RDWR,
        (_, true) => libc::O_WRONLY,
        _ => libc::O_RDONLY,
    };
    if status & crate::O_APPEND != 0 {
        flags |= libc::O_APPEND;
    }
    if status & crate::O_NONBLOCK != 0 {
        flags |= libc::O_NONBLOCK;
    }
    #[cfg(target_os = "linux")]
    {
        if status & crate::O_PATH != 0 {
            flags |= libc::O_PATH;
        }
        if status & crate::O_DIRECTORY != 0 {
            flags |= libc::O_DIRECTORY;
        }
        // libc's O_LARGEFILE is zero on LP64; the kernel's bit is not.
        if status & crate::O_OPENED != 0 {
            flags |= linux_raw_sys::general::O_LARGEFILE as c_int;
        }
        if status & crate::O_CLOEXEC != 0 {
            flags |= libc::O_CLOEXEC;
        }
    }
    flags
}

fn setfl_from_posix(flags: c_int) -> u32 {
    let mut status = 0;
    if flags & libc::O_APPEND != 0 {
        status |= crate::O_APPEND;
    }
    if flags & libc::O_NONBLOCK != 0 {
        status |= crate::O_NONBLOCK;
    }
    status
}

fn record_command(command: c_int) -> Option<u32> {
    Some(match command {
        libc::F_GETLK => crate::F_GETLK,
        libc::F_SETLK => crate::F_SETLK,
        libc::F_SETLKW => crate::F_SETLKW,
        #[cfg(target_os = "linux")]
        libc::F_OFD_GETLK => crate::F_OFD_GETLK,
        #[cfg(target_os = "linux")]
        libc::F_OFD_SETLK => crate::F_OFD_SETLK,
        #[cfg(target_os = "linux")]
        libc::F_OFD_SETLKW => crate::F_OFD_SETLKW,
        _ => return None,
    })
}

fn record_lock(fd: c_int, command: u32, pointer: *mut libc::flock) -> c_int {
    // As in the kernel, reject the descriptor before copying guest memory.
    if let Err(errno) = crate::fdget(fd) {
        return super::error(errno);
    }
    let original = match crate::uaccess::read::<libc::flock>(pointer as usize) {
        Ok(lock) => lock,
        Err(errno) => return super::error(errno),
    };
    #[allow(
        clippy::unnecessary_cast,
        reason = "libc lock constants are i32 on Linux and i16 on Darwin"
    )]
    let mut request = crate::PatinaFlock {
        l_type: match original.l_type {
            value if value == libc::F_RDLCK as i16 => crate::F_RDLCK,
            value if value == libc::F_WRLCK as i16 => crate::F_WRLCK,
            value if value == libc::F_UNLCK as i16 => crate::F_UNLCK,
            _ => -1,
        },
        l_whence: original.l_whence,
        l_start: original.l_start,
        l_len: original.l_len,
        l_pid: original.l_pid,
    };
    // SAFETY: the fixed model receives our live local structure, not guest memory.
    let result = unsafe { crate::patina_record_lock(fd, command, &mut request) };
    if result < 0 {
        return super::model_result(result);
    }
    if matches!(command, crate::F_GETLK | crate::F_OFD_GETLK) {
        let lock_type = match request.l_type {
            crate::F_RDLCK => libc::F_RDLCK,
            crate::F_WRLCK => libc::F_WRLCK,
            _ => libc::F_UNLCK,
        } as libc::c_short;
        let address = pointer as usize;
        let write = || -> Result<(), c_int> {
            // Copy only returned fields: an unlocked result changes l_type
            // alone, and no copy exports uninitialized structure padding.
            crate::uaccess::write(
                address + core::mem::offset_of!(libc::flock, l_type),
                &lock_type,
            )?;
            if request.l_type != crate::F_UNLCK {
                crate::uaccess::write(
                    address + core::mem::offset_of!(libc::flock, l_whence),
                    &(libc::SEEK_SET as libc::c_short),
                )?;
                crate::uaccess::write(
                    address + core::mem::offset_of!(libc::flock, l_start),
                    &request.l_start,
                )?;
                crate::uaccess::write(
                    address + core::mem::offset_of!(libc::flock, l_len),
                    &request.l_len,
                )?;
                crate::uaccess::write(
                    address + core::mem::offset_of!(libc::flock, l_pid),
                    &request.l_pid,
                )?;
            }
            Ok(())
        };
        if let Err(errno) = write() {
            return super::error(errno);
        }
    }
    0
}
