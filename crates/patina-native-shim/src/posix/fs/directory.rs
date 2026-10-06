//! Directory streams preserve each platform's existing descriptor ownership.
use super::*;
use core::ptr;

#[cfg(target_os = "linux")]
#[repr(C, align(8))]
struct Directory {
    fd: c_int,
    size: usize,
    offset: usize,
    filepos: libc::off_t,
    data: [u8; 32768],
}
#[cfg(target_os = "linux")]
const _: () = {
    assert!(size_of::<libc::dirent>() == size_of::<libc::dirent64>());
    assert!(
        core::mem::offset_of!(libc::dirent, d_name)
            == core::mem::offset_of!(libc::dirent64, d_name)
    );
    assert!(align_of::<libc::dirent64>() == 8);
    assert!(core::mem::offset_of!(Directory, data) == 32);
};

#[cfg(target_os = "linux")]
unsafe fn allocate(fd: c_int) -> *mut libc::DIR {
    unsafe {
        let directory = libc::malloc(size_of::<Directory>()).cast::<Directory>();
        if directory.is_null() {
            error(libc::ENOMEM);
            return ptr::null_mut();
        }
        ptr::addr_of_mut!((*directory).fd).write(fd);
        ptr::addr_of_mut!((*directory).size).write(0);
        ptr::addr_of_mut!((*directory).offset).write(0);
        ptr::addr_of_mut!((*directory).filepos).write(0);
        directory.cast()
    }
}

#[cfg(target_os = "linux")]
unsafe fn next(directory: *mut Directory, error_out: *mut c_int) -> *mut libc::dirent64 {
    unsafe {
        error_out.write(0);
        if (*directory).offset >= (*directory).size {
            let bytes = crate::sud::patina_sud_dispatch(
                libc::SYS_getdents64,
                (*directory).fd as u64,
                ptr::addr_of_mut!((*directory).data) as u64,
                32768,
                0,
                0,
                0,
                0,
            );
            if bytes <= 0 {
                if bytes < 0 && bytes != -(libc::ENOENT as i64) {
                    error_out.write(-bytes as c_int);
                }
                return ptr::null_mut();
            }
            (*directory).size = bytes as usize;
            (*directory).offset = 0;
        }
        let entry = ptr::addr_of_mut!((*directory).data)
            .cast::<u8>()
            .add((*directory).offset)
            .cast::<libc::dirent64>();
        (*directory).offset += (*entry).d_reclen as usize;
        (*directory).filepos = (*entry).d_off;
        entry
    }
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct Directory {
    state: *mut core::ffi::c_void,
    owned_fd: c_int,
    entry: libc::dirent,
}

/// # Safety
/// `path` satisfies opendir's libc string contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn opendir(path: *const c_char) -> *mut libc::DIR {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        let flags = crate::O_READ | crate::O_DIRECTORY | crate::O_CLOEXEC;
        #[cfg(target_os = "linux")]
        let flags = flags | crate::O_NONBLOCK;
        let fd = crate::patina_openat(AT_FDCWD, path, flags, 0);
        if fd < 0 {
            error(crate::patina_errno());
            return ptr::null_mut();
        }
        #[cfg(target_os = "linux")]
        {
            let directory = allocate(fd);
            if directory.is_null() {
                crate::patina_close(fd);
            }
            directory
        }
        #[cfg(target_os = "macos")]
        {
            let mut state = ptr::null_mut();
            if crate::patina_read_dir(fd, &mut state) != 0 {
                let saved = crate::patina_errno();
                crate::patina_close(fd);
                error(saved);
                return ptr::null_mut();
            }
            let directory = libc::calloc(1, size_of::<Directory>()).cast::<Directory>();
            if directory.is_null() {
                crate::patina_read_dir_free(state);
                crate::patina_close(fd);
                error(libc::ENOMEM);
                return ptr::null_mut();
            }
            (*directory).state = state;
            (*directory).owned_fd = fd;
            directory.cast()
        }
    }
}

/// # Safety
/// Adopts the descriptor on success, as libc fdopendir does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fdopendir(fd: c_int) -> *mut libc::DIR {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        #[cfg(target_os = "linux")]
        {
            let mut values = core::mem::MaybeUninit::<crate::PatinaMetadata>::uninit();
            if crate::patina_fd_metadata_full(fd, values.as_mut_ptr()) < 0 {
                error(crate::patina_errno());
                return ptr::null_mut();
            }
            if values.assume_init().kind != crate::PATINA_ENTRY_DIRECTORY {
                error(libc::ENOTDIR);
                return ptr::null_mut();
            }
            let status = crate::patina_fd_getfl(fd);
            if status < 0 {
                error(crate::patina_errno());
                return ptr::null_mut();
            }
            if status as u32 & crate::O_PATH != 0 {
                error(libc::EBADF);
                return ptr::null_mut();
            }
            if crate::patina_fd_setfd(fd, 1) < 0 {
                error(crate::patina_errno());
                return ptr::null_mut();
            }
            allocate(fd)
        }
        #[cfg(target_os = "macos")]
        {
            let mut state = ptr::null_mut();
            if crate::patina_read_dir(fd, &mut state) != 0 {
                error(crate::patina_errno());
                return ptr::null_mut();
            }
            let directory = libc::calloc(1, size_of::<Directory>()).cast::<Directory>();
            if directory.is_null() {
                crate::patina_read_dir_free(state);
                error(libc::ENOMEM);
                return ptr::null_mut();
            }
            (*directory).state = state;
            (*directory).owned_fd = fd;
            directory.cast()
        }
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// `dirp` is a live stream owned by this adapter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn readdir64(dirp: *mut libc::DIR) -> *mut libc::dirent64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        let mut failure = 0;
        let entry = next(dirp.cast(), &mut failure);
        if failure != 0 {
            error(failure);
        }
        entry
    }
}

/// # Safety
/// `dirp` is a live stream owned by this adapter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn readdir(dirp: *mut libc::DIR) -> *mut libc::dirent {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        #[cfg(target_os = "linux")]
        {
            readdir64(dirp).cast()
        }
        #[cfg(target_os = "macos")]
        {
            let directory = dirp.cast::<Directory>();
            let mut kind = 0;
            let mut ino = 0;
            let entry = ptr::addr_of_mut!((*directory).entry);
            let result = crate::patina_read_dir_next(
                (*directory).state,
                ptr::addr_of_mut!((*entry).d_name).cast(),
                size_of_val(&(*entry).d_name),
                &mut kind,
                &mut ino,
            );
            if result < 0 {
                error(crate::patina_errno());
                return ptr::null_mut();
            }
            if result == 0 {
                return ptr::null_mut();
            }
            (*entry).d_ino = ino as libc::ino_t;
            (*entry).d_reclen = size_of::<libc::dirent>() as u16;
            (*entry).d_namlen = libc::strlen(ptr::addr_of!((*entry).d_name).cast()) as u8 as u16;
            (*entry).d_type = match kind {
                crate::PATINA_ENTRY_DIRECTORY => libc::DT_DIR,
                crate::PATINA_ENTRY_SYMLINK => libc::DT_LNK,
                crate::PATINA_ENTRY_FIFO => libc::DT_FIFO,
                crate::PATINA_ENTRY_SOCKET => libc::DT_SOCK,
                crate::PATINA_ENTRY_CHAR => libc::DT_CHR,
                _ => libc::DT_REG,
            };
            entry
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn readdir_copy(
    dirp: *mut libc::DIR,
    entry: *mut libc::dirent64,
    result: *mut *mut libc::dirent64,
) -> c_int {
    unsafe {
        let mut failure = 0;
        let next = next(dirp.cast(), &mut failure);
        if next.is_null() {
            result.write(ptr::null_mut());
            if failure != 0 {
                error(failure);
            }
            return failure;
        }
        ptr::copy_nonoverlapping(
            next.cast::<u8>(),
            entry.cast::<u8>(),
            (*next).d_reclen as usize,
        );
        result.write(entry);
        0
    }
}

/// # Safety
/// The stream and writable outputs satisfy libc readdir_r's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn readdir_r(
    dirp: *mut libc::DIR,
    entry: *mut libc::dirent,
    result: *mut *mut libc::dirent,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        #[cfg(target_os = "linux")]
        {
            readdir_copy(dirp, entry.cast(), result.cast())
        }
        #[cfg(target_os = "macos")]
        {
            super::super::errno(0);
            let next = readdir(dirp);
            if next.is_null() {
                result.write(ptr::null_mut());
                return super::super::get_errno();
            }
            ptr::copy_nonoverlapping(
                next.cast::<u8>(),
                entry.cast::<u8>(),
                size_of::<libc::dirent>(),
            );
            result.write(entry);
            0
        }
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// The stream and writable outputs satisfy libc readdir64_r's contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn readdir64_r(
    dirp: *mut libc::DIR,
    entry: *mut libc::dirent64,
    result: *mut *mut libc::dirent64,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { readdir_copy(dirp, entry, result) }
}

#[cfg(target_os = "linux")]
/// # Safety
/// The guest buffer is copied through the dispatcher model's uaccess.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getdents64(
    fd: c_int,
    buffer: *mut core::ffi::c_void,
    length: usize,
) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let result = unsafe {
        crate::sud::patina_sud_dispatch(
            libc::SYS_getdents64,
            fd as u64,
            buffer as u64,
            length.min(c_int::MAX as usize) as u64,
            0,
            0,
            0,
            0,
        )
    };
    if (-4095..=-1).contains(&result) {
        error(-result as c_int) as isize
    } else {
        result as isize
    }
}

/// # Safety
/// Releases a live directory stream created by this adapter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn closedir(dirp: *mut libc::DIR) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        #[cfg(target_os = "linux")]
        {
            if dirp.is_null() {
                return error(libc::EINVAL);
            }
            let fd = (*dirp.cast::<Directory>()).fd;
            libc::free(dirp.cast());
            model_result(crate::patina_close(fd))
        }
        #[cfg(target_os = "macos")]
        {
            let directory = dirp.cast::<Directory>();
            crate::patina_read_dir_free((*directory).state);
            crate::patina_close((*directory).owned_fd);
            libc::free(directory.cast());
            0
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn seek(dirp: *mut libc::DIR, position: libc::c_long) {
    unsafe {
        let directory = dirp.cast::<Directory>();
        crate::patina_seek((*directory).fd, position, libc::SEEK_SET as u32);
        (*directory).size = 0;
        (*directory).offset = 0;
        (*directory).filepos = position;
    }
}

/// # Safety
/// `dirp` is a live stream owned by this adapter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rewinddir(dirp: *mut libc::DIR) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        #[cfg(target_os = "linux")]
        {
            seek(dirp, 0);
        }
        #[cfg(target_os = "macos")]
        {
            let directory = dirp.cast::<Directory>();
            let mut state = ptr::null_mut();
            if crate::patina_read_dir((*directory).owned_fd, &mut state) != 0 {
                error(crate::patina_errno());
                return;
            }
            crate::patina_read_dir_free((*directory).state);
            (*directory).state = state;
        }
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// `dirp` is a live stream and position was answered by telldir.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seekdir(dirp: *mut libc::DIR, position: libc::c_long) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        seek(dirp, position);
    }
}

#[cfg(target_os = "linux")]
/// # Safety
/// `dirp` is a live stream owned by this adapter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn telldir(dirp: *mut libc::DIR) -> libc::c_long {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe { (*dirp.cast::<Directory>()).filepos }
}

/// # Safety
/// `dirp` is a live stream owned by this adapter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dirfd(dirp: *mut libc::DIR) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        #[cfg(target_os = "linux")]
        {
            (*dirp.cast::<Directory>()).fd
        }
        #[cfg(target_os = "macos")]
        {
            (*dirp.cast::<Directory>()).owned_fd
        }
    }
}
