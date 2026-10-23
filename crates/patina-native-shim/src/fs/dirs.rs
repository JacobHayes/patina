//! Directory iteration: a snapshot of a directory's entries (the volume's
//! or a procfs one), read through its descriptor and handed out one entry
//! at a time.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;
use patina_dst_abi::FsDirectoryEntry;

struct ReadDirState {
    entries: Vec<FsDirectoryEntry>,
    position: usize,
}

/// Capture a directory snapshot and return the owned snapshot pointer.
///
/// # Safety
/// `state_out` must be writable.
#[cfg(all(patina_posix_exports, target_os = "macos"))]
pub(crate) unsafe fn read_dir(
    raw_fd: c_int,
    state_out: *mut *mut c_void,
) -> crate::abi::SysResult<()> {
    if state_out.is_null() {
        return Err(crate::abi::failed(EINVAL));
    }
    // The call's scheduling point comes before the descriptor resolves, so
    // the read is of the description the number names when it reads, not of
    // one another task's `dup2` or `close` has meanwhile let go.
    if let Err(errno) = boundary_point() {
        return Err(crate::abi::failed(errno));
    }
    // SAFETY: per this function's contract.
    unsafe { read_dir_after_point(raw_fd, state_out) }
}

/// [`read_dir`] for a call that took its scheduling point itself, before
/// everything else it does with the descriptor (`getdents64`'s access
/// notification), so all of it is of one description.
///
/// # Safety
/// `state_out` must be writable.
pub(crate) unsafe fn read_dir_after_point(
    raw_fd: c_int,
    state_out: *mut *mut c_void,
) -> crate::abi::SysResult<()> {
    if state_out.is_null() {
        return Err(crate::abi::failed(EINVAL));
    }
    #[cfg(target_os = "linux")]
    if let Ok(resolved) = resolve_fd(raw_fd)
        && resolved.kind == FdKind::ProcDir
    {
        let node = crate::procfs::node_of(resolved.handle);
        let state = Box::new(ReadDirState {
            entries: crate::procfs::listing(node),
            position: 0,
        });
        // SAFETY: `state_out` was checked and is required to be writable.
        unsafe { state_out.write(Box::into_raw(state).cast()) };
        set_errno(0);
        return Ok(());
    }
    let fd = match fs_handle(raw_fd) {
        Ok(fd) => fd,
        Err(errno) => return Err(crate::abi::failed(errno)),
    };
    match with_context_raw(|context| context.fs_read_directory_fd(fd)) {
        Ok(listed) => {
            let state = Box::new(ReadDirState {
                entries: listed,
                position: 0,
            });
            // SAFETY: `state_out` was checked and is required to be writable.
            unsafe { state_out.write(Box::into_raw(state).cast()) };
            set_errno(0);
            Ok(())
        }
        Err(errno) => Err(crate::abi::failed(errno)),
    }
}

/// A getdents on directory descriptor `raw_fd` reached `iterate_dir`: the
/// directory's watches see `IN_ACCESS` unless it is dead, whatever the call
/// then answers.
#[cfg(target_os = "linux")]
pub(crate) fn dir_accessed(raw_fd: c_int) {
    if let Ok(resolved) = resolve_fd(raw_fd)
        && resolved.kind == FdKind::Dir
    {
        fsnotify::dir_read(Fd(resolved.handle));
    }
}

/// Copy the next entry from a captured directory snapshot.
///
/// # Safety
/// `state` must be a snapshot returned by [`read_dir`], `name_buf` must be
/// writable for `buf_len` bytes, and `kind` and `ino` must be writable.
pub(crate) unsafe fn read_dir_next(
    state: *mut c_void,
    name_buf: *mut c_char,
    buf_len: usize,
    kind: *mut u32,
    ino: *mut u64,
) -> crate::abi::SysResult<c_int> {
    if state.is_null() || kind.is_null() || ino.is_null() || (buf_len != 0 && name_buf.is_null()) {
        return Err(crate::abi::failed(EINVAL));
    }
    // SAFETY: Guaranteed by this function's C ABI contract.
    let state = unsafe { &mut *state.cast::<ReadDirState>() };
    let Some(entry) = state.entries.get(state.position) else {
        set_errno(0);
        return Ok(0);
    };
    let bytes = entry.name.as_bytes();
    if bytes
        .len()
        .checked_add(1)
        .is_none_or(|needed| needed > buf_len)
    {
        return Err(crate::abi::failed(EINVAL));
    }
    // SAFETY: The destination buffer has room for the bytes plus a NUL.
    unsafe {
        let destination = slice::from_raw_parts_mut(name_buf.cast::<u8>(), buf_len);
        destination[..bytes.len()].copy_from_slice(bytes);
        destination[bytes.len()] = 0;
        kind.write(metadata_kind(entry.kind));
        ino.write(entry.ino);
    }
    state.position += 1;
    set_errno(0);
    Ok(1)
}

/// Free a snapshot produced by [`read_dir`].
///
/// # Safety
/// `state` must be null or a live, not-yet-freed pointer returned by [`read_dir`].
pub(crate) unsafe fn free_dir(state: *mut c_void) {
    if !state.is_null() {
        // SAFETY: Guaranteed by this function's C ABI contract.
        drop(unsafe { Box::from_raw(state.cast::<ReadDirState>()) });
    }
}
