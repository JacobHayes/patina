//! Descriptor seek, synchronization, and length entry points.

use super::*;

fn no_position(whence: u32) -> c_int {
    const SEEK_MAX: u32 = 4;
    if cfg!(target_os = "linux") && whence > SEEK_MAX {
        EINVAL
    } else {
        ESPIPE
    }
}

#[unsafe(no_mangle)]
/// `lseek(2)`: a file's cursor; a description without offset addressing is
/// `ESPIPE`.
///
/// On Linux a directory's position is its `getdents64` iteration, which both
/// doors read and move (`crate::sud::seek_dir_iteration`).
pub extern "C" fn patina_seek(raw_fd: c_int, offset: i64, whence: u32) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let handle = match resolve_fd(raw_fd) {
        #[cfg(target_os = "linux")]
        Ok(resolved) if resolved.kind == FdKind::Dir => {
            return match crate::sud::seek_dir_iteration(raw_fd, offset, whence) {
                Some(position) => {
                    set_errno(0);
                    position as i64
                }
                None => i64::from(fail(EINVAL)),
            };
        }
        #[cfg(target_os = "linux")]
        Ok(resolved) if resolved.kind == FdKind::MessageQueue => {
            return match thread::ipc::mq_seek(resolved.handle, offset, whence) {
                Ok(position) => {
                    set_errno(0);
                    position
                }
                Err(errno) => i64::from(fail(errno)),
            };
        }
        // Secret memory has no position (`FMODE_LSEEK`).
        #[cfg(target_os = "linux")]
        Ok(resolved) if resolved.kind == FdKind::File && mem::secret(resolved.handle) => {
            return i64::from(fail(no_position(whence)));
        }
        // An `O_PATH` descriptor opened nothing to seek in (`fdget_pos`).
        Ok(resolved)
            if resolved.kind == FdKind::OPath && matches!(whence, SEEK_DATA | SEEK_HOLE) =>
        {
            return i64::from(fail(EBADF));
        }
        #[cfg(target_os = "linux")]
        Ok(resolved) if resolved.kind == FdKind::NamespacePath => {
            return i64::from(fail(EBADF));
        }
        Ok(resolved) if resolved.kind.is_fs() => Fd(resolved.handle),
        // `noop_llseek`: the position stays where it is, 0, for any whence
        // `ksys_lseek` passes on.
        Ok(resolved) if resolved.kind.seeks_nowhere() => {
            return i64::from(if whence > SEEK_HOLE { fail(EINVAL) } else { 0 });
        }
        Ok(_) => return i64::from(fail(no_position(whence))),
        Err(errno) => return i64::from(fail(errno)),
    };
    let whence = match whence {
        0 => SeekWhence::Start,
        1 => SeekWhence::Current,
        2 => SeekWhence::End,
        SEEK_DATA => SeekWhence::Data,
        SEEK_HOLE => SeekWhence::Hole,
        _ => return i64::from(fail(EINVAL)),
    };
    #[cfg(target_os = "linux")]
    if matches!(whence, SeekWhence::Data | SeekWhence::Hole) {
        mem::inspecting(handle.0);
    }
    match with_context(|context| context.fs_seek(handle, offset, whence)) {
        Ok(position) => i64::try_from(position).unwrap_or_else(|_| i64::from(fail(EOVERFLOW))),
        Err(errno) => i64::from(fail(errno)),
    }
}

/// `PATINA_SEEK_DATA`/`PATINA_SEEK_HOLE`: Linux's `SEEK_DATA`/`SEEK_HOLE` numbers.
const SEEK_DATA: u32 = 3;
const SEEK_HOLE: u32 = 4;

#[unsafe(no_mangle)]
/// `fsync(2)`: durability for a file (or a directory: the crash model's
/// namespace barrier); every other kind is `EINVAL`, as the kernel answers for
/// a pipe or a socket.
pub extern "C" fn patina_fsync(raw_fd: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let handle = match fdget(raw_fd) {
        // Secret memory has nothing to write back (no `fsync` operation).
        #[cfg(target_os = "linux")]
        Ok(resolved) if resolved.kind == FdKind::File && mem::secret(resolved.handle) => {
            return fail(EINVAL);
        }
        Ok(resolved) if resolved.kind.is_fs() => Fd(resolved.handle),
        Ok(_) => return fail(EINVAL),
        Err(errno) => return fail(errno),
    };
    match fs_sync_handle(handle) {
        Ok(()) => 0,
        Err(errno) => fail(errno),
    }
}

/// `fsync` of a filesystem handle: what shared mappings of its file stored is
/// written back first, so it becomes durable with the rest of the file.
pub(crate) fn fs_sync_handle(handle: Fd) -> Result<(), c_int> {
    #[cfg(target_os = "linux")]
    mem::syncing(handle.0)?;
    with_context(|context| context.fs_sync(handle))
}

/// `sync`/`syncfs` of the volume: every mapped file's stores are written back
/// first.
#[cfg(target_os = "linux")]
pub(crate) fn fs_sync_volume() -> Result<(), c_int> {
    mem::syncing_all()?;
    with_context(|context| context.fs_sync_all())
}

#[unsafe(no_mangle)]
/// `ftruncate(2)`: a file's length; every other kind is `EINVAL`.
pub extern "C" fn patina_set_len(raw_fd: c_int, length: u64) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let handle = match fdget(raw_fd) {
        Ok(resolved) if resolved.kind.is_fs() => Fd(resolved.handle),
        Ok(_) => return fail(EINVAL),
        Err(errno) => return fail(errno),
    };
    // `secretmem_setattr`: secret memory is sized once, while it is empty.
    #[cfg(target_os = "linux")]
    if !mem::secret_resizable(handle.0) {
        return fail(EINVAL);
    }
    match with_context(|context| context.fs_set_len(handle, length)) {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            {
                mem::resized(handle.0, length);
                mem::secret_resized(handle.0, length);
                fsnotify::on_handle(handle, fsnotify::IN_MODIFY);
            }
            0
        }
        Err(errno) => fail(errno),
    }
}
