//! Whole-file and record-lock entry points.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

#[cfg(any(target_os = "linux", patina_posix_exports))]
const LOCK_SH: c_int = 1;
#[cfg(any(target_os = "linux", patina_posix_exports))]
const LOCK_EX: c_int = 2;
#[cfg(any(target_os = "linux", patina_posix_exports))]
const LOCK_NB: c_int = 4;
#[cfg(any(target_os = "linux", patina_posix_exports))]
const LOCK_UN: c_int = 8;

#[cfg(any(target_os = "linux", patina_posix_exports))]
pub(crate) fn flock(raw_fd: c_int, operation: c_int) -> crate::abi::SysResult<c_int> {
    #[cfg(target_os = "linux")]
    if operation & linux_raw_sys::general::LOCK_MAND as c_int != 0 {
        set_errno(0);
        return Ok(0);
    }
    let non_blocking = operation & LOCK_NB != 0;
    let mode = match operation & !LOCK_NB {
        LOCK_UN => None,
        LOCK_SH => Some(FlockMode::Shared),
        LOCK_EX => Some(FlockMode::Exclusive),
        _ => return Err(crate::abi::failed(EINVAL)),
    };
    let resolved = match fdget(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return Err(crate::abi::failed(errno)),
    };
    let Some(mode) = mode else {
        flock_release(resolved.desc);
        set_errno(0);
        return Ok(0);
    };
    let identity = match lock_identity(&resolved) {
        Ok(identity) => identity,
        Err(errno) => return Err(crate::abi::failed(errno)),
    };
    let mut table = flock_table().lock();
    let conflict = table.iter().any(|(&holder, &(held_identity, held_mode))| {
        holder != resolved.desc
            && held_identity == identity
            && (mode == FlockMode::Exclusive || held_mode == FlockMode::Exclusive)
    });
    if conflict {
        drop(table);
        return if non_blocking {
            Err(crate::abi::failed(EWOULDBLOCK))
        } else {
            Err(crate::abi::failed(EDEADLK))
        };
    }
    table.insert(resolved.desc, (identity, mode));
    set_errno(0);
    Ok(0)
}

/// The record-lock commands of `patina_record_lock`, in Linux's numbering
/// (the SUD `fcntl` row passes the guest's through; the libc `fcntl` door maps its
/// platform's onto them).
pub(crate) const F_GETLK: u32 = 5;
pub(crate) const F_SETLK: u32 = 6;
pub(crate) const F_SETLKW: u32 = 7;
pub(crate) const F_OFD_GETLK: u32 = 36;
pub(crate) const F_OFD_SETLK: u32 = 37;
pub(crate) const F_OFD_SETLKW: u32 = 38;
/// The lock types, in Linux's numbering.
pub(crate) const F_RDLCK: i16 = 0;
pub(crate) const F_WRLCK: i16 = 1;
pub(crate) const F_UNLCK: i16 = 2;

/// `struct flock` as the 64-bit Linux kernel lays it out (the record-lock
/// structure in `patina_native.h`): what the SUD `fcntl` row reads from the
/// guest, and what the libc `fcntl` door translates its platform layout into.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PatinaFlock {
    pub l_type: i16,
    pub l_whence: i16,
    pub l_start: i64,
    pub l_len: i64,
    pub l_pid: i32,
}

const _: () = {
    assert!(core::mem::size_of::<PatinaFlock>() == 32);
    assert!(core::mem::offset_of!(PatinaFlock, l_type) == 0);
    assert!(core::mem::offset_of!(PatinaFlock, l_whence) == 2);
    assert!(core::mem::offset_of!(PatinaFlock, l_start) == 8);
    assert!(core::mem::offset_of!(PatinaFlock, l_len) == 16);
    assert!(core::mem::offset_of!(PatinaFlock, l_pid) == 24);
};

#[cfg(target_os = "linux")]
const _: () = {
    assert!(core::mem::size_of::<PatinaFlock>() == core::mem::size_of::<libc::flock>());
    assert!(
        core::mem::offset_of!(PatinaFlock, l_type) == core::mem::offset_of!(libc::flock, l_type)
    );
    assert!(
        core::mem::offset_of!(PatinaFlock, l_whence)
            == core::mem::offset_of!(libc::flock, l_whence)
    );
    assert!(
        core::mem::offset_of!(PatinaFlock, l_start) == core::mem::offset_of!(libc::flock, l_start)
    );
    assert!(core::mem::offset_of!(PatinaFlock, l_len) == core::mem::offset_of!(libc::flock, l_len));
    assert!(core::mem::offset_of!(PatinaFlock, l_pid) == core::mem::offset_of!(libc::flock, l_pid));
};

/// Read the named fields of a caller's `struct patina_flock`. Its padding may
/// be uninitialised, so it is never read.
///
/// # Safety
/// `lock` is non-null and readable for one `PatinaFlock`, at any alignment.
unsafe fn read_fields(lock: *const PatinaFlock) -> PatinaFlock {
    // SAFETY: per this function's contract; each field pointer stays inside
    // `*lock` and is read unaligned.
    unsafe {
        PatinaFlock {
            l_type: (&raw const (*lock).l_type).read_unaligned(),
            l_whence: (&raw const (*lock).l_whence).read_unaligned(),
            l_start: (&raw const (*lock).l_start).read_unaligned(),
            l_len: (&raw const (*lock).l_len).read_unaligned(),
            l_pid: (&raw const (*lock).l_pid).read_unaligned(),
        }
    }
}

/// Store `value`'s named fields, leaving the caller's padding bytes as they
/// were: Linux copies the whole `struct flock` in and back, so padding
/// round-trips.
///
/// # Safety
/// `lock` is non-null and writable for one `PatinaFlock`, at any alignment.
unsafe fn write_fields(lock: *mut PatinaFlock, value: &PatinaFlock) {
    // SAFETY: per this function's contract; each field pointer stays inside
    // `*lock` and is written unaligned.
    unsafe {
        (&raw mut (*lock).l_type).write_unaligned(value.l_type);
        (&raw mut (*lock).l_whence).write_unaligned(value.l_whence);
        (&raw mut (*lock).l_start).write_unaligned(value.l_start);
        (&raw mut (*lock).l_len).write_unaligned(value.l_len);
        (&raw mut (*lock).l_pid).write_unaligned(value.l_pid);
    }
}

/// `flock_to_posix_lock`: the byte range a `struct flock` names, from the
/// start (`SEEK_SET`), the description's offset (`SEEK_CUR`) or the file's
/// size (`SEEK_END`). `l_len` 0 runs to the end of the file, a negative one
/// ends just before the start. An unknown whence or a range that starts
/// before zero is `EINVAL`, one past `OFFSET_MAX` `EOVERFLOW`. (The `SEEK_CUR`
/// and `SEEK_END` bases are read through the fault-eligible `fs_seek` and
/// `fs_fd_metadata`, so an injected filesystem error can fail them, which no
/// kernel does; a never-faulted size and position lookup would close it.)
fn lock_range(resolved: &Resolved, lock: &PatinaFlock) -> Result<(u64, u64), c_int> {
    const OFFSET_MAX: i64 = i64::MAX;
    let base = match lock.l_whence {
        0 => 0,
        1 | 2 if !resolved.kind.is_fs() => 0,
        1 => {
            let handle = Fd(resolved.handle);
            let position = with_context(|context| context.fs_seek(handle, 0, SeekWhence::Current))?;
            i64::try_from(position).map_err(|_| EOVERFLOW)?
        }
        2 => {
            let handle = Fd(resolved.handle);
            let size = with_context(|context| context.fs_fd_metadata(handle))?.len;
            i64::try_from(size).map_err(|_| EOVERFLOW)?
        }
        _ => return Err(EINVAL),
    };
    if lock.l_start > OFFSET_MAX - base {
        return Err(EOVERFLOW);
    }
    let start = base + lock.l_start;
    if start < 0 {
        return Err(EINVAL);
    }
    let (start, end) = if lock.l_len > 0 {
        if lock.l_len - 1 > OFFSET_MAX - start {
            return Err(EOVERFLOW);
        }
        (start, start + (lock.l_len - 1))
    } else if lock.l_len < 0 {
        if start + lock.l_len < 0 {
            return Err(EINVAL);
        }
        (start + lock.l_len, start - 1)
    } else {
        (start, OFFSET_MAX)
    };
    Ok((start as u64, end as u64))
}

#[unsafe(no_mangle)]
/// `fcntl(2)`'s record locks, both doors: `F_GETLK`/`F_SETLK`/`F_SETLKW`
/// (POSIX locks, owned by the process) and `F_OFD_GETLK`/`F_OFD_SETLK`/
/// `F_OFD_SETLKW` (owned by the open file description), in `fs/locks.c`'s
/// order of refusals: an empty slot or an `O_PATH` descriptor is `EBADF`, a
/// NULL `struct flock` `EFAULT`; a test needs a read or write type (an OFD
/// test also accepts `F_UNLCK`), a set a type the description's access mode
/// allows (`EBADF`); an OFD command needs `l_pid` 0. A test reports the
/// first conflicting lock (`l_pid` its process, -1 for an OFD lock) or
/// `F_UNLCK`; a set that conflicts is `EAGAIN`, or with `F_SETLKW` waits on
/// the scheduler (`EDEADLK` where a POSIX wait would close a cycle). The
/// model is `thread::locks`.
///
/// # Safety
/// `lock` must be null or point to a writable `struct patina_flock`, at any
/// alignment.
pub unsafe extern "C" fn patina_record_lock(
    raw_fd: c_int,
    command: u32,
    lock: *mut PatinaFlock,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    use thread::locks::{Lock, Owner, Type};
    if !matches!(
        command,
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW
    ) {
        return fail(EINVAL);
    }
    let resolved = match fdget(raw_fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno),
    };
    if lock.is_null() {
        return fail(EFAULT);
    }
    // SAFETY: non-null, and a `struct patina_flock` per this entry's contract
    // (at any alignment, as `copy_from_user` reads it).
    let request = unsafe { read_fields(lock) };
    let ofd = matches!(command, F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW);
    let testing = matches!(command, F_GETLK | F_OFD_GETLK);
    let kind = match request.l_type {
        F_RDLCK => Some(Type::Read),
        F_WRLCK => Some(Type::Write),
        F_UNLCK => Some(Type::Unlock),
        _ => None,
    };
    // `fcntl_getlk` judges the type before the range, `fcntl_setlk` after it.
    // (`F_OFD_GETLK` also tests `F_UNLCK`, and meets an unknown type after.)
    if testing && !ofd && !matches!(kind, Some(Type::Read | Type::Write)) {
        return fail(EINVAL);
    }
    let (start, end) = match lock_range(&resolved, &request) {
        Ok(range) => range,
        Err(errno) => return fail(errno),
    };
    let Some(kind) = kind else {
        return fail(EINVAL);
    };
    if !testing {
        // `check_fmode_for_setlk`.
        let allowed = match kind {
            Type::Read => resolved.status & O_READ != 0,
            Type::Write => resolved.status & O_WRITE != 0,
            Type::Unlock => true,
        };
        if !allowed {
            return fail(EBADF);
        }
    }
    if ofd && request.l_pid != 0 {
        return fail(EINVAL);
    }
    let owner = if ofd {
        Owner::Description(resolved.desc)
    } else {
        Owner::Process(patina_pid())
    };
    let file = match lock_identity(&resolved) {
        Ok(file) => file,
        Err(errno) => return fail(errno),
    };
    let wanted = Lock {
        owner,
        kind,
        start,
        end,
    };
    if testing {
        let reported = match thread::locks::test(file, wanted) {
            None => PatinaFlock {
                l_type: F_UNLCK,
                ..request
            },
            Some(held) => PatinaFlock {
                l_type: if held.kind == Type::Write {
                    F_WRLCK
                } else {
                    F_RDLCK
                },
                l_whence: 0,
                l_start: held.start as i64,
                l_len: if held.end == thread::locks::OFFSET_MAX {
                    0
                } else {
                    (held.end - held.start + 1) as i64
                },
                l_pid: match held.owner {
                    Owner::Process(pid) => pid,
                    Owner::Description(_) => -1,
                },
            },
        };
        // SAFETY: `lock` is non-null and writable for one `PatinaFlock` by this
        // entry's contract, at any alignment.
        unsafe { write_fields(lock, &reported) };
        set_errno(0);
        return 0;
    }
    let waits = matches!(command, F_SETLKW | F_OFD_SETLKW);
    // `fcntl` holds its file for the whole call (`fdget_raw`): a close of the
    // description's last descriptor during a wait leaves it, and the OFD locks
    // it holds or is granted, until the call returns.
    let pinned = waits && fd_table().lock().retain(resolved.desc).is_ok();
    let mut result = thread::locks::set(file, wanted, waits);
    // `fcntl_setlk`'s close race: a POSIX lock granted after the number
    // stopped naming this description is undone, and the call is `EBADF`.
    if result.is_ok()
        && !ofd
        && kind != Type::Unlock
        && resolve_fd(raw_fd).map(|now| now.desc) != Ok(resolved.desc)
    {
        let undo = Lock {
            kind: Type::Unlock,
            ..wanted
        };
        let _ = thread::locks::set(file, undo, false);
        result = Err(EBADF);
    }
    if pinned {
        let released = fd_table().lock().release(resolved.desc);
        if let Ok(Some(release)) = released {
            let _ = release_description(release);
        }
    }
    match result {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

/// A close of `raw_fd` releases the process's POSIX locks on its file
/// (`locks_remove_posix`), whichever descriptor took them, unless it is an
/// `O_PATH` descriptor (`filp_flush` skips `FMODE_PATH`). Called before the
/// number is vacated, while its description can still name its inode; a
/// process holding no POSIX lock looks nothing up.
pub(crate) fn release_posix_locks(raw_fd: c_int) {
    if !thread::locks::process_holds_locks() {
        return;
    }
    let Ok(resolved) = resolve_fd(raw_fd) else {
        return;
    };
    if resolved.kind.is_path_only() {
        return;
    }
    if let Ok(file) = lock_identity(&resolved) {
        thread::locks::release_process_locks(file);
    }
}
