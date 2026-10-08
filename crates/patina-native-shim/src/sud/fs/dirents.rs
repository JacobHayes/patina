//! File-handle and directory-entry syscall encoding.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

// ---- name_to_handle_at ----

/// `name_to_handle_at`'s flags: `AT_SYMLINK_FOLLOW`, `AT_EMPTY_PATH`, and
/// `AT_HANDLE_FID` (Linux 6.5; the value `AT_REMOVEDIR` has).
const AT_HANDLE_FID: u64 = AT_REMOVEDIR;
const NAME_TO_HANDLE_FLAGS: u64 = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH | AT_HANDLE_FID;

/// `MAX_HANDLE_SZ`: the largest handle a caller may declare room for.
const MAX_HANDLE_SZ: u32 = 128;

/// ext4's handle shape (`FILEID_INO32_GEN`): the inode number and its
/// generation, two 32-bit words; `FILEID_INVALID` when the caller's room is
/// short.
const FILEID_INO32_GEN: i32 = 1;
const FILEID_INVALID: i32 = 255;
const HANDLE_BYTES: u32 = 8;

/// The volume's mount id, the one `statx` reports.
const MOUNT_ID: i32 = STATX_MNT_ID_VALUE as i32;

/// The fixed header of a guest `struct file_handle`.
#[repr(C)]
#[derive(Clone, Copy)]
struct FileHandleHeader {
    handle_bytes: u32,
    handle_type: i32,
}

#[allow(dead_code)]
mod plain_impls {
    #![deny(clippy::undocumented_unsafe_blocks)]

    crate::plain!(super::FileHandleHeader {
        handle_bytes: u32,
        handle_type: i32,
    });
}

/// `name_to_handle_at(2)` (`fs/fhandle.c`): the flags first (`EINVAL`), then
/// the path (`AT_SYMLINK_FOLLOW` follows a final symlink, `AT_EMPTY_PATH`
/// names the descriptor), then whether the node's filesystem can encode one
/// at all (`EOPNOTSUPP` on a pseudo-filesystem, before the handle is read),
/// then the caller's declared room (`EINVAL` past `MAX_HANDLE_SZ`). A handle
/// names the node: the inode number and a zero generation, as ext4 encodes
/// one; room for less than that is `EOVERFLOW` with the size it needs written
/// back. The mount id is the volume's.
pub(in crate::sud) fn sys_name_to_handle_at(
    dirfd: i64,
    path: u64,
    handle: u64,
    mount_id: u64,
    flags: u64,
) -> i64 {
    if flags & !NAME_TO_HANDLE_FLAGS != 0 {
        return -EINVAL;
    }
    let resolve = if flags & AT_SYMLINK_FOLLOW != 0 {
        0
    } else {
        PATINA_RESOLVE_NOFOLLOW
    } | if flags & AT_EMPTY_PATH != 0 {
        PATINA_RESOLVE_EMPTY_PATH
    } else {
        0
    };
    let values = if dirfd as c_int != AT_FDCWD as c_int && is_empty_path(path, flags) {
        fd_stat_values(dirfd as c_int)
    } else {
        path_stat_values(dirfd, path, resolve)
    };
    let values = match values {
        Ok(values) => values,
        Err(errno) => return errno,
    };
    // devtmpfs (tmpfs) can encode a handle for the entropy device's node,
    // which the model does not; a filesystem with no export operations
    // refuses before the handle is read (`exportfs_can_encode_fh`).
    if values.fs == crate::PATINA_FS_DEVTMPFS {
        crate::trap_fatal(
            "name_to_handle_at of the entropy device (a devtmpfs file handle) is not modeled; \
             failing closed",
        );
    }
    if values.fs != crate::PATINA_FS_VOLUME {
        return -EOPNOTSUPP;
    }
    if handle == 0 {
        return -EFAULT;
    }
    let header = handle as *mut FileHandleHeader;
    // SAFETY: `handle` is the guest's `struct file_handle`.
    let room = unsafe { header.read_unaligned() }.handle_bytes;
    if room > MAX_HANDLE_SZ {
        return -EINVAL;
    }
    let fits = room >= HANDLE_BYTES;
    // SAFETY: the header is the guest's; the payload follows it and has
    // `room >= HANDLE_BYTES` bytes when written.
    unsafe {
        header.write_unaligned(FileHandleHeader {
            handle_bytes: HANDLE_BYTES,
            handle_type: if fits {
                FILEID_INO32_GEN
            } else {
                FILEID_INVALID
            },
        });
        if fits {
            let payload = (handle as *mut u8).add(std::mem::size_of::<FileHandleHeader>());
            let mut words = [0u8; HANDLE_BYTES as usize];
            words[..4].copy_from_slice(&(values.ino as u32).to_ne_bytes());
            std::ptr::copy_nonoverlapping(words.as_ptr(), payload, words.len());
        }
    }
    if mount_id == 0 {
        return -EFAULT;
    }
    // SAFETY: `mount_id` is the guest's `int`.
    unsafe { (mount_id as *mut i32).write_unaligned(MOUNT_ID) };
    if fits { 0 } else { -EOVERFLOW }
}

// ---- getdents64 ----

pub(in crate::sud) fn dt_for_kind(kind: u32) -> u8 {
    match kind {
        PATINA_ENTRY_DIRECTORY => DT_DIR,
        PATINA_ENTRY_SYMLINK => DT_LNK,
        PATINA_ENTRY_FIFO => DT_FIFO,
        PATINA_ENTRY_SOCKET => DT_SOCK,
        PATINA_ENTRY_CHAR => DT_CHR,
        _ => DT_REG,
    }
}

/// The directory-record layout a `getdents` row fills.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::sud) enum DirentFormat {
    /// `struct linux_dirent64` (`getdents64`): `d_ino`, `d_off`, `d_reclen`,
    /// `d_type`, then the name.
    Dirent64,
    /// The legacy `struct linux_dirent` (x86_64 `getdents`): `d_ino`, `d_off`,
    /// `d_reclen`, the name, and the type in the record's LAST byte, after the
    /// name's padding (`fs/readdir.c filldir`).
    #[cfg(target_arch = "x86_64")]
    Dirent,
}

impl DirentFormat {
    /// The fixed header before the name: `d_ino` and `d_off` (8 bytes each on
    /// a 64-bit kernel), `d_reclen`, and for `linux_dirent64` `d_type`.
    pub(super) fn header(self) -> usize {
        match self {
            DirentFormat::Dirent64 => 19,
            #[cfg(target_arch = "x86_64")]
            DirentFormat::Dirent => 18,
        }
    }

    /// A record's length: header, name, its NUL (and, for the legacy layout,
    /// the type byte), 8-byte aligned.
    fn reclen(self, name_len: usize) -> usize {
        let trailer = match self {
            DirentFormat::Dirent64 => 1,
            #[cfg(target_arch = "x86_64")]
            DirentFormat::Dirent => 2,
        };
        (self.header() + name_len + trailer + 7) & !7
    }
}

/// Fill the guest buffer with directory records from the fd's snapshot,
/// advancing `patina_read_dir_next` past every entry that fits. Returns the
/// number of bytes written (0 at end-of-directory) or `-errno`.
pub(in crate::sud) fn sys_getdents64(fd: i64, dirp: u64, count: u64) -> i64 {
    getdents(fd, dirp, count, DirentFormat::Dirent64)
}

pub(in crate::sud) fn getdents(fd: i64, dirp: u64, count: u64, format: DirentFormat) -> i64 {
    // Linux directory iteration needs an opened directory (`fdget_pos`): a
    // number that names nothing, or an `O_PATH` one, is EBADF; anything else
    // (a file, a socket) is ENOTDIR.
    match c_int::try_from(fd).map(crate::fdget) {
        Err(_) | Ok(Err(_)) => return -EBADF,
        Ok(Ok(resolved)) if resolved.kind == crate::fdtable::FdKind::Dir => {}
        Ok(Ok(_)) => return -ENOTDIR,
    }
    // `iterate_dir` reaches the directory before anything is copied out.
    crate::dir_accessed(fd as c_int);
    if dirp == 0 {
        return -EFAULT;
    }
    // The kernel reads the length as an unsigned int.
    let cap = count as u32 as usize;
    // The snapshot is taken by the FIRST getdents on the descriptor (and after
    // a seek), through the same `patina_read_dir` entry the interposed
    // `opendir` uses — a second caller, never a second directory model.
    let Ok(fd) = c_int::try_from(fd) else {
        return -EBADF;
    };
    let mut map = DIR_ITERATIONS.lock().unwrap();
    let dir = map.entry(fd).or_insert(DirIteration {
        snapshot: 0,
        position: 0,
        pending: None,
    });
    if dir.snapshot == 0 {
        let mut snapshot: *mut c_void = std::ptr::null_mut();
        // The snapshot is read through the DESCRIPTOR: its `r` was charged at
        // open, so a later `chmod` cannot break a walk under way and an `O_PATH`
        // descriptor (which opened nothing) cannot iterate at all.
        // SAFETY: `snapshot` is writable local storage.
        let rc = crate::abi::raw(unsafe { crate::fs::read_dir(fd, &mut snapshot) }.map(|_| 0));
        if rc != 0 {
            return rc;
        }
        dir.snapshot = snapshot as usize;
        // Resume at the position: skip the entries before it.
        let mut name = [0u8; 256];
        let mut kind: u32 = 0;
        let mut ino: u64 = 0;
        for _ in 0..dir.position {
            // SAFETY: `snapshot` is the live box; `name` is writable for its length.
            let rc = crate::abi::raw(
                unsafe {
                    crate::fs::read_dir_next(
                        snapshot,
                        name.as_mut_ptr() as *mut c_char,
                        name.len(),
                        &mut kind,
                        &mut ino,
                    )
                }
                .map(i64::from),
            );
            if rc != 1 {
                break;
            }
        }
    }
    let snapshot = dir.snapshot as *mut c_void;
    let mut written = 0usize;
    loop {
        // Next entry: the pushed-back one first, else consume from the snapshot.
        // `patina_read_dir_next` only advances (no peek), so an entry that does
        // not fit is stashed in `dir.pending` and never dropped.
        let record = if let Some(entry) = dir.pending.take() {
            entry
        } else {
            let mut buf = [0u8; 256];
            let (mut kind, mut ino) = (0u32, 0u64);
            // SAFETY: `snapshot` is the live box; `buf` is writable for its length.
            let rc = crate::abi::raw(
                unsafe {
                    crate::fs::read_dir_next(
                        snapshot,
                        buf.as_mut_ptr() as *mut c_char,
                        buf.len(),
                        &mut kind,
                        &mut ino,
                    )
                }
                .map(i64::from),
            );
            match rc {
                1 => {
                    // SAFETY: `buf` now holds a NUL-terminated name.
                    let len = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const c_char) }
                        .to_bytes()
                        .len();
                    DirRecord {
                        name: buf[..len].to_vec(),
                        kind,
                        ino,
                    }
                }
                0 => break, // end of directory
                _ => {
                    if written > 0 {
                        break;
                    }
                    return rc;
                }
            }
        };
        let reclen = format.reclen(record.name.len());
        if written + reclen > cap {
            // No room: push the entry back for the next call and stop. If nothing
            // fit at all, the caller's buffer is too small for even one entry.
            let empty = written == 0;
            dir.pending = Some(record);
            if empty {
                return -EINVAL;
            }
            break;
        }
        // Commit: write the record into the guest buffer, zeroed first so the
        // padding carries nothing.
        // SAFETY: `dirp+written` has `reclen` bytes of room (checked above).
        unsafe {
            let rec = (dirp as *mut u8).add(written);
            std::ptr::write_bytes(rec, 0, reclen);
            (rec as *mut u64).write_unaligned(record.ino); // d_ino
            // d_off: the position after this entry, which `lseek` resumes from.
            (rec.add(8) as *mut i64).write_unaligned((dir.position + 1) as i64);
            (rec.add(16) as *mut u16).write_unaligned(reclen as u16); // d_reclen
            // d_type: after d_reclen in `linux_dirent64`, the record's last
            // byte in the legacy layout.
            let type_offset = match format {
                DirentFormat::Dirent64 => 18,
                #[cfg(target_arch = "x86_64")]
                DirentFormat::Dirent => reclen - 1,
            };
            rec.add(type_offset).write(dt_for_kind(record.kind));
            let dst = rec.add(format.header());
            std::ptr::copy_nonoverlapping(record.name.as_ptr(), dst, record.name.len());
        }
        written += reclen;
        dir.position += 1;
    }
    written as i64
}
