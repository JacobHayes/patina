//! Regular-file page-cache funnel hooks and synchronization.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

// ---------------------------------------------------------------- the funnels' hooks

/// Before a read of `handle`'s file: what the views stored is what the read
/// returns. A write-back the filesystem refuses stays dirty for the next one;
/// the read itself is not failed for it.
pub(crate) fn reading(handle: u64) {
    if let Some(ino) = cached_ino(handle)
        && let Some(writer) = writer_of(ino)
    {
        let _ = write_back(ino, writer);
    }
}

/// Before `SEEK_DATA`/`SEEK_HOLE` or a metadata query (`fstat`, `statx`) of
/// `handle`'s file: a store through a shared view allocates its block at the
/// write fault natively, so what the views stored is written back first and
/// the answer (`st_blocks`, the data the seek finds) counts it. Not modeled:
/// a store of the bytes a page already held, and a read fault on tmpfs,
/// allocate natively and not here.
pub(crate) fn inspecting(handle: u64) {
    reading(handle);
}

/// [`inspecting`] for a query by name that found the node `ino`: whether a
/// write-back ran (the caller then asks again, since even one that failed
/// partway may have changed the file).
pub(crate) fn inspecting_ino(ino: u64) -> bool {
    if !caching() || !MAPPINGS.lock().caches.contains_key(&ino) {
        return false;
    }
    writer_of(ino).is_some_and(|writer| write_back_counted(ino, writer).0)
}

/// Before `fsync`/`fdatasync` of `handle`'s file: what the views stored
/// becomes durable with the rest of the file.
pub(crate) fn syncing(handle: u64) -> Result<(), c_int> {
    match cached_ino(handle).and_then(|ino| writer_of(ino).map(|writer| (ino, writer))) {
        Some((ino, writer)) => write_back(ino, writer),
        None => Ok(()),
    }
}

/// Before `sync`/`syncfs` of the volume: every mapped file's stores.
pub(crate) fn syncing_all() -> Result<(), c_int> {
    if !caching() {
        return Ok(());
    }
    let inos: Vec<u64> = MAPPINGS.lock().caches.keys().copied().collect();
    for ino in inos {
        if let Some(writer) = writer_of(ino) {
            write_back(ino, writer)?;
        }
    }
    Ok(())
}

/// After the filesystem accepted `bytes` for `handle`'s file at `offset`.
pub(crate) fn written(handle: u64, offset: u64, bytes: &[u8]) {
    let Some(ino) = cached_ino(handle) else {
        return;
    };
    if let Some(cache) = MAPPINGS.lock().caches.get_mut(&ino) {
        cache.store(offset, bytes);
    }
}

/// After a cursor write of `bytes` to `handle`'s file: they end at the
/// cursor.
pub(crate) fn written_at_cursor(handle: u64, bytes: &[u8]) {
    if cached_ino(handle).is_none() || bytes.is_empty() {
        return;
    }
    if let Ok(cursor) = crate::with_context_raw(|context| context.fs_cursor_unrecorded(Fd(handle)))
    {
        written(handle, cursor.saturating_sub(bytes.len() as u64), bytes);
    }
}

/// After `handle`'s file became `len` bytes long.
pub(crate) fn resized(handle: u64, len: u64) {
    if let Some(ino) = cached_ino(handle) {
        resized_ino(ino, len);
    }
}

/// After the file `ino` became `len` bytes long (a truncation by path, an
/// `O_TRUNC` open).
pub(crate) fn resized_ino(ino: u64, len: u64) {
    if !caching() {
        return;
    }
    if let Some(cache) = MAPPINGS.lock().caches.get_mut(&ino) {
        cache.resize(len);
    }
}

/// After `fallocate` of `[offset, offset + len)` on `handle`'s file: a hole
/// punch or a zeroed range cleared it, and without `keep_size` the file
/// reaches its end.
pub(crate) fn allocated(
    handle: u64,
    offset: u64,
    len: u64,
    mode: patina_dst_abi::FsAllocateMode,
    keep_size: bool,
) {
    let Some(ino) = cached_ino(handle) else {
        return;
    };
    if let Some(cache) = MAPPINGS.lock().caches.get_mut(&ino) {
        let end = offset.saturating_add(len);
        if mode != patina_dst_abi::FsAllocateMode::Reserve {
            cache.zero(offset, end);
        }
        if !keep_size && end > cache.size() {
            cache.resize(end);
        }
    }
}

/// After the filesystem rolled back to its durable image
/// ([`crate::patina_crash`]): every page cache reloads what its file holds
/// now, so a store no write-back or sync made durable is lost with the other
/// unsynced writes, and the views follow their files to the inode numbers the
/// rebuilt image gave them; a file the image lost leaves its views empty.
pub(crate) fn crashed() {
    if !caching() {
        return;
    }
    let files: Vec<(u64, u64)> = {
        let mappings = MAPPINGS.lock();
        mappings
            .caches
            .keys()
            .filter_map(|ino| {
                let desc = mappings
                    .views
                    .all()
                    .find(|(_, _, object)| object.ino() == Some(*ino))
                    .and_then(|(_, _, object)| object.desc())?;
                mappings.descs.get(&desc).map(|handle| (*ino, *handle))
            })
            .collect()
    };
    let mut reloaded = Vec::new();
    for (old, handle) in files {
        let recovered = crate::with_context_raw(|context| {
            let metadata = context.fs_fd_metadata(Fd(handle))?;
            let contents = context.fs_read_at(Fd(handle), 0, metadata.len as usize)?;
            Ok((metadata.ino, contents))
        });
        // A file the durable image does not hold (its name never became
        // durable) has nothing to reload: the views map an empty file, and a
        // touch is `SIGBUS` as after a truncation. The in-process crash has no
        // kernel analogue; this is the page cache agreeing with the image.
        reloaded.push(match recovered {
            Ok((ino, contents)) => (old, ino, contents),
            Err(_) => (old, old, Vec::new()),
        });
    }
    let mut mappings = MAPPINGS.lock();
    mappings.handles.clear();
    let mut rekeyed = BTreeMap::new();
    for (old, ino, contents) in reloaded {
        let Some(mut cache) = mappings.caches.remove(&old) else {
            continue;
        };
        cache.reload(&contents);
        rekeyed.insert(ino, cache);
        let moved: Vec<(usize, usize, Object)> = mappings
            .views
            .all()
            .filter(|(_, _, object)| object.ino() == Some(old))
            .collect();
        for (start, end, object) in moved {
            if let Object::File {
                desc,
                shared,
                maywrite,
                secret,
                ..
            } = object
            {
                let object = Object::File {
                    ino,
                    desc,
                    shared,
                    maywrite,
                    secret,
                };
                mappings.views.set(start, end, object);
            }
        }
    }
    mappings.caches.extend(rekeyed);
    mappings.publish();
}

#[unsafe(no_mangle)]
/// `msync(2)`: 0, or `-errno`. The host judges the flags and the alignment
/// (`EINVAL`) and finds the holes (`ENOMEM`, every view being host memory);
/// then the walk of mm/msync.c: `MS_INVALIDATE` over a locked page is `EBUSY`
/// there (the locks are this module's, so the host cannot see them), and
/// `MS_SYNC` writes back and syncs the file of each SHARED view before that
/// point (`vfs_fsync_range` only `if (vma->vm_flags & VM_SHARED)`), a hole
/// answering `ENOMEM` only after the views past it are synced.
pub extern "C" fn patina_msync(addr: usize, len: usize, flags: c_int) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    crate::abi::raw(msync(addr, len, flags))
}

pub(crate) fn msync(addr: usize, len: usize, flags: c_int) -> crate::abi::SysResult<i64> {
    'result: {
        let result = host(Syscall::N_msync, [addr, len, flags as usize, 0, 0, 0]);
        if (result != 0 && result != -i64::from(ENOMEM)) || !tracking() {
            break 'result crate::abi::LinuxReturn::new(result)
                .decode()
                .map(|result| result as i64);
        }
        let end = addr.saturating_add(round_up(len).unwrap_or(usize::MAX));
        let (files, busy) = {
            let mappings = MAPPINGS.lock();
            let busy = (flags & MS_INVALIDATE != 0)
                .then(|| {
                    mappings
                        .locks
                        .within(addr, end)
                        .first()
                        .map(|(from, _, _)| *from)
                })
                .flatten();
            let mut files: Vec<(u64, u64, bool)> = if flags & MS_SYNC == 0 {
                Vec::new()
            } else {
                mappings
                    .views
                    .within(addr, busy.unwrap_or(end))
                    .into_iter()
                    .filter(|(_, _, object)| object.is_shared())
                    .filter_map(|(_, _, object)| {
                        let handle = mappings.descs.get(&object.desc()?)?;
                        Some((object.ino()?, *handle, object.is_secret()))
                    })
                    .collect()
            };
            files.sort_unstable();
            files.dedup_by_key(|(ino, _, _)| *ino);
            (files, busy)
        };
        crate::LAST_BOUNDARY_SYMBOL.store(c"msync".as_ptr().cast_mut(), Ordering::Relaxed);
        for (ino, handle, secret) in files {
            // Secret memory has no `fsync` operation (`vfs_fsync_range`).
            if secret {
                break 'result Err(crate::abi::Errno::new(EINVAL));
            }
            if let Some(writer) = writer_of(ino)
                && let Err(errno) = write_back(ino, writer)
            {
                break 'result Err(crate::abi::Errno::new(errno));
            }
            if let Err(errno) = crate::with_context(|context| context.fs_sync(Fd(handle))) {
                break 'result Err(crate::abi::Errno::new(errno));
            }
        }
        if busy.is_some() {
            break 'result Err(crate::abi::Errno::new(crate::EBUSY));
        }
        crate::abi::LinuxReturn::new(result)
            .decode()
            .map(|result| result as i64)
    }
}
