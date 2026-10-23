//! Regular-file page-cache funnel hooks and synchronization.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

use patina_dst_runtime::{Bookkeeping, Context, RuntimeError};

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
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
pub(crate) fn written(handle: u64, offset: u64, bytes: &[u8]) {
    let Some(ino) = cached_ino(handle) else {
        return;
    };
    if let Some(cache) = MAPPINGS.lock().caches.get_mut(&ino) {
        cache.store(offset, bytes);
    }
}

/// [`written`] from inside the Context closure that made the write, before
/// the closure makes its next one: a vectored write whose later segment is a
/// view of the same file reads the bytes the earlier segment stored, as one
/// kernel write through the page cache does. The handle's inode is asked of
/// the caller's Context through its bookkeeping view (a second gateway would
/// need the lock the caller holds), and the page cache is reached whatever
/// the held Context lock says about shim-critical sections: this is a guest
/// write, not shim memory. Every in-closure hook answers a runtime error
/// that is no filesystem refusal (a crash, one that could not be carried out,
/// a stop) for the closure to end with, as the gateway it stands in for would
/// have ended the call.
pub(crate) fn written_in(
    context: &mut Bookkeeping<'_>,
    handle: u64,
    offset: u64,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    if bytes.is_empty() {
        return Ok(());
    }
    if let Some(ino) = cached_ino_in(context, handle)?
        && let Some(cache) = MAPPINGS.lock().caches.get_mut(&ino)
    {
        cache.store(offset, bytes);
    }
    Ok(())
}

/// [`written_in`] for a cursor write of `bytes` to `handle`'s file: they end
/// at the cursor, wherever the description's `O_APPEND` put them.
pub(crate) fn written_at_cursor_in(
    context: &mut Bookkeeping<'_>,
    handle: u64,
    bytes: &[u8],
) -> Result<(), RuntimeError> {
    if bytes.is_empty() || cached_ino_in(context, handle)?.is_none() {
        return Ok(());
    }
    let Some(cursor) = refused_is_none(context.fs_cursor_unrecorded(Fd(handle)))? else {
        return Ok(());
    };
    written_in(
        context,
        handle,
        cursor.saturating_sub(bytes.len() as u64),
        bytes,
    )
}

/// [`reading`] from inside the Context closure that reads, before a vectored
/// read's later segment: an earlier segment may have copied into a view of
/// the same file. A write-back the filesystem refuses or takes short stays
/// dirty and fails nothing.
pub(crate) fn reading_in(context: &mut Context, handle: u64) -> Result<(), RuntimeError> {
    let Some(ino) = cached_ino_in(&mut context.bookkeeping(), handle)? else {
        return Ok(());
    };
    let Some(writer) = writer_of(ino) else {
        return Ok(());
    };
    let written = write_back_through(
        ino,
        |offset, bytes| {
            context
                .fs_write_back_at(Fd(writer), offset, bytes)
                .map_err(Some)
        },
        || None,
    )
    .1;
    match written {
        Ok(()) | Err(None) => Ok(()),
        Err(Some(error)) => refused_is_none::<()>(Err(error)).map(drop),
    }
}

/// A filesystem refusal (`Effect`) as `None`; any other runtime error is the
/// closure's to end with.
fn refused_is_none<T>(result: Result<T, RuntimeError>) -> Result<Option<T>, RuntimeError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(RuntimeError::Effect(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// [`cached_ino`] from inside a Context closure: the handle's inode is asked
/// of the caller's Context through its bookkeeping view, whatever the held
/// Context lock says about shim-critical sections.
fn cached_ino_in(context: &mut Bookkeeping<'_>, handle: u64) -> Result<Option<u64>, RuntimeError> {
    if !CACHES.load(Ordering::Acquire) {
        return Ok(None);
    }
    let known = MAPPINGS.lock().handles.get(&handle).copied();
    let ino = match known {
        Some(ino) => ino,
        None => {
            let Some(metadata) = refused_is_none(context.fs_fd_metadata_unrecorded(Fd(handle)))?
            else {
                return Ok(None);
            };
            MAPPINGS.lock().handles.insert(handle, metadata.ino);
            metadata.ino
        }
    };
    Ok(MAPPINGS.lock().caches.contains_key(&ino).then_some(ino))
}

/// After `handle`'s file became `len` bytes long.
#[cfg_attr(not(any(target_os = "linux", patina_posix_exports)), allow(dead_code))]
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
#[cfg(target_os = "linux")]
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
        // Bookkeeping, as at the first mapping: no injected fault reaches the
        // reload, which reads the whole file.
        let recovered =
            crate::with_bookkeeping(|context| context.fs_fd_metadata_unrecorded(Fd(handle)));
        // A file the durable image does not hold (its name never became
        // durable) has nothing to reload: the views map an empty file, and a
        // touch is `SIGBUS` as after a truncation. The in-process crash has no
        // kernel analogue; this is the page cache agreeing with the image.
        reloaded.push(match recovered {
            Ok(metadata) => (
                old,
                metadata.ino,
                cache::file_bytes(handle, metadata.len as usize),
            ),
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
            mappings.views.set(start, end, object.renumbered(ino));
        }
    }
    mappings.caches.extend(rekeyed);
    mappings.publish();
}

/// `msync(2)` as Linux judges it: the host's answer for the range, then a
/// write-back and a sync of every file a shared view in it maps under
/// `MS_SYNC`.
#[cfg(target_os = "linux")]
pub(crate) fn msync(addr: usize, len: usize, flags: c_int) -> crate::abi::SysResult<i64> {
    'result: {
        // The arena's region, as a range nothing maps, once the kernel has
        // judged the flags and the start.
        const MS_ASYNC: c_int = 1;
        let judged = flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) == 0
            && flags & (MS_ASYNC | MS_SYNC) != MS_ASYNC | MS_SYNC
            && addr.is_multiple_of(PAGE);
        if judged && in_arena(addr, len) {
            break 'result Err(crate::abi::Errno::new(ENOMEM));
        }
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
