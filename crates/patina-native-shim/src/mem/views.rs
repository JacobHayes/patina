//! The views the address-space rows keep: a view joins the table when the
//! host maps it, holds its description, and on leaving writes back what it
//! stored and lets go of the page cache and the description no other view
//! needs. Shared by every platform's address-space rows.

#![deny(clippy::undocumented_unsafe_blocks)]

use super::*;

/// Map `rounded` bytes of the page file `fd` (a page cache's, or a System V
/// segment's) from `offset` as a view of `object` — anywhere, or at `fixed`,
/// replacing what it lands on. `flags` is the mapping type and the host
/// hints. The address, or `-errno`.
pub(super) fn alias(
    fd: c_int,
    offset: usize,
    rounded: usize,
    fixed: Option<usize>,
    prot: c_int,
    flags: c_int,
    object: Object,
) -> i64 {
    // The pieces a fixed view replaces leave the table before the host call
    // and are finished after the new view joins it, so a replaced view of the
    // same file never tears its page cache down.
    let replaced = fixed
        .map(|addr| take_all(addr, addr + rounded))
        .unwrap_or_default();
    let view = host_map(
        fixed.unwrap_or(0),
        rounded,
        prot,
        flags | if fixed.is_some() { MAP_FIXED } else { 0 },
        fd,
        offset,
    );
    if view < 0 {
        restore(replaced);
        return view;
    }
    let start = view as usize;
    #[cfg(target_os = "linux")]
    if fixed.is_none() {
        crate::arena::refuse_placement(start, rounded);
    }
    if let Some(desc) = object.desc()
        && hold(desc).is_err()
    {
        host_unmap(start, rounded);
        finish(replaced);
        return fail(crate::EBADF);
    }
    {
        let mut mappings = MAPPINGS.lock();
        mappings.views.set(start, start + rounded, object);
        if let Some(ino) = object.ino()
            && object.writes_back(ino)
            && let Some(cache) = mappings.caches.get_mut(&ino)
        {
            cache.track(true);
        }
        mappings.publish();
    }
    finish(replaced);
    view
}

/// Hold `desc` for a view: the first view of a description takes a hidden
/// reference in the descriptor table, as a kernel mapping's `get_file`.
pub(super) fn hold(desc: DescId) -> Result<(), c_int> {
    if MAPPINGS.lock().descs.contains_key(&desc) {
        return Ok(());
    }
    let handle = {
        let mut table = crate::fd_table().lock();
        table.retain(desc)?;
        table
            .description(desc)
            .map(|description| description.handle)
            .expect("a retained description exists")
    };
    MAPPINGS.lock().descs.insert(desc, handle);
    Ok(())
}

/// The page file of `ino`'s page cache, created and loaded with all `size`
/// bytes of the file through `handle` when the file is first mapped.
pub(super) fn cache_for(ino: u64, handle: u64, size: u64) -> Result<c_int, i64> {
    if let Some(cache) = MAPPINGS.lock().caches.get(&ino) {
        return Ok(cache.pages.fd);
    }
    let size = usize::try_from(size).map_err(|_| fail(crate::EOVERFLOW))?;
    let cache = Cache::new(PageFile::new(), &cache::file_bytes(handle, size));
    let fd = cache.pages.fd;
    let mut mappings = MAPPINGS.lock();
    mappings.caches.insert(ino, cache);
    mappings.publish();
    Ok(fd)
}

/// Remove `[from, to)` from the address space's per-range state, answering
/// the views it covered (they still hold their descriptions until
/// [`finish`]).
pub(super) fn take_all(from: usize, to: usize) -> Vec<(usize, usize, Object)> {
    let mut mappings = MAPPINGS.lock();
    #[cfg(target_os = "linux")]
    {
        mappings.locks.cut(from, to);
        mappings.policies.cut(from, to);
    }
    let pieces = mappings.views.cut(from, to);
    mappings.publish();
    pieces
}

/// `[addr, addr + len)` is no longer mapped as it was.
pub(super) fn forget(addr: usize, len: usize) {
    if let Some(len) = round_up(len) {
        finish(take_all(addr, addr.saturating_add(len)));
    }
}

/// Put back views [`take_all`] removed for a replacement that did not happen.
pub(super) fn restore(pieces: Vec<(usize, usize, Object)>) {
    let mut mappings = MAPPINGS.lock();
    for (start, end, object) in pieces {
        mappings.views.set(start, end, object);
    }
    mappings.publish();
}

/// The views [`take_all`] removed are gone from the address space: write back
/// and stop shadowing the page caches they leave without a view that may
/// write, drop the page caches they leave without any view, release the
/// descriptions no view holds any more, and tell each segment it lost an
/// attachment.
pub(super) fn finish(pieces: Vec<(usize, usize, Object)>) {
    if pieces.is_empty() {
        return;
    }
    let mut inos: Vec<u64> = pieces
        .iter()
        .filter_map(|(_, _, object)| object.ino())
        .collect();
    inos.sort_unstable();
    inos.dedup();
    for ino in &inos {
        // The write-back goes through a description a dropped view holds.
        let (writer, without_writer) = {
            let mappings = MAPPINGS.lock();
            let writer = pieces
                .iter()
                .filter(|(_, _, object)| object.writes_back(*ino))
                .find_map(|(_, _, object)| {
                    object
                        .desc()
                        .and_then(|desc| mappings.descs.get(&desc).copied())
                });
            let without_writer = !mappings
                .views
                .all()
                .any(|(_, _, object)| object.writes_back(*ino));
            (writer, without_writer)
        };
        if let (Some(writer), true) = (writer, without_writer) {
            // Nothing is left to fail: a write-back the filesystem refuses here
            // loses those stores, as a kernel's failed writeback of an evicted
            // page does.
            let _ = write_back(*ino, writer);
            if let Some(cache) = MAPPINGS.lock().caches.get_mut(ino) {
                cache.track(false);
            }
        }
    }
    settle(&inos);
    let released: Vec<DescId> = {
        let mut mappings = MAPPINGS.lock();
        let held: Vec<DescId> = mappings
            .views
            .all()
            .filter_map(|(_, _, o)| o.desc())
            .collect();
        let gone: Vec<DescId> = mappings
            .descs
            .keys()
            .copied()
            .filter(|desc| !held.contains(desc))
            .collect();
        for desc in &gone {
            mappings.descs.remove(desc);
        }
        gone
    };
    for desc in released {
        let released = crate::fd_table().lock().release(desc);
        if let Ok(Some(release)) = released {
            let _ = crate::release_description(release);
        }
    }
    #[cfg(target_os = "linux")]
    for (_, _, object) in pieces {
        if let Object::Segment { id, .. } = object {
            crate::thread::ipc::shm_detached(id);
        }
    }
}

/// Drop the page caches of `inos` no view maps any more.
pub(super) fn settle(inos: &[u64]) {
    let mut unused = Vec::new();
    {
        let mut mappings = MAPPINGS.lock();
        for ino in inos {
            if !mappings
                .views
                .all()
                .any(|(_, _, object)| object.ino() == Some(*ino))
            {
                if let Some(cache) = mappings.caches.remove(ino) {
                    unused.push(cache);
                }
                mappings.handles.retain(|_, mapped| mapped != ino);
            }
        }
        mappings.publish();
    }
    drop(unused);
}

/// Write back the pages the views of `ino` changed since the last
/// write-back, through `handle` (a description open for writing), one
/// recorded write per page. A page the filesystem refused stays dirty for
/// the next write-back.
pub(super) fn write_back(ino: u64, handle: u64) -> Result<(), c_int> {
    write_back_counted(ino, handle).1
}

/// [`write_back`], also answering whether it wrote to the file at all: a
/// write-back that fails partway may have written its first pages.
pub(super) fn write_back_counted(ino: u64, handle: u64) -> (bool, Result<(), c_int>) {
    let pages = match MAPPINGS.lock().caches.get(&ino) {
        Some(cache) => cache.dirty_pages(),
        None => return (false, Ok(())),
    };
    let tried = !pages.is_empty();
    let written_all = || {
        for (offset, bytes) in pages {
            let written = crate::with_context_raw(|context| {
                context.fs_write_back_at(Fd(handle), offset, &bytes)
            })?;
            if let Some(cache) = MAPPINGS.lock().caches.get_mut(&ino) {
                cache.accept(offset, &bytes[..written.min(bytes.len())]);
            }
            if written < bytes.len() {
                return Err(crate::EIO);
            }
        }
        Ok(())
    };
    (tried, written_all())
}

/// The pages of the file `handle` is open on that a store through a shared
/// view changed and no write-back has written yet, by index: dirty on 6.8
/// from the write fault on (`cachestat`).
#[cfg(target_os = "linux")]
pub(crate) fn view_dirty_pages(handle: u64) -> Vec<u64> {
    let Some(ino) = cached_ino(handle) else {
        return Vec::new();
    };
    MAPPINGS
        .lock()
        .caches
        .get(&ino)
        .map(|cache| {
            cache
                .dirty_pages()
                .into_iter()
                .map(|(offset, _)| offset / PAGE as u64)
                .collect()
        })
        .unwrap_or_default()
}

/// The inode `handle` is open on, when a page cache exists for it.
pub(super) fn cached_ino(handle: u64) -> Option<u64> {
    if !caching() {
        return None;
    }
    let known = MAPPINGS.lock().handles.get(&handle).copied();
    let ino = match known {
        Some(ino) => ino,
        None => {
            let ino =
                crate::with_context_raw(|context| context.fs_fd_metadata_unrecorded(Fd(handle)))
                    .ok()?
                    .ino;
            MAPPINGS.lock().handles.insert(handle, ino);
            ino
        }
    };
    MAPPINGS.lock().caches.contains_key(&ino).then_some(ino)
}

/// A handle a write-back of `ino` can go through: a view that may write.
pub(super) fn writer_of(ino: u64) -> Option<u64> {
    let mappings = MAPPINGS.lock();
    writer_among(&mappings, ino)
}

/// The driver handle of the writable shared views of `ino` that was opened
/// first (the lowest handle), whatever address each view sits at. The
/// write-back is a recorded operation that names its handle, and view
/// addresses come from the host (ASLR), so choosing by address would let
/// two runs of one seed, or a record and its replay, write back through
/// different descriptions.
pub(super) fn writer_among(mappings: &Mappings, ino: u64) -> Option<u64> {
    mappings
        .views
        .all()
        .filter(|(_, _, object)| object.writes_back(ino))
        .filter_map(|(_, _, object)| object.desc())
        .filter_map(|desc| mappings.descs.get(&desc).copied())
        .min()
}
