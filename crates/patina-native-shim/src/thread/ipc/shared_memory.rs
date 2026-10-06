//! System V shared-memory operations.

use super::*;

// ---------------------------------------------------------------- shared memory

/// `shmget(2)`.
pub(crate) fn shmget(key: i32, size: usize, flags: i32) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    let mut state = lock_state();
    let result = get_or_create(
        &mut state.ipc.shm,
        key,
        flags,
        |segment| {
            if segment.size < size {
                Err(EINVAL)
            } else {
                Ok(())
            }
        },
        || {
            if !(1..=SHMMAX).contains(&size) {
                return Err(EINVAL);
            }
            if flags & SHM_HUGETLB != 0 {
                // `newseg`: a pool the machine has, then `hugetlb_file_setup`,
                // which lets only `CAP_IPC_LOCK` or the `hugetlb_shm_group`
                // back a segment with huge pages — not the one identity.
                let sizelog = (flags >> SHM_HUGE_SHIFT) as u32 & SHM_HUGE_MASK;
                if crate::mem::huge_page_size(sizelog).is_none() {
                    return Err(EINVAL);
                }
                return Err(crate::EPERM);
            }
            let pages = crate::mem::Segment::new(size);
            Ok(Segment {
                pages,
                size,
                atime: 0,
                dtime: 0,
                ctime: now(),
                lpid: 0,
            })
        },
    );
    answer(result)
}

/// `shmat(2)`: the attachment's address, or `-errno`.
pub(crate) fn shmat(id: i32, addr: usize, flags: i32) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if id < 0 {
        return fail(EINVAL);
    }
    let mut addr = addr;
    if addr != 0 {
        if !addr.is_multiple_of(SHMLBA) {
            if flags & SHM_RND == 0 {
                return fail(EINVAL);
            }
            addr -= addr % SHMLBA;
            if addr == 0 && flags & SHM_REMAP != 0 {
                return fail(EINVAL);
            }
        }
    } else if flags & SHM_REMAP != 0 {
        return fail(EINVAL);
    }
    let (mut prot, mut access) = if flags & SHM_RDONLY != 0 {
        (PROT_READ, S_IRUGO)
    } else {
        (PROT_READ | PROT_WRITE, S_IRUGO | S_IWUGO)
    };
    if flags & SHM_EXEC != 0 {
        prot |= PROT_EXEC;
        access |= S_IXUGO;
    }
    let (fd, size) = {
        let state = lock_state();
        let (perm, segment) = match state.ipc.shm.get(id) {
            Ok(found) => found,
            Err(errno) => return fail(errno),
        };
        if !perm.allows(access) {
            return fail(EACCES);
        }
        (segment.pages.fd(), segment.size)
    };
    let fixed = (addr != 0).then_some(addr);
    let attached = crate::mem::attach(id, fd, size, fixed, flags & SHM_REMAP != 0, prot);
    if attached >= 0 {
        let mut state = lock_state();
        if let Ok((_, segment)) = state.ipc.shm.get_mut(id) {
            segment.atime = now();
            segment.lpid = PID;
        }
    }
    attached
}

/// `shmdt(2)`.
pub(crate) fn shmdt(addr: usize) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if !addr.is_multiple_of(crate::mem::PAGE) {
        return fail(EINVAL);
    }
    let size_of = |id: i32| {
        lock_state()
            .ipc
            .shm
            .get(id)
            .ok()
            .map(|(_, segment)| segment.size)
    };
    match crate::mem::detach(addr, size_of) {
        Ok(_) => 0,
        Err(errno) => fail(errno),
    }
}

/// A view of segment `id` went away (`shm_close`): stamp the detach, and
/// destroy a segment marked for destruction once nothing attaches it.
pub(crate) fn shm_detached(id: i32) {
    let mut state = lock_state();
    let Ok((perm, segment)) = state.ipc.shm.get_mut(id) else {
        return;
    };
    segment.dtime = now();
    segment.lpid = PID;
    if perm.mode & SHM_DEST != 0 && crate::mem::attachments(id) == 0 {
        destroy_segment(&mut state, id);
    }
}

fn destroy_segment(state: &mut ThreadRuntime, id: i32) {
    // The segment's pages go with it.
    state.ipc.shm.remove(id);
}

/// `shmctl(2)`.
///
/// # Safety
/// `buf` must be NULL or valid for the command's `shmid_ds`.
pub(crate) unsafe fn shmctl(id: i32, cmd: i32, buf: *mut ShmidDs) -> i64 {
    if let Err(errno) = boundary() {
        return fail(errno);
    }
    if cmd < 0 || id < 0 {
        return fail(EINVAL);
    }
    match cmd {
        IPC_INFO | SHM_INFO | SHM_STAT | SHM_STAT_ANY | SHM_LOCK | SHM_UNLOCK => {
            i64::from(crate::deny(DENY_TABLES))
        }
        IPC_STAT => {
            let stat = {
                let state = lock_state();
                let (perm, segment) = match state.ipc.shm.get(id) {
                    Ok(found) => found,
                    Err(errno) => return fail(errno),
                };
                if !perm.allows(S_IRUGO) {
                    return fail(EACCES);
                }
                ShmidDs {
                    perm: perm.stat(),
                    segsz: segment.size as u64,
                    atime: segment.atime,
                    dtime: segment.dtime,
                    ctime: segment.ctime,
                    cpid: PID,
                    lpid: segment.lpid,
                    nattch: crate::mem::attachments(id) as u64,
                    unused: [0; 2],
                }
            };
            // SAFETY: per this function's contract.
            unsafe { copy_out(buf, stat) }
        }
        IPC_SET | IPC_RMID => {
            let from = if cmd == IPC_SET {
                if buf.is_null() {
                    return fail(EFAULT);
                }
                // SAFETY: per this function's contract.
                Some(unsafe { (*buf).perm })
            } else {
                None
            };
            let mut state = lock_state();
            let (perm, segment) = match state.ipc.shm.get_mut(id) {
                Ok(found) => found,
                Err(errno) => return fail(errno),
            };
            match from {
                Some(from) => {
                    if let Err(errno) = perm.update(&from) {
                        return fail(errno);
                    }
                    segment.ctime = now();
                }
                None => {
                    // `do_shm_rmid`: the key goes at once; the segment lives
                    // while anything attaches it.
                    perm.key = IPC_PRIVATE;
                    perm.mode |= SHM_DEST;
                    if crate::mem::attachments(id) == 0 {
                        destroy_segment(&mut state, id);
                    }
                }
            }
            0
        }
        _ => fail(EINVAL),
    }
}
