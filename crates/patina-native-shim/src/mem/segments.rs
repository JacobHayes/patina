//! System V attachments, memory policies, and residency queries.

use super::*;

// ---------------------------------------------------------------- System V segments

/// The pages of a System V shared memory segment: a host memfd of the
/// segment's size, which attachments map.
pub(crate) struct Segment(Memfd);

impl Segment {
    pub(crate) fn new(size: usize) -> Segment {
        let mut memfd = Memfd::new();
        memfd.set_len(size as u64);
        Segment(memfd)
    }

    pub(crate) fn fd(&self) -> c_int {
        self.0.fd
    }
}

/// `shmat`'s mapping of segment `id`: the whole segment (`len` bytes),
/// anywhere or at `addr`, with `prot`. Without `remap` a fixed address must be
/// free (`EINVAL`, as `do_shmat`'s intersection check answers); with it the
/// attachment replaces what it lands on. The address, or `-errno`.
pub(crate) fn attach(
    id: i32,
    fd: c_int,
    len: usize,
    addr: Option<usize>,
    remap: bool,
    prot: c_int,
) -> i64 {
    let Some(rounded) = round_up(len) else {
        return fail(EINVAL);
    };
    let lock = match lock_request(0, rounded) {
        Ok(lock) => lock,
        Err(errno) => return fail(errno),
    };
    let claimed = matches!((addr, remap), (Some(_), false));
    if let (Some(addr), true) = (addr, claimed) {
        let claim = host(
            Syscall::N_mmap,
            [
                addr,
                rounded,
                0,
                (MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE) as usize,
                usize::MAX,
                0,
            ],
        );
        if claim < 0 {
            return fail(if claim == fail(crate::EEXIST) {
                EINVAL
            } else {
                (-claim) as c_int
            });
        }
    }
    let object = Object::Segment {
        id,
        maywrite: prot & PROT_WRITE != 0,
    };
    let view = alias(fd, 0, rounded, addr, prot, MAP_SHARED, object, lock);
    if view < 0 && claimed {
        host(Syscall::N_munmap, [addr.unwrap_or(0), rounded, 0, 0, 0, 0]);
    }
    view
}

/// `shmdt`: unmap the attachment that starts at `addr` — every piece of it
/// within the segment's `len` bytes from there — and answer its segment's id,
/// or `EINVAL` when no attachment starts at `addr`.
pub(crate) fn detach(addr: usize, len: impl Fn(i32) -> Option<usize>) -> Result<i32, c_int> {
    let id = match MAPPINGS.lock().views.containing(addr) {
        Some((start, _, Object::Segment { id, .. })) if start == addr => id,
        _ => return Err(EINVAL),
    };
    let end = addr.saturating_add(len(id).and_then(round_up).unwrap_or(PAGE));
    let pieces: Vec<(usize, usize)> = MAPPINGS
        .lock()
        .views
        .within(addr, end)
        .into_iter()
        .filter(
            |(_, _, object)| matches!(object, Object::Segment { id: mapped, .. } if *mapped == id),
        )
        .map(|(start, piece_end, _)| (start, piece_end))
        .collect();
    for (start, piece_end) in pieces {
        host(Syscall::N_munmap, [start, piece_end - start, 0, 0, 0, 0]);
        forget(start, piece_end - start);
    }
    Ok(id)
}

/// How many views attach segment `id`: its `shm_nattch`.
pub(crate) fn attachments(id: i32) -> usize {
    MAPPINGS
        .lock()
        .views
        .all()
        .filter(
            |(_, _, object)| matches!(object, Object::Segment { id: mapped, .. } if *mapped == id),
        )
        .count()
}

// ---------------------------------------------------------------- memory policies

/// The policy of the range `[from, to)`: `None` is the default one.
pub(crate) fn set_policy(from: usize, to: usize, policy: Option<Policy>) {
    let mut mappings = MAPPINGS.lock();
    mappings.policies.cut(from, to);
    if let Some(policy) = policy {
        mappings.policies.set(from, to, policy);
    }
    mappings.publish();
}

/// The policy `addr` has, if its range has one of its own.
pub(crate) fn policy_at(addr: usize) -> Option<Policy> {
    MAPPINGS.lock().policies.at(addr)
}

/// The ranges within `[from, to)` that have a policy of their own.
pub(crate) fn policies_in(from: usize, to: usize) -> Vec<(usize, usize, Policy)> {
    MAPPINGS.lock().policies.within(from, to)
}

/// Whether every page of `[addr, addr + len)` is mapped: host `mincore`,
/// which answers `ENOMEM` for a range with a hole and touches nothing, over
/// chunks a stack vector holds.
pub(crate) fn mapped(addr: usize, len: usize) -> bool {
    const CHUNK: usize = 256;
    let mut vector = [0u8; CHUNK];
    let end = addr.saturating_add(len.max(1));
    let mut at = addr;
    while at < end {
        let span = (end - at).min(CHUNK * PAGE);
        if host(
            Syscall::N_mincore,
            [at, span, vector.as_mut_ptr() as usize, 0, 0, 0],
        ) != 0
        {
            return false;
        }
        at += span;
    }
    true
}

/// Whether the page at `addr` is mapped and resident.
pub(crate) fn resident(addr: usize) -> Option<bool> {
    let mut vector = [0u8; 1];
    let page = addr & !(PAGE - 1);
    (host(
        Syscall::N_mincore,
        [page, PAGE, vector.as_mut_ptr() as usize, 0, 0, 0],
    ) == 0)
        .then_some(vector[0] & 1 != 0)
}

/// Read-fault the page at `addr` in, as `get_user_pages` does for a lookup:
/// `false` when no fault reaches it (unmapped, or `PROT_NONE`).
pub(crate) fn fault_in(addr: usize) -> bool {
    require_populate();
    host(
        Syscall::N_madvise,
        [addr & !(PAGE - 1), PAGE, MADV_POPULATE_READ, 0, 0, 0],
    ) == 0
}
