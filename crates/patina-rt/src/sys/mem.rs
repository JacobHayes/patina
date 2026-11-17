//! Memory placement: the runtime chooses every address the kernel would have chosen.

use super::*;
use crate::state::{ctl, proc};
use proto::layout::*;

const MAP_32BIT: u64 = 0x40;
const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;
const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;
const MADV_COLLAPSE: u64 = 25;

fn page_up(x: u64) -> u64 {
    x.wrapping_add(PAGE - 1) & !(PAGE - 1)
}

/// Does `[a, a+len)` touch the runtime's region?
fn hits_runtime(a: u64, len: u64) -> bool {
    let end = a.saturating_add(len);
    end > RT_BASE && a < RT_REGION_END
}

/// Next address from the top-down cursor (never reused within an image).
fn take(len: u64) -> Option<u64> {
    let p = proc();
    let len = page_up(len);
    let a = p.mmap_cursor.checked_sub(len)?;
    if a < MMAP_FLOOR {
        return None;
    }
    p.mmap_cursor = a;
    Some(a)
}

fn mmap_place(call: &mut dyn Call) -> i64 {
    let [addr, len, prot, flags, fd, off] = args(call);
    if len == 0 {
        return -e::EINVAL;
    }
    if flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0 {
        if hits_runtime(addr, page_up(len)) {
            return -e::ENOMEM;
        }
        return raw(call);
    }
    if flags & MAP_32BIT != 0 {
        return -e::ENOMEM;
    }
    let f = flags | MAP_FIXED_NOREPLACE;
    // The guest's hint, when that range is free.
    if addr != 0
        && addr & (PAGE - 1) == 0
        && !hits_runtime(addr, page_up(len))
        && addr.checked_add(page_up(len)).is_some()
    {
        let r = unsafe { sc6(nr::MMAP, addr, len, prot, f, fd, off) };
        if r as u64 == addr {
            return r;
        }
        if r >= 0 {
            unsafe { sc2(nr::MUNMAP, r as u64, len) };
        } else if r != -e::EEXIST && r != -e::ENOMEM && r != -e::EPERM {
            return r;
        }
    }
    loop {
        let Some(a) = take(len) else {
            return -e::ENOMEM;
        };
        let r = unsafe { sc6(nr::MMAP, a, len, prot, f, fd, off) };
        if r != -e::EEXIST {
            return r;
        }
    }
}

fn brk(call: &mut dyn Call) -> i64 {
    let p = proc();
    let want = call.arg(0);
    let cur = p.brk_cur;
    if !(BRK_BASE..=BRK_BASE + BRK_SIZE).contains(&want) {
        return cur as i64;
    }
    let (old_end, new_end) = (page_up(cur), page_up(want));
    if new_end > old_end {
        let r = unsafe {
            sc3(
                nr::MPROTECT,
                old_end,
                new_end - old_end,
                PROT_READ | PROT_WRITE,
            )
        };
        if r != 0 {
            return cur as i64;
        }
    } else if new_end < old_end {
        // Fresh inaccessible pages: growing again later yields zeroes, as on Linux.
        let r = unsafe {
            sc6(
                nr::MMAP,
                new_end,
                old_end - new_end,
                0,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE,
                u64::MAX,
                0,
            )
        };
        if r < 0 {
            return cur as i64;
        }
    }
    p.brk_cur = want;
    want as i64
}

fn mremap(call: &mut dyn Call) -> i64 {
    let [old, oldlen, newlen, flags, new, _] = args(call);
    if hits_runtime(old, oldlen) {
        return -e::EINVAL;
    }
    if flags & MREMAP_FIXED != 0 {
        if hits_runtime(new, newlen) {
            return -e::EINVAL;
        }
        return raw(call);
    }
    if flags & MREMAP_MAYMOVE == 0 {
        return raw(call);
    }
    // In place first; if it cannot grow there, move to an address the runtime chooses.
    let r = unsafe { sc6(nr::MREMAP, old, oldlen, newlen, 0, 0, 0) };
    if r != -e::ENOMEM {
        return r;
    }
    let Some(a) = take(newlen) else {
        return -e::ENOMEM;
    };
    unsafe {
        sc6(
            nr::MREMAP,
            old,
            oldlen,
            newlen,
            MREMAP_MAYMOVE | MREMAP_FIXED,
            a,
            0,
        )
    }
}

// ---- memory shared across processes: futex keys ----

const MAP_SHARED: u64 = 1;
const MAP_ANON: u64 = 0x20;

fn mmap(call: &mut dyn Call) -> i64 {
    let [_, len, prot, flags, fd, off] = args(call);
    let r = mmap_place(call);
    if r >= 0 && flags & 3 == 2 && flags & MAP_FIXED != 0 {
        // A private mapping over a shared one: the shared record goes.
        forget_shared(r as u64, page_up(len));
    }
    if r >= 0 && flags & 3 != 0 && flags & 3 != 2 {
        // MAP_SHARED or MAP_SHARED_VALIDATE
        let _ = MAP_SHARED;
        let id = if flags & MAP_ANON != 0 || fd as i64 == -1 {
            // Shared anonymous memory: an id taken from the global sequence number,
            // so it is unique in the run and a function of history.
            (1 << 30) | (ctl().seq.load(Relaxed) & 0x3fff_ffff)
        } else {
            // A shared file mapping: the file's identity (tmpfs inode numbers are
            // a function of creation order).
            let mut st = [0u64; proto::abi::stat::WORDS];
            if unsafe { sc2(nr::FSTAT, fd, st.as_mut_ptr() as u64) } != 0 {
                return r;
            }
            // The device as its mount index (st_dev itself comes from a host-global counter).
            let dev = crate::path::mount_index(st[0])
                .map(|i| i as u64 + 1)
                .unwrap_or(0);
            let h =
                dev.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ st[1].wrapping_mul(0xc2b2_ae3d_27d4_eb4f);
            (h >> 34) & 0x3fff_ffff
        };
        let off = if flags & MAP_ANON != 0 { 0 } else { off };
        record_shared(r as u64, page_up(len), id, off, prot & PROT_WRITE != 0);
    }
    r
}

/// Record a shared mapping. With the table full, a read-only one goes unrecorded (a futex word
/// there can be waited on but never changed by this process); a writable one ends the run,
/// since a process-shared futex in it would be keyed as private and miss the other processes'
/// wakes.
fn record_shared(addr: u64, len: u64, id: u64, off: u64, writable: bool) {
    forget_shared(addr, len);
    let p = proc();
    if p.nshared == p.shared.len() {
        if !writable {
            return;
        }
        crate::sup::capacity(proto::ctl::LIMIT_SHARED, p.shared.len() as u64);
    }
    p.shared[p.nshared] = crate::state::Shared { addr, len, id, off };
    p.nshared += 1;
}

/// `[addr, addr+len)` is no longer mapped as it was: trim or drop overlapping records.
fn forget_shared(addr: u64, len: u64) {
    let p = proc();
    let end = addr.saturating_add(len);
    let mut i = 0;
    while i < p.nshared {
        let m = p.shared[i];
        let mend = m.addr + m.len;
        if mend <= addr || m.addr >= end {
            i += 1;
            continue;
        }
        if addr <= m.addr && end >= mend {
            p.nshared -= 1;
            p.shared[i] = p.shared[p.nshared];
            continue;
        }
        if addr <= m.addr {
            let cut = end - m.addr;
            p.shared[i] = crate::state::Shared {
                addr: end,
                len: m.len - cut,
                id: m.id,
                off: m.off + cut,
            };
        } else {
            // the tail (a hole in the middle keeps the head only)
            p.shared[i].len = addr - m.addr;
        }
        i += 1;
    }
}

/// The futex key the supervisor uses for the word at `addr`: the address itself (keyed by
/// the caller's address space), or, inside a `MAP_SHARED` mapping, (mapping id, offset)
/// with `FUTEX_SHARED_BIT` set, so that every process sharing the memory names one queue.
fn shared_at(addr: u64) -> Option<crate::state::Shared> {
    let p = proc();
    p.shared[..p.nshared]
        .iter()
        .copied()
        .find(|m| addr >= m.addr && addr < m.addr + m.len)
}

pub fn futex_key(addr: u64) -> u64 {
    let p = proc();
    for m in &p.shared[..p.nshared] {
        if addr >= m.addr && addr < m.addr + m.len {
            let off = (m.off + (addr - m.addr)) & 0xffff_ffff;
            return proto::ctl::FUTEX_SHARED_BIT | (m.id << 32) | off;
        }
    }
    addr
}

/// `mem-limit-mb`: the growth of private anonymous memory this call asks for (0: none).
fn anon_growth(call: &dyn Call) -> u64 {
    let a = |i: usize| call.arg(i);
    match call.nr() {
        nr::MMAP
            if a(3) & 3 == 2
                && (a(3) & MAP_ANON != 0 || a(4) as i32 == -1)
                && a(2) & PROT_WRITE != 0 =>
        {
            page_up(a(1))
        }
        nr::BRK => {
            let cur = proc().brk_cur;
            if (BRK_BASE..=BRK_BASE + BRK_SIZE).contains(&a(0)) {
                page_up(a(0)).saturating_sub(page_up(cur))
            } else {
                0
            }
        }
        nr::MREMAP => page_up(a(2)).saturating_sub(page_up(a(1))),
        _ => 0,
    }
}

pub fn handle(call: &mut dyn Call) -> Action {
    if ctl().faults.cfg.mem_limit_bytes != 0
        && matches!(call.nr(), nr::MMAP | nr::BRK | nr::MREMAP)
        && crate::inject::mem_limit_refuses(call.nr(), anon_growth(call))
    {
        return Action::Return(if call.nr() == nr::BRK {
            proc().brk_cur as i64
        } else {
            -e::ENOMEM
        });
    }
    let r = match call.nr() {
        nr::MMAP => {
            // Shared writable mappings of /work files are tracked by the durability log.
            let r = mmap(call);
            if r >= 0 {
                let a = args(call);
                crate::oplog::on_mmap(r as u64, a[1], a[3], a[4] as i32 as i64, a[5]);
                crate::insn::scan::on_mmap(r as u64, a[1], a[2], a[3], a[4], a[5]);
            }
            r
        }
        nr::BRK => brk(call),
        nr::MREMAP => {
            let (old, oldlen) = (call.arg(0), call.arg(1));
            let was = shared_at(old);
            let prev = if hits_runtime(old, oldlen) {
                None
            } else {
                crate::oplog::on_mremap_before(old, oldlen)
            };
            let r = mremap(call);
            crate::oplog::on_mremap_after(r as u64, call.arg(2), prev, r >= 0);
            if r >= 0 {
                crate::insn::patch::relocate(call.arg(0), call.arg(1), r as u64);
                if let Some(m) = was {
                    forget_shared(old, page_up(oldlen));
                    record_shared(
                        r as u64,
                        page_up(call.arg(2)),
                        m.id,
                        m.off + (old - m.addr),
                        true,
                    );
                }
            }
            r
        }
        nr::MUNMAP | nr::MPROTECT => {
            if hits_runtime(call.arg(0), call.arg(1)) {
                -e::EINVAL
            } else {
                if call.nr() == nr::MUNMAP {
                    crate::oplog::on_munmap(call.arg(0), call.arg(1));
                }
                let r = raw(call);
                if r == 0 {
                    if call.nr() == nr::MUNMAP {
                        crate::insn::patch::forget(call.arg(0), call.arg(1));
                        forget_shared(call.arg(0), page_up(call.arg(1)));
                    } else if call.arg(2) & PROT_EXEC != 0 {
                        crate::insn::scan::on_mprotect_exec(call.arg(0), call.arg(1), call.arg(2));
                    }
                }
                r
            }
        }
        // mlock family: memory is never paged out from the guest's point of view.
        nr::MLOCK | nr::MUNLOCK | nr::MLOCK2 => {
            if hits_runtime(call.arg(0), call.arg(1))
                || (call.nr() == nr::MLOCK2 && call.arg(2) & !1 != 0)
            {
                -e::EINVAL
            } else {
                set_class(call, Class::Virt);
                0
            }
        }
        nr::MLOCKALL => {
            if call.arg(0) == 0 || call.arg(0) & !7 != 0 {
                -e::EINVAL
            } else {
                0
            }
        }
        nr::MUNLOCKALL => 0,
        // msync: on tmpfs and anonymous memory the kernel call only validates its arguments.
        nr::MSYNC => {
            if hits_runtime(call.arg(0), call.arg(1)) {
                -e::ENOMEM
            } else {
                let r = raw(call);
                if r == 0 {
                    crate::oplog::on_msync(call.arg(0), call.arg(1), call.arg(2))
                } else {
                    r
                }
            }
        }
        // pkey_mprotect with no key (pkey_alloc is refused, so the key is always -1).
        nr::PKEY_MPROTECT => {
            if hits_runtime(call.arg(0), call.arg(1)) {
                -e::EINVAL
            } else {
                let r = raw(call);
                if r == 0 && call.arg(2) & PROT_EXEC != 0 {
                    crate::insn::scan::on_mprotect_exec(call.arg(0), call.arg(1), call.arg(2));
                }
                r
            }
        }
        nr::MADVISE => {
            let [a, len, mut advice, ..] = args(call);
            if hits_runtime(a, len) {
                -e::EINVAL
            } else if advice == MADV_COLLAPSE {
                // Whether a synchronous collapse into huge pages succeeds (0) or not
                // (EAGAIN) depends on the host's free huge pages and fragmentation. A kernel
                // built without transparent huge pages answers EINVAL; so does the sandbox.
                crate::path::refuse(b"madvise:collapse");
                -e::EINVAL
            } else {
                if advice == MADV_FREE {
                    advice = MADV_DONTNEED;
                }
                unsafe { sc3(nr::MADVISE, a, len, advice) }
            }
        }
        _ => return stop_here(call),
    };
    Action::Return(r)
}
