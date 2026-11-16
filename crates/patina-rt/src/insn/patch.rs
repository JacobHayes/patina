//! The side table of patched sites and the patch itself.
//!
//! A site is keyed by the address of its `0F` opcode byte. Patching overwrites the two opcode
//! bytes `0F C7` with `ud2` (`0F 0B`); prefixes before them and the ModRM byte after them stay,
//! so the CPU still decodes one instruction starting at the same first byte, and it raises #UD
//! there (SIGILL with the instruction pointer at the first prefix). The table is per process
//! (runtime memory: copied by fork, fresh after execve). Unmapping or replacing a range drops
//! its entries; `mremap` moves them.

use crate::raw::*;
use core::cell::UnsafeCell;

const CAP: usize = 4096;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Entry {
    pub addr: u64,
    pub orig: [u8; 2],
    /// `proto::insn::SiteKind` as u8.
    pub kind: u8,
    _pad: [u8; 5],
}

const EMPTY: Entry = Entry {
    addr: 0,
    orig: [0; 2],
    kind: 0,
    _pad: [0; 5],
};

/// Sorted by address: lookups are a binary search, range operations touch only their entries.
struct Table {
    e: [Entry; CAP],
    n: usize,
}

struct G(UnsafeCell<Table>);
unsafe impl Sync for G {}
static TABLE: G = G(UnsafeCell::new(Table {
    e: [EMPTY; CAP],
    n: 0,
}));

#[allow(clippy::mut_from_ref)]
fn table() -> &'static mut Table {
    unsafe { &mut *TABLE.0.get() }
}

/// Index of the first entry with address >= `a`.
fn lower(t: &Table, a: u64) -> usize {
    let (mut lo, mut hi) = (0, t.n);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if t.e[mid].addr < a {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

pub fn lookup(addr: u64) -> Option<Entry> {
    let t = table();
    let i = lower(t, addr);
    (i < t.n && t.e[i].addr == addr).then(|| t.e[i])
}

fn insert(addr: u64, orig: [u8; 2], kind: u8) -> bool {
    let t = table();
    let i = lower(t, addr);
    if i < t.n && t.e[i].addr == addr {
        return true;
    }
    if t.n == CAP {
        return false;
    }
    t.e.copy_within(i..t.n, i + 1);
    t.e[i] = Entry {
        addr,
        orig,
        kind,
        _pad: [0; 5],
    };
    t.n += 1;
    true
}

/// Drop every entry in `[a, a + len)` (the range was unmapped or replaced).
pub fn forget(a: u64, len: u64) {
    let t = table();
    if t.n == 0 {
        return;
    }
    let (i, j) = (lower(t, a), lower(t, a.saturating_add(len)));
    if i < j {
        t.e.copy_within(j..t.n, i);
        t.n -= j - i;
    }
}

/// Entries of `[old, old + len)` now live at `new + (addr - old)` (`mremap` moved the range).
pub fn relocate(old: u64, len: u64, new: u64) {
    let t = table();
    if t.n == 0 || old == new {
        return;
    }
    let (i, j) = (lower(t, old), lower(t, old.saturating_add(len)));
    let mut moved = [EMPTY; 64];
    let k = (j - i).min(moved.len());
    moved[..k].copy_from_slice(&t.e[i..i + k]);
    forget(old, len);
    for m in &moved[..k] {
        insert(new + (m.addr - old), m.orig, m.kind);
    }
}

const PAGE: u64 = 4096;

/// Overwrite the opcode at `op` with `ud2` and record the site. `writable`: the mapping is
/// writable right now (the loader's segments before their final protection); otherwise the
/// pages are made writable for the write and given back `prot`. The mapping is private, so
/// the write makes a private copy of the page. Returns false if the table is full.
pub fn patch(op: u64, kind: u8, writable: bool, prot: u64) -> bool {
    let orig = unsafe { [*(op as *const u8), *((op + 1) as *const u8)] };
    if !insert(op, orig, kind) {
        return false;
    }
    let lo = op & !(PAGE - 1);
    let hi = (op + 2 + PAGE - 1) & !(PAGE - 1);
    if !writable {
        let r = unsafe { sc3(nr::MPROTECT, lo, hi - lo, prot | PROT_WRITE) };
        if r != 0 {
            crate::sup::host_error(r, nr::MPROTECT, proto::ctl::HE_SYSCALL);
        }
    }
    unsafe {
        core::ptr::write_volatile(op as *mut u8, 0x0f);
        core::ptr::write_volatile((op + 1) as *mut u8, 0x0b);
    }
    if !writable {
        let r = unsafe { sc3(nr::MPROTECT, lo, hi - lo, prot) };
        if r != 0 {
            crate::sup::host_error(r, nr::MPROTECT, proto::ctl::HE_SYSCALL);
        }
    }
    true
}
