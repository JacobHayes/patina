//! The side table of patched sites and the patch itself.
//!
//! A site is keyed by the address the patch is written at, and keeps the bytes it replaced.
//! The patch is `crate::arch::insn::PATCH`: on x86_64 `ud2` (`0F 0B`) over the two opcode
//! bytes `0F C7` or `F3 90` (prefixes before them and the ModRM byte after them stay, so the
//! CPU still decodes one instruction starting at the same first byte, and it raises #UD there:
//! SIGILL with the instruction pointer at the first prefix); on arm64 `udf #0x7061` over the
//! whole word. The table is per process (runtime memory: copied by fork, fresh after execve).
//! Unmapping or replacing a range drops its entries; `mremap` moves them; `mprotect` updates
//! the protection they record; discarding the pages (`MADV_DONTNEED`) scans them again
//! (`repatch`).

use crate::raw::*;
use core::cell::UnsafeCell;

pub const CAP: usize = 4096;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Entry {
    pub addr: u64,
    /// The bytes the patch replaced (the first `PATCH.len()`).
    pub orig: [u8; 4],
    /// `proto::insn::SiteKind` as u8.
    pub kind: u8,
    /// The mapping's protection bits (low byte): arm64 asks whether the page is guarded
    /// (`PROT_BTI`).
    pub prot: u8,
    _pad: [u8; 2],
}

const EMPTY: Entry = Entry {
    addr: 0,
    orig: [0; 4],
    kind: 0,
    prot: 0,
    _pad: [0; 2],
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

/// Sites this process's table can still take.
pub fn room() -> usize {
    CAP - table().n
}

fn insert(addr: u64, orig: [u8; 4], kind: u8, prot: u8) -> bool {
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
        prot,
        _pad: [0; 2],
    };
    t.n += 1;
    true
}

/// The pages of `[a, a + len)` were discarded (`MADV_DONTNEED`): a private copy that held
/// patches is gone and the file's bytes are back. Every site there (and one starting just
/// before, whose patch reaches in) that reads its original bytes again is patched again, with
/// the protection it recorded (`PROT_BTI` included).
pub fn repatch(a: u64, len: u64) {
    let t = table();
    if t.n == 0 {
        return;
    }
    let n = crate::arch::insn::PATCH.len();
    let (i, j) = (
        lower(t, a.saturating_sub(n as u64 - 1)),
        lower(t, page_end(a, len)),
    );
    for k in i..j {
        let e = t.e[k];
        let prot = e.prot as u64;
        let (lo, hi) = (e.addr & !(PAGE - 1), page_end(e.addr, n as u64));
        // Execute-only code is made readable for the comparison.
        let unreadable = prot & PROT_READ == 0;
        if unreadable {
            unsafe { sc3(nr::MPROTECT, lo, hi - lo, prot | PROT_READ) };
        }
        let now = unsafe { core::slice::from_raw_parts(e.addr as *const u8, n) };
        if now == &e.orig[..n] {
            write(e.addr, false, prot);
        } else if unreadable {
            unsafe { sc3(nr::MPROTECT, lo, hi - lo, prot) };
        }
    }
}

/// Drop every entry in `[a, a + len)` (the range was unmapped or replaced).
/// A site is patched in `[a, a + len)`.
pub fn any_in(a: u64, len: u64) -> bool {
    let t = table();
    let i = lower(t, a);
    i < t.n && t.e[i].addr < a.saturating_add(len)
}

pub fn forget(a: u64, len: u64) {
    let t = table();
    if t.n == 0 {
        return;
    }
    let (i, j) = (lower(t, a), lower(t, page_end(a, len)));
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
        insert(new + (m.addr - old), m.orig, m.kind, m.prot);
    }
}

/// `mprotect` gave `[a, a + len)` the protection `prot`: the entries there record it.
pub fn reprotect(a: u64, len: u64, prot: u64) {
    let t = table();
    let (i, j) = (lower(t, a), lower(t, page_end(a, len)));
    for e in &mut t.e[i..j] {
        e.prot = prot as u8;
    }
}

/// `[a, a + len)` was mapped again from its file (`plans::changing` putting back a plan's
/// pages, with protection `prot`): the patches there are written again.
pub fn rewrite(a: u64, len: u64, prot: u64) {
    let t = table();
    let (i, j) = (lower(t, a), lower(t, page_end(a, len)));
    for e in &t.e[i..j] {
        write(e.addr, false, prot);
    }
}

const PAGE: u64 = 4096;

/// The end of `[a, a + len)` rounded up to a page, as `munmap` and `mprotect` take it.
fn page_end(a: u64, len: u64) -> u64 {
    a.saturating_add(len).saturating_add(PAGE - 1) & !(PAGE - 1)
}

/// Write the patch at `op` and record the site. `writable`: the mapping is writable right now
/// (the loader's segments before their final protection); otherwise the pages are made
/// writable for the write and given back `prot`. The mapping is private, so the write makes a
/// private copy of the page. Returns false if the table is full.
pub fn patch(op: u64, kind: u8, writable: bool, prot: u64) -> bool {
    let bytes = crate::arch::insn::PATCH;
    let mut orig = [0u8; 4];
    for (k, o) in orig.iter_mut().enumerate().take(bytes.len()) {
        *o = unsafe { *((op + k as u64) as *const u8) };
    }
    if !insert(op, orig, kind, prot as u8) {
        return false;
    }
    write(op, writable, prot);
    true
}

/// Write the patch at `op`: `patch`'s write, with `prot` given back.
fn write(op: u64, writable: bool, prot: u64) {
    let bytes = crate::arch::insn::PATCH;
    let n = bytes.len() as u64;
    let lo = op & !(PAGE - 1);
    let hi = (op + n + PAGE - 1) & !(PAGE - 1);
    if !writable {
        let r = unsafe { sc3(nr::MPROTECT, lo, hi - lo, prot | PROT_WRITE) };
        if r != 0 {
            crate::sup::host_error(r, nr::MPROTECT, proto::ctl::HE_SYSCALL);
        }
    }
    for (k, &b) in bytes.iter().enumerate() {
        unsafe { core::ptr::write_volatile((op + k as u64) as *mut u8, b) };
    }
    crate::arch::insn::sync_code(op, n);
    if !writable {
        let r = unsafe { sc3(nr::MPROTECT, lo, hi - lo, prot) };
        if r != 0 {
            crate::sup::host_error(r, nr::MPROTECT, proto::ctl::HE_SYSCALL);
        }
    }
}
