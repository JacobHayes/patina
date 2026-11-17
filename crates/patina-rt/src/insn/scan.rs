//! Find and patch instruction sites in executable mappings, before the guest can run them.
//!
//! Called by the loader for each executable `PT_LOAD`, by the `mmap` handler for executable
//! mappings, and by `mprotect` when a range becomes executable. The rule (`proto::insn`, shared
//! with `patina __insn-scan`, which the false-positive audit runs) is applied by
//! `crate::arch::insn::scan_range`; this module decides which mappings are scanned.

use crate::insn::bump;
use crate::raw::*;
use crate::state::ctl;

/// The file a mapping came from: descriptor and file offset of the mapping's first byte.
#[derive(Clone, Copy)]
pub struct FileId {
    pub fd: u64,
    pub off: u64,
}

/// Scan `[va, va + len)` (mapped, readable) and patch the confirmed sites. `writable`: the
/// pages are writable now; else they are made writable for each patch and given `prot` back.
pub fn scan_exec(va: u64, len: u64, file: Option<FileId>, writable: bool, prot: u64) {
    let c = ctl();
    // Pages wholly past the end of the file would raise SIGBUS when read.
    let len =
        match file.and_then(|f| crate::sys::fs::fstat_raw(f.fd as i64).map(|st| (f, st.size()))) {
            Some((f, size)) => len.min(((size.saturating_sub(f.off)) + 4095) & !4095),
            None => len,
        };
    if len == 0 {
        return;
    }
    bump(&c.insn.scanned_mappings, 1);
    bump(&c.insn.scanned_bytes, len);
    // Execute-only memory (the kernel backs PROT_EXEC alone with an access-disabled pkey) cannot
    // be read: make it readable for the scan.
    let unreadable = prot & PROT_READ == 0;
    if unreadable {
        unsafe { sc3(nr::MPROTECT, va, len, prot | PROT_READ) };
    }
    crate::arch::insn::scan_range(va, len, file, writable, prot | PROT_READ);
    if unreadable {
        unsafe { sc3(nr::MPROTECT, va, len, prot) };
    }
}

pub fn pread(fd: u64, buf: &mut [u8], off: u64) -> bool {
    let r = unsafe {
        sc4(
            nr::PREAD64,
            fd,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            off,
        )
    };
    r == buf.len() as i64
}

/// `mmap` succeeded at `[a, a + len)` with `prot`/`flags` on `fd` at `off`.
pub fn on_mmap(a: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) {
    // A fixed mapping replaces whatever was there, patched sites included.
    super::patch::forget(a, len);
    if prot & PROT_EXEC == 0 {
        return;
    }
    if flags & MAP_ANONYMOUS != 0 {
        bump(&ctl().insn.unscanned_exec_mappings, 1);
        return;
    }
    if flags & MAP_SHARED != 0 {
        // A patch would write `ud2` into the file itself (visible to every reader), and the bytes
        // can change later through another mapping or a write: not patched, labelled.
        bump(&ctl().insn.unscanned_exec_mappings, 1);
        return;
    }
    scan_exec(
        a,
        len,
        Some(FileId { fd, off }),
        prot & PROT_WRITE != 0,
        prot,
    );
}

/// `mprotect` succeeded and made `[a, a + len)` executable: classify the range by the kernel's
/// own map (anonymous and shared memory are counted, private file mappings are scanned).
pub fn on_mprotect_exec(a: u64, len: u64, prot: u64) {
    let mut buf = [0u8; 32768];
    let n = crate::loader::read_file(b"/proc/self/maps\0", &mut buf);
    let end = a.saturating_add(len);
    for line in buf[..n].split(|&c| c == b'\n') {
        let mut f = line.split(|&c| c == b' ').filter(|s| !s.is_empty());
        let (Some(range), Some(perms), Some(offs), Some(_dev), Some(ino)) =
            (f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        let dash = range.iter().position(|&c| c == b'-').unwrap_or(0);
        let (s, e) = (hex(&range[..dash]), hex(&range[dash + 1..]));
        if e <= a || s >= end {
            continue;
        }
        let (lo, hi) = (s.max(a), e.min(end));
        if dec(ino) == 0 || perms.get(3) == Some(&b's') {
            bump(&ctl().insn.unscanned_exec_mappings, 1);
            continue;
        }
        let path = f.next().unwrap_or(b"");
        let mut p = [0u8; 512];
        if path.is_empty() || path.len() >= p.len() || path[0] != b'/' {
            bump(&ctl().insn.unscanned_exec_mappings, 1);
            continue;
        }
        p[..path.len()].copy_from_slice(path);
        let fd = unsafe {
            sc4(
                nr::OPENAT,
                (-100i64) as u64,
                p.as_ptr() as u64,
                0o2000000,
                0,
            )
        };
        let file = (fd >= 0).then(|| FileId {
            fd: fd as u64,
            off: hex(offs) + (lo - s),
        });
        scan_exec(lo, hi - lo, file, prot & PROT_WRITE != 0, prot);
        if fd >= 0 {
            unsafe { sc1(nr::CLOSE, fd as u64) };
        }
    }
}

fn hex(s: &[u8]) -> u64 {
    s.iter()
        .map_while(|&c| (c as char).to_digit(16))
        .fold(0, |v, d| v * 16 + d as u64)
}
fn dec(s: &[u8]) -> u64 {
    s.iter()
        .map_while(|&c| (c as char).to_digit(10))
        .fold(0, |v, d| v * 10 + d as u64)
}
