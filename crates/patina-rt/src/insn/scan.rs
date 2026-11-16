//! Find and patch `rdrand`/`rdseed` sites in executable mappings, before the guest can run them.
//!
//! Called by the loader for each executable `PT_LOAD`, by the `mmap` handler for executable
//! mappings, and by `mprotect` when a range becomes executable. The rule is
//! `proto::insn` (shared with `patina insn-scan`, which the false-positive audit runs): byte
//! candidates, each confirmed by a linear sweep from the nearest function symbol of the file
//! (`.symtab`, `.dynsym`) or from the start of the mapping.

use crate::insn::bump;
use crate::raw::*;
use crate::state::ctl;
use proto::insn::{candidates, confirm, sweep_start, SiteKind, Verdict};

/// The file a mapping came from: descriptor and file offset of the mapping's first byte.
#[derive(Clone, Copy)]
pub struct FileId {
    pub fd: u64,
    pub off: u64,
}

const MAX_CANDS: usize = 256;

/// Scan `[va, va + len)` (mapped, readable) and patch the confirmed sites. `writable`: the
/// pages are writable now; else they are made writable for each patch and given `prot` back.
pub fn scan_exec(va: u64, len: u64, file: Option<FileId>, writable: bool, prot: u64) {
    let c = ctl();
    // Pages wholly past the end of the file would raise SIGBUS when read.
    let len = match file.and_then(|f| crate::sys::fs::fstat_raw(f.fd as i64).map(|st| (f, st[6]))) {
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
    scan_range(va, len, file, writable, prot | PROT_READ);
    if unreadable {
        unsafe { sc3(nr::MPROTECT, va, len, prot) };
    }
}

fn scan_range(va: u64, len: u64, file: Option<FileId>, writable: bool, prot: u64) {
    let c = ctl();
    let code = unsafe { core::slice::from_raw_parts(va as *const u8, len as usize) };
    let mut cands = [0usize; MAX_CANDS];
    let mut n = 0;
    let mut over = 0u64;
    candidates(code, |o| {
        if n < MAX_CANDS {
            cands[n] = o;
            n += 1;
        } else {
            over += 1;
        }
    });
    if over > 0 {
        bump(&c.insn.rejected_sites, over);
    }
    if n == 0 {
        return;
    }
    let mut starts = [va; MAX_CANDS];
    if let Some(f) = file {
        symbol_starts(f, va, len, &cands[..n], &mut starts[..n]);
    }
    for i in 0..n {
        let from = (starts[i] - va) as usize;
        match confirm(code, from, cands[i]) {
            Verdict::Real(s) => match s.kind {
                Some(SiteKind::Rdrand | SiteKind::Rdseed) => {
                    let k = s.kind.unwrap() as u8;
                    if super::patch::patch(va + s.op as u64, k, writable, prot) {
                        bump(&c.insn.patched[k as usize], 1);
                    } else {
                        bump(&c.insn.table_full, 1);
                        bump(&c.insn.rejected_sites, 1);
                    }
                }
                Some(SiteKind::Rdpid) => bump(&c.insn.rdpid_sites, 1),
                None => {}
            },
            Verdict::Inside { .. } | Verdict::Skipped => bump(&c.insn.rejected_sites, 1),
        }
    }
}

fn pread(fd: u64, buf: &mut [u8], off: u64) -> bool {
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

fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}
fn le32(b: &[u8], o: usize) -> u64 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as u64
}
fn le16(b: &[u8], o: usize) -> u64 {
    u16::from_le_bytes([b[o], b[o + 1]]) as u64
}

/// For each candidate, the nearest function symbol at or before it inside the mapping (run-time
/// address), from the file's `.symtab` and `.dynsym`. Leaves `starts` alone when the file has no
/// usable headers.
fn symbol_starts(f: FileId, va: u64, len: u64, cands: &[usize], starts: &mut [u64]) {
    let mut eh = [0u8; 64];
    if !pread(f.fd, &mut eh, 0) || &eh[..4] != b"\x7fELF" || eh[4] != 2 {
        return;
    }
    // Load bias: the PT_LOAD that holds the mapping's file offset gives link address -> va.
    let (phoff, phentsize, phnum) = (le64(&eh, 0x20), le16(&eh, 0x36), le16(&eh, 0x38));
    let mut bias = None;
    let mut ph = [0u8; 56];
    for i in 0..phnum.min(64) {
        if !pread(f.fd, &mut ph, phoff + i * phentsize) {
            return;
        }
        let (typ, off, vaddr, filesz) =
            (le32(&ph, 0), le64(&ph, 8), le64(&ph, 0x10), le64(&ph, 0x20));
        if typ == 1 && f.off >= off && f.off < off + filesz.max(1) {
            bias = Some(va.wrapping_sub(vaddr.wrapping_add(f.off - off)));
            break;
        }
    }
    let Some(bias) = bias else { return };
    let (shoff, shentsize, shnum) = (le64(&eh, 0x28), le16(&eh, 0x3a), le16(&eh, 0x3c));
    if shoff == 0 || shentsize != 64 {
        return;
    }
    let mut sh = [0u8; 64];
    let mut buf = [0u8; 24 * 170];
    let end = va + len;
    for i in 0..shnum.min(256) {
        if !pread(f.fd, &mut sh, shoff + i * 64) {
            return;
        }
        let typ = le32(&sh, 4);
        if typ != 2 && typ != 11 {
            continue;
        }
        let (off, size, ent) = (le64(&sh, 0x18), le64(&sh, 0x20), le64(&sh, 0x38));
        if ent != 24 {
            continue;
        }
        let mut done = 0;
        while done < size {
            let chunk = (size - done).min(buf.len() as u64) / 24 * 24;
            if chunk == 0 || !pread(f.fd, &mut buf[..chunk as usize], off + done) {
                break;
            }
            for k in 0..(chunk / 24) as usize {
                let e = &buf[k * 24..k * 24 + 24];
                if e[4] & 0xf != 2 {
                    continue; // STT_FUNC only
                }
                let v = le64(e, 8);
                if v == 0 {
                    continue;
                }
                let a = v.wrapping_add(bias);
                if a < va || a >= end {
                    continue;
                }
                for (j, &cand) in cands.iter().enumerate() {
                    starts[j] = sweep_start(va + cand as u64, starts[j], core::iter::once(a));
                }
            }
            done += chunk;
        }
    }
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
