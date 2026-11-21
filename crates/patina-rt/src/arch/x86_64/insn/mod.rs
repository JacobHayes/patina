//! x86_64's instruction rule and emulators (`crate::insn` holds the portable part).
//!
//! The rule is `proto::insn`: byte candidates (`0F C7 /6|/7` register forms, `F3 90`), each
//! confirmed by a linear sweep from the nearest function start of the file (a `.symtab` or
//! `.dynsym` function symbol, or a function the `.eh_frame_hdr` table lists) or from the start
//! of the mapping. A site is patched by overwriting its two opcode bytes with `ud2`.

pub mod emulate;
pub mod tsc;

use crate::insn::scan::{pread, FileId};
use crate::insn::{bump, REJECTED};
use crate::state::ctl;
use proto::insn::{candidates, sweep, Site, SiteKind, Verdict};

/// The bytes written over a site: `ud2`, over the two opcode bytes.
pub const PATCH: &[u8] = &[0x0f, 0x0b];

/// After writing code: nothing to do (x86 keeps instruction fetch coherent with stores).
#[inline(always)]
pub fn sync_code(_a: u64, _len: u64) {}

/// At image start, from the kernel's `AT_HWCAP2`: nothing on x86_64.
#[inline(always)]
pub fn init(_hwcap2: Option<u64>) {}

/// The protection bits the kernel adds to an image's executable segments: none on x86_64.
pub fn image_prot(_feature_1_and: impl FnOnce(u32) -> u32) -> u64 {
    0
}

/// Candidates confirmed per batch.
const MAX_CANDS: usize = 256;

/// Scan `[va, va + len)` (mapped, readable) and patch the confirmed sites. `writable`: the
/// pages are writable now; else they are made writable for each patch and given `prot` back.
/// Each verdict is applied (`apply`) as it is made, so later sweeps decode the patched bytes,
/// and then given to `note` (offset in the mapping, verdict code).
pub fn scan_range(
    va: u64,
    len: u64,
    file: Option<FileId>,
    writable: bool,
    prot: u64,
    note: &mut dyn FnMut(u64, u8),
) {
    let code = unsafe { core::slice::from_raw_parts(va as *const u8, len as usize) };
    // Candidates in batches: each batch looks up its sweep starts in the file's symbols once.
    let mut cands = [0usize; MAX_CANDS];
    let mut n = 0;
    candidates(code, |o| {
        cands[n] = o;
        n += 1;
        if n == MAX_CANDS {
            confirm_batch(code, va, file, writable, prot, &cands, note);
            n = 0;
        }
    });
    if n > 0 {
        confirm_batch(code, va, file, writable, prot, &cands[..n], note);
    }
}

fn confirm_batch(
    code: &[u8],
    va: u64,
    file: Option<FileId>,
    writable: bool,
    prot: u64,
    cands: &[usize],
    note: &mut dyn FnMut(u64, u8),
) {
    let n = cands.len();
    let mut starts = [va; MAX_CANDS];
    if let Some(f) = file {
        symbol_starts(f, va, code.len() as u64, cands, &mut starts[..n]);
    }
    // Candidates are in address order: one whose sweep starts where the last one's did
    // resumes that sweep instead of decoding the same bytes again.
    let (mut last_from, mut stop) = (usize::MAX, 0);
    for i in 0..n {
        let from = (starts[i] - va) as usize;
        let at = if from == last_from && stop >= from {
            stop
        } else {
            from
        };
        let (v, s) = sweep(code, at, cands[i]);
        (last_from, stop) = (from, s);
        let (off, k) = match v {
            Verdict::Real(Site {
                op, kind: Some(k), ..
            }) => (op, k as u8),
            Verdict::Real(_) => continue,
            Verdict::Inside { .. } | Verdict::Skipped => (cands[i], REJECTED),
        };
        apply(va, off as u64, k, writable, prot);
        note(off as u64, k);
    }
}

/// The effect of the verdict `k` on the candidate at `va + off`: patch a site (unless it is a
/// pause hint and pause points are off), count an `rdpid`, count a rejected candidate.
pub fn apply(va: u64, off: u64, k: u8, writable: bool, prot: u64) {
    let c = ctl();
    if k == REJECTED {
        return bump(&c.insn.rejected_sites, 1);
    }
    if k == SiteKind::Rdpid as u8 {
        return bump(&c.insn.counted_sites, 1);
    }
    let pause = crate::state::config().sched & proto::ctl::SCHED_PAUSE_POINTS != 0;
    if k == SiteKind::Pause as u8 && !pause {
        return;
    }
    if crate::insn::patch::patch(va + off, k, writable, prot) {
        bump(&c.insn.patched[k as usize], 1);
    } else {
        bump(&c.insn.table_full, 1);
        bump(&c.insn.rejected_sites, 1);
    }
}

/// For each candidate, the nearest function start at or before it inside the mapping (run-time
/// address): a function symbol of the file's `.symtab` and `.dynsym`, or a function its
/// `.eh_frame_hdr` table lists. Leaves `starts` alone when the file has no usable headers.
fn symbol_starts(f: FileId, va: u64, len: u64, cands: &[usize], starts: &mut [u64]) {
    let mut eh = [0u8; 64];
    if !pread(f.fd, &mut eh, 0) || &eh[..4] != b"\x7fELF" || eh[4] != 2 {
        return;
    }
    // Load bias: the PT_LOAD that holds the mapping's file offset gives link address -> va.
    let (phoff, phentsize, phnum) = (le64(&eh, 0x20), le16(&eh, 0x36), le16(&eh, 0x38));
    let mut bias = None;
    // The unwind table's header: file offset and link-time address.
    let mut hdr = None;
    let mut ph = [0u8; 56];
    for i in 0..phnum.min(64) {
        if !pread(f.fd, &mut ph, phoff + i * phentsize) {
            return;
        }
        let (typ, off, vaddr, filesz) =
            (le32(&ph, 0), le64(&ph, 8), le64(&ph, 0x10), le64(&ph, 0x20));
        if typ == 1 && bias.is_none() && f.off >= off && f.off < off + filesz.max(1) {
            bias = Some(va.wrapping_sub(vaddr.wrapping_add(f.off - off)));
        }
        if typ == proto::insn::PT_GNU_EH_FRAME as u64 && hdr.is_none() {
            hdr = Some((off, vaddr));
        }
    }
    let Some(bias) = bias else { return };
    let end = va + len;
    // A function start starts the sweep of every candidate at or after it: note it at the
    // first such candidate; the prefix maximum at the end carries it forward.
    let mut note = |link: u64| {
        let a = link.wrapping_add(bias);
        if a < va || a >= end {
            return;
        }
        let j = cands.partition_point(|&c| va + (c as u64) < a);
        if j < cands.len() && starts[j] < a {
            starts[j] = a;
        }
    };
    let mut buf = [0u8; 24 * 170];
    if let Some((off, vaddr)) = hdr {
        let mut h = [0u8; 12];
        if let Some((table, n)) = pread(f.fd, &mut h, off)
            .then(|| proto::insn::eh_frame_table(&h))
            .flatten()
        {
            let (mut done, size) = (0, n * 8);
            while done < size {
                let chunk = (size - done).min(buf.len() as u64) / 8 * 8;
                if chunk == 0 || !pread(f.fd, &mut buf[..chunk as usize], off + table + done) {
                    break;
                }
                for e in buf[..chunk as usize].as_chunks::<8>().0 {
                    note(proto::insn::fde_start(vaddr, e));
                }
                done += chunk;
            }
        }
    }
    let (shoff, shentsize, shnum) = (le64(&eh, 0x28), le16(&eh, 0x3a), le16(&eh, 0x3c));
    if shoff != 0 && shentsize == 64 {
        section_symbols(f, shoff, shnum, &mut buf, &mut note);
    }
    // Candidates are in address order: each starts at the nearest function start before it.
    for j in 1..cands.len() {
        if starts[j] < starts[j - 1] {
            starts[j] = starts[j - 1];
        }
    }
}

/// Every function symbol's link-time address in the file's `.symtab` and `.dynsym`.
fn section_symbols(f: FileId, shoff: u64, shnum: u64, buf: &mut [u8], note: &mut impl FnMut(u64)) {
    let mut sh = [0u8; 64];
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
                if v != 0 {
                    note(v);
                }
            }
            done += chunk;
        }
    }
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
