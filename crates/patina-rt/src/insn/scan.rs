//! Find and patch instruction sites in executable mappings, before the guest can run them.
//!
//! Called by the loader for each executable `PT_LOAD`, by the `mmap` handler for executable
//! mappings, and by `mprotect` when a range becomes executable. The rule (`proto::insn`, shared
//! with `patina __insn-scan`, which the false-positive audit runs) is applied by
//! `crate::arch::insn::scan_range`; this module decides which mappings are scanned.

use crate::insn::bump;
use crate::raw::*;
use crate::state::ctl;
use proto::ctl::{ScanKey, ScanTab};

/// The file a mapping came from: descriptor and file offset of the mapping's first byte.
#[derive(Clone, Copy)]
pub struct FileId {
    pub fd: u64,
    pub off: u64,
    /// Some(z): the mapping holds the file's bytes, zeros from offset `z` on (the loader's
    /// `.bss` tail; the mapping's length when nothing was zeroed), so another mapping of the
    /// same bytes made the same way has the same verdicts. None: the bytes may be another's
    /// (a range made executable after it was written).
    pub as_file: Option<u64>,
}

/// The run's kept scans (`proto::ctl::ScanTab`).
fn scans() -> &'static mut ScanTab {
    unsafe { ScanTab::at(crate::state::ctl_base()) }
}

/// Whether the file of `fd` lies on a read-only mount (`statfs`'s `ST_RDONLY`): nothing in the
/// run can change its bytes.
fn read_only(fd: u64) -> bool {
    const F_FLAGS: usize = 10; // the eleventh word of `struct statfs` (x86_64 and arm64)
    const ST_RDONLY: u64 = 1;
    let mut sf = [0u64; 15];
    let r = unsafe { sc2(nr::FSTATFS, fd, sf.as_mut_ptr() as u64) };
    r == 0 && sf[F_FLAGS] & ST_RDONLY != 0
}

/// Whether kept verdicts can stand for a scan of a `len`-byte mapping here: each names a place
/// in the mapping and a known code, and this process's side table takes every site, as it did
/// in the process that made the scan (else the scan is made again, which is always exact).
fn replayable(vs: &[u64], len: u64) -> bool {
    let site = |k: u8| (1..proto::ctl::INSN_KINDS as u8).contains(&k);
    let ok = vs.iter().all(|&v| {
        let k = v as u8;
        (k == crate::insn::REJECTED || site(k))
            && (v >> 8) + crate::arch::insn::PATCH.len() as u64 <= len
    });
    ok && vs.iter().filter(|&&v| site(v as u8)).count() <= super::patch::room()
}

/// Scan `[va, va + len)` (mapped, readable) and patch the confirmed sites. `writable`: the
/// pages are writable now; else they are made writable for each patch and given `prot` back.
/// A mapping of a read-only file holding its bytes whose scan another process of the run made
/// already takes that scan's verdicts, applied in the same order (`ScanKey` says what they are
/// a function of); otherwise the scan is made, and kept when it may be asked again.
/// The protection execute-only memory keeps after a scan: readable where a site was patched,
/// since the SIGILL entry reads the patched instruction (its prefixes, its word) to emulate it.
pub fn kept_prot(va: u64, len: u64, prot: u64) -> u64 {
    if prot & PROT_EXEC != 0 && prot & PROT_READ == 0 && super::patch::any_in(va, len) {
        prot | PROT_READ
    } else {
        prot
    }
}

pub fn scan_exec(va: u64, len: u64, file: Option<FileId>, writable: bool, prot: u64) {
    let c = ctl();
    let st = file.and_then(|f| crate::sys::fs::fstat_raw(f.fd as i64).map(|st| (f, st)));
    // Pages wholly past the end of the file would raise SIGBUS when read.
    let len = match st {
        Some((f, st)) => len.min(((st.size().saturating_sub(f.off)) + 4095) & !4095),
        None => len,
    };
    if len == 0 {
        return;
    }
    bump(&c.insn.scanned_mappings, 1);
    bump(&c.insn.scanned_bytes, len);
    let key = st.and_then(|(f, st)| {
        let zero = f.as_file?;
        read_only(f.fd).then(|| ScanKey {
            dev: st.dev(),
            ino: st.ino(),
            off: f.off,
            len,
            zero: zero.min(len),
        })
    });
    // Execute-only memory (the kernel backs PROT_EXEC alone with an access-disabled pkey) cannot
    // be read: make it readable for the scan (and for a patch, which reads the bytes it covers),
    // keeping it writable where it is now (the loader's segments: a patch writes it as it is).
    let now = prot | if writable { PROT_WRITE } else { 0 };
    let unreadable = prot & PROT_READ == 0;
    if unreadable {
        unsafe { sc3(nr::MPROTECT, va, len, now | PROT_READ) };
    }
    let kept = key
        .and_then(|k| scans().find(&k))
        .filter(|vs| replayable(vs, len));
    let (mut n, mut fits) = (0, key.is_some() && kept.is_none());
    match kept {
        Some(vs) => {
            bump(&c.insn.reused_mappings, 1);
            for &v in vs {
                crate::arch::insn::apply(va, v >> 8, v as u8, writable, prot | PROT_READ);
            }
        }
        None => {
            let full = c
                .insn
                .table_full
                .load(core::sync::atomic::Ordering::Relaxed);
            crate::arch::insn::scan_range(
                va,
                len,
                file,
                writable,
                prot | PROT_READ,
                &mut |off, k| {
                    if fits {
                        fits = scans().record(n, (off << 8) | k as u64);
                        n += 1;
                    }
                },
            );
            // A patch that did not fit left the original bytes for the later sweeps to decode:
            // such a scan is this process's alone.
            fits &= c
                .insn
                .table_full
                .load(core::sync::atomic::Ordering::Relaxed)
                == full;
        }
    }
    if unreadable {
        unsafe { sc3(nr::MPROTECT, va, len, kept_prot(va, len, now)) };
    }
    if let (Some(key), true) = (key, fits) {
        scans().commit(key, n);
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
    // A new private mapping holds the file's bytes.
    scan_exec(
        a,
        len,
        Some(FileId {
            fd,
            off,
            as_file: Some(len),
        }),
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
        let fd = crate::fdlim::transient(|| unsafe {
            sc4(
                nr::OPENAT,
                (-100i64) as u64,
                p.as_ptr() as u64,
                0o2000000,
                0,
            )
        });
        let file = (fd >= 0).then(|| FileId {
            fd: fd as u64,
            off: hex(offs) + (lo - s),
            as_file: None,
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
