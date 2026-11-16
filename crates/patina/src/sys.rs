//! The wire: one reserved system call (`sdk/c/patina.h` in the Patina repository is the
//! reference) and the per-site byte that keeps passing assertions to one load.

use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering::Relaxed};

pub const SYSCALL: u64 = 0x7061;
const VERSION: i64 = 1;
const HELLO_BUGGIFY: i64 = 1 << 16;

const OP_HELLO: u64 = 1;
const OP_ASSERT: u64 = 2;
const OP_BUGGIFY: u64 = 3;
const OP_KNOB: u64 = 4;
const OP_DELAY: u64 = 5;
const OP_MARK: u64 = 6;

pub const KIND_ALWAYS: u8 = 1;
pub const KIND_SOMETIMES: u8 = 2;
pub const KIND_REACHABLE: u8 = 3;
pub const KIND_BUGGIFY: u8 = 4;
pub const KIND_KNOB: u8 = 5;
pub const KIND_DELAY: u8 = 6;

const NEVER: i64 = 2;
const HDR: usize = 32;
const LABEL_MAX: usize = 255;
const TEXT_MAX: usize = 4096;

/// Process state: 0 not asked yet, else `ASKED` plus `ON` (under Patina) and `BUGGIFY`.
static STATE: AtomicU8 = AtomicU8::new(0);
const ASKED: u8 = 1;
const ON: u8 = 2;
const BUGGIFY: u8 = 4;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
fn sys(op: u64, p: *const u8, len: usize) -> i64 {
    let r: i64;
    // SAFETY: a system call the kernel answers ENOSYS (or a sandbox EPERM) outside Patina;
    // under Patina the runtime reads `len` bytes at `p` and may write bytes 8..16 (a knob).
    unsafe {
        core::arch::asm!("syscall", inlateout("rax") SYSCALL as i64 => r, in("rdi") op,
            in("rsi") p, in("rdx") len, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    r
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[inline(always)]
fn sys(_op: u64, _p: *const u8, _len: usize) -> i64 {
    -38
}

#[inline]
fn state() -> u8 {
    let s = STATE.load(Relaxed);
    if s != 0 { s } else { hello() }
}

#[cold]
fn hello() -> u8 {
    let r = sys(OP_HELLO, core::ptr::null(), 0);
    let ok = r >= 0 && r & 0xffff == VERSION;
    if r >= 0 && !ok {
        let m = b"patina: unknown SDK protocol version; the SDK is inert\n";
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        // SAFETY: write(2) of a static buffer to stderr.
        unsafe {
            core::arch::asm!("syscall", inlateout("rax") 1i64 => _, in("rdi") 2, in("rsi") m.as_ptr(),
                in("rdx") m.len(), lateout("rcx") _, lateout("r11") _, options(nostack));
        }
        let _ = m;
    }
    let s = ASKED
        | if ok { ON } else { 0 }
        | if ok && r & HELLO_BUGGIFY != 0 {
            BUGGIFY
        } else {
            0
        };
    STATE.store(s, Relaxed);
    s
}

/// Whether this process runs under Patina.
pub fn is_simulated() -> bool {
    state() & ON != 0
}

/// A detail being formatted: at most `TEXT_MAX` bytes, the rest cut.
pub struct Text {
    b: [u8; TEXT_MAX],
    n: usize,
}

impl fmt::Write for Text {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let k = s.len().min(TEXT_MAX - self.n);
        self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
        self.n += k;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn call(
    op: u64,
    kind: u8,
    cond: bool,
    label: &str,
    text: &[u8],
    a: &mut i64,
    b: i64,
    c: i64,
) -> i64 {
    let mut buf = [0u8; HDR + LABEL_MAX + TEXT_MAX];
    let label = &label.as_bytes()[..label.len().min(LABEL_MAX)];
    let text = &text[..text.len().min(TEXT_MAX)];
    buf[0] = kind;
    buf[1] = cond as u8;
    buf[2..4].copy_from_slice(&(label.len() as u16).to_le_bytes());
    buf[4..8].copy_from_slice(&(text.len() as u32).to_le_bytes());
    buf[8..16].copy_from_slice(&a.to_le_bytes());
    buf[16..24].copy_from_slice(&b.to_le_bytes());
    buf[24..32].copy_from_slice(&c.to_le_bytes());
    buf[HDR..HDR + label.len()].copy_from_slice(label);
    buf[HDR + label.len()..HDR + label.len() + text.len()].copy_from_slice(text);
    let r = sys(op, buf.as_ptr(), HDR + label.len() + text.len());
    if r == 0 {
        *a = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    }
    r
}

/// A named point in the run's log; `setup-complete` ends setup (`faults-after-setup`).
pub fn mark(label: &str) {
    if state() & ON != 0 {
        call(OP_MARK, KIND_REACHABLE, false, label, b"", &mut 0, 0, 0);
    }
}

/// One site's byte: reported evaluated, reported held, never fires. Outside Patina all bits are
/// set at the first call, so every later call is one load and a branch.
pub struct Site(AtomicU8);

const EVAL: u8 = 1;
const HELD: u8 = 2;
const QUIET: u8 = 4;
const ALL: u8 = EVAL | HELD | QUIET;

impl Default for Site {
    fn default() -> Self {
        Self::new()
    }
}

impl Site {
    pub const fn new() -> Site {
        Site(AtomicU8::new(0))
    }

    #[inline]
    pub fn always(&self, cond: bool, label: &str, detail: impl FnOnce(&mut Text)) {
        if cond && self.0.load(Relaxed) & EVAL != 0 {
            return;
        }
        self.report(KIND_ALWAYS, cond, label, detail);
    }

    #[inline]
    pub fn sometimes(&self, cond: bool, label: &str) {
        if self.0.load(Relaxed) & if cond { HELD } else { EVAL } != 0 {
            return;
        }
        self.report(KIND_SOMETIMES, cond, label, |_| {});
    }

    #[inline]
    pub fn reachable(&self, label: &str) {
        if self.0.load(Relaxed) & EVAL != 0 {
            return;
        }
        self.report(KIND_REACHABLE, true, label, |_| {});
    }

    #[cold]
    #[inline(never)]
    fn report(&self, kind: u8, cond: bool, label: &str, detail: impl FnOnce(&mut Text)) {
        if state() & ON == 0 {
            self.0.store(ALL, Relaxed);
            return;
        }
        self.0.fetch_or(EVAL | if cond { HELD } else { 0 }, Relaxed);
        let mut t = Text {
            b: [0; TEXT_MAX],
            n: 0,
        };
        if !cond {
            detail(&mut t);
        }
        call(OP_ASSERT, kind, cond, label, &t.b[..t.n], &mut 0, 0, 0);
    }

    /// A fault point (`OP_BUGGIFY`) or delay (`OP_DELAY`, `a` the largest delay in ns).
    #[inline]
    pub fn point(&self, delay: bool, label: &str, a: i64) -> bool {
        if self.0.load(Relaxed) & QUIET != 0 {
            return false;
        }
        self.ask(delay, label, a)
    }

    #[cold]
    #[inline(never)]
    fn ask(&self, delay: bool, label: &str, mut a: i64) -> bool {
        if state() & BUGGIFY == 0 {
            self.0.store(ALL, Relaxed);
            return false;
        }
        let (op, kind) = if delay {
            (OP_DELAY, KIND_DELAY)
        } else {
            (OP_BUGGIFY, KIND_BUGGIFY)
        };
        let r = call(op, kind, false, label, b"", &mut a, 0, 0);
        if r == NEVER {
            self.0.fetch_or(QUIET, Relaxed);
        }
        r == 1
    }
}

/// A knob: `default` outside Patina or without `--buggify`, else the run's value in `[lo, hi]`.
pub fn knob(label: &str, default: i64, lo: i64, hi: i64) -> i64 {
    if state() & BUGGIFY == 0 {
        return default;
    }
    let mut v = default;
    if call(OP_KNOB, KIND_KNOB, false, label, b"", &mut v, lo, hi) == 0 {
        v
    } else {
        default
    }
}

/// A failed assertion with a label computed at run time (not declared ahead).
pub fn violation(label: &str, detail: &str) {
    if state() & ON != 0 {
        call(
            OP_ASSERT,
            KIND_ALWAYS,
            false,
            label,
            detail.as_bytes(),
            &mut 0,
            0,
            0,
        );
    }
}

/// The record a literal-label macro places in the `patina_sites` section: a marker byte, the
/// kind, the two lengths, the label and the source location. No pointers: it needs no
/// relocation, and the runtime reads it from the executable file before the program runs.
#[repr(C)]
pub struct Rec<const N: usize, const M: usize> {
    h: [u8; 4],
    l: [u8; N],
    s: [u8; M],
}

impl<const N: usize, const M: usize> Rec<N, M> {
    pub const fn new(kind: u8, label: &str, loc: &str) -> Self {
        assert!(
            N == label.len() && N >= 1 && N <= LABEL_MAX,
            "a label is 1 to 255 bytes"
        );
        let (lb, sb) = (label.as_bytes(), loc.as_bytes());
        let mut l = [0u8; N];
        let mut i = 0;
        while i < N {
            l[i] = lb[i];
            i += 1;
        }
        // The end of a long path: the file name and the line.
        let mut s = [0u8; M];
        let skip = sb.len() - M;
        let mut j = 0;
        while j < M {
            s[j] = sb[skip + j];
            j += 1;
        }
        Rec {
            h: [0xb7, kind, N as u8, M as u8],
            l,
            s,
        }
    }
}

pub const fn loc_len(loc: &str) -> usize {
    if loc.len() > 120 { 120 } else { loc.len() }
}

/// `0.0..=1.0` as per mille.
pub fn permille(p: f64) -> i64 {
    let p = if p.is_nan() { 0.0 } else { p.clamp(0.0, 1.0) };
    (p * 1000.0 + 0.5) as i64
}

pub fn nanos(d: core::time::Duration) -> i64 {
    i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)
}
