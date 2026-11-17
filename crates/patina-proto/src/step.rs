//! arm64's single step, as the software stepper of a spin probe needs it (`rt::spin`,
//! `rt::arch::aarch64::step`): where a thread is after its next instruction, and how far an
//! exclusive pair reaches. Compiled on every host so that its tests run everywhere.
//!
//! arm64 has no single-step bit a program may set: the stepper plants a breakpoint at the
//! instruction's successor. Every instruction is one word, so the successor of anything but a
//! branch is `pc + 4`; a branch is decoded and its condition evaluated on the frame, so the
//! successor is exactly one address. Every encoding of the branch group (`op0` = `x101`) that
//! is not decoded here is refused: an unknown branch form is never stepped as `pc + 4`.
//!
//! **Exclusive pairs.** A stop between a load-exclusive and its store-exclusive clears the
//! exclusive monitor, so the store fails every time: stepped one instruction at a time, an
//! `ldxr`/`stxr` retry loop would never complete. A load-exclusive is therefore stepped as a
//! whole: the stops are the instruction after the first store-exclusive or `clrex` within
//! `PAIR_MAX` instructions, and the target of each conditional branch in between that leaves
//! the range (at most `EXITS_MAX`). The pair is refused when it holds an unconditional or
//! indirect branch, an exception-generating instruction (`svc`, `brk`, ...), another
//! load-exclusive, an undecoded branch, or no store within reach. (The rule debuggers use.)
//! Single-instruction atomics (`cas`, `ldadd`, `swp`, `casp`) need no rule.
//!
//! A store-exclusive may fail without another writer (an interrupt on the host clears the
//! monitor), more or less often by host. When the store is followed by the usual retry, a
//! `cbnz` (or `tbnz #0`) on its status register back into the pair, that branch is part of the
//! pair: the retry runs inside the step and its stops are the same whether the store failed
//! or not. A retry that goes elsewhere is the program's own path, as it is natively.
//!
//! Pointer authentication: the runtime disables the keys, so the authenticating branches
//! (`braa`, `blraaz`, `retaa`, ...) branch to the register's value as the plain forms do.

/// Instructions scanned for the end of an exclusive pair.
pub const PAIR_MAX: usize = 32;
/// Conditional exits from a pair, besides its end.
pub const EXITS_MAX: usize = 4;

/// Where a thread is after the instruction at `pc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// One instruction later, at this address.
    At(u64),
    /// A direct branch to itself: one execution leaves only `pc` (and, with `link`, `x30 =
    /// pc + 4`) as they were; no breakpoint can be planted at the instruction being executed.
    SelfLoop { link: bool },
    /// A load-exclusive: the whole pair runs, and stops at one of these addresses (the first
    /// is after the pair's end).
    Pair { at: [u64; EXITS_MAX + 1], n: usize },
    /// Not steppable here.
    Refuse(Refusal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `svc`, `brk`, `hlt` and the rest of the exception-generating group, and `udf`.
    Exception,
    /// A branch-group encoding this decoder does not know.
    UnknownBranch,
    /// An indirect branch to itself.
    IndirectSelf,
    /// An exclusive pair this rule does not cover (see the module).
    Pair,
}

/// The registers a successor depends on: `x0`-`x30` and `pstate` (its NZCV bits).
pub struct Regs<'a> {
    pub x: &'a [u64; 31],
    pub pstate: u64,
}

impl Regs<'_> {
    /// Register `n` as a branch reads it: 31 is the zero register.
    fn x(&self, n: u32) -> u64 {
        if n < 31 {
            self.x[n as usize]
        } else {
            0
        }
    }
}

/// `clrex #CRm`.
const CLREX_MASK: u32 = 0xffff_f0ff;
const CLREX: u32 = 0xd503_305f;

/// Whether `w` is a load-exclusive (`ldxr`, `ldaxr`, `ldxp`, `ldaxp`, any size).
pub fn is_load_exclusive(w: u32) -> bool {
    exclusive(w) == Some(true)
}

/// Whether `w` ends an exclusive pair: a store-exclusive (`stxr`, `stlxr`, `stxp`, `stlxp`)
/// or `clrex`.
pub fn ends_pair(w: u32) -> bool {
    exclusive(w) == Some(false) || w & CLREX_MASK == CLREX
}

/// The exclusive class (`size 001000 o2 L o1 Rs o0 Rt2 Rn Rt`, `o2` = 0): `Some(true)` for a
/// load, `Some(false)` for a store. `o1` = 1 with a 32-bit `size` is `casp`, an atomic.
fn exclusive(w: u32) -> Option<bool> {
    let pair = w >> 21 & 1 == 1;
    if w & 0x3f80_0000 != 0x0800_0000 || pair && w >> 31 == 0 {
        return None;
    }
    Some(w >> 22 & 1 == 1)
}

/// What a word of the branch group does.
enum Branch {
    /// Not a branch (system instructions: hints, barriers, `mrs`, `msr`, `sys`).
    No,
    /// Taken or not by a condition on registers: `(taken, target)`.
    Cond(bool, u64),
    /// Always taken, to a target from the instruction: `(target, link)`.
    Direct(u64, bool),
    /// Always taken, to a register's value: `(target, link)`.
    Indirect(u64, bool),
    Refuse(Refusal),
}

fn sext(v: u32, bits: u32) -> i64 {
    ((v as i64) << (64 - bits)) >> (64 - bits)
}

fn cond(c: u32, pstate: u64) -> bool {
    let (n, z, cy, v) = (
        pstate >> 31 & 1 == 1,
        pstate >> 30 & 1 == 1,
        pstate >> 29 & 1 == 1,
        pstate >> 28 & 1 == 1,
    );
    let r = match c >> 1 {
        0 => z,
        1 => cy,
        2 => n,
        3 => v,
        4 => cy && !z,
        5 => n == v,
        6 => !z && n == v,
        _ => return true, // AL, NV
    };
    r != (c & 1 == 1)
}

fn branch(pc: u64, w: u32, r: &Regs) -> Branch {
    if w >> 26 & 7 != 0b101 {
        return Branch::No;
    }
    let rel = |off: i64| pc.wrapping_add((off << 2) as u64);
    match w >> 24 {
        // b, bl
        0x14..=0x17 | 0x94..=0x97 => Branch::Direct(rel(sext(w & 0x3ff_ffff, 26)), w >> 31 == 1),
        // b.cond, bc.cond
        0x54 => Branch::Cond(cond(w & 0xf, r.pstate), rel(sext(w >> 5 & 0x7_ffff, 19))),
        // cbz, cbnz (32 and 64 bit)
        0x34 | 0x35 | 0xb4 | 0xb5 => {
            let v = r.x(w & 0x1f);
            let v = if w >> 31 == 1 { v } else { v & 0xffff_ffff };
            let nz = w >> 24 & 1 == 1;
            Branch::Cond((v != 0) == nz, rel(sext(w >> 5 & 0x7_ffff, 19)))
        }
        // tbz, tbnz
        0x36 | 0x37 | 0xb6 | 0xb7 => {
            let bit = (w >> 31) << 5 | (w >> 19 & 0x1f);
            let set = r.x(w & 0x1f) >> bit & 1 == 1;
            let nz = w >> 24 & 1 == 1;
            Branch::Cond(set == nz, rel(sext(w >> 5 & 0x3fff, 14)))
        }
        // svc, hvc, smc, brk, hlt, dcps, tcancel
        0xd4 => Branch::Refuse(Refusal::Exception),
        // hints, barriers, system registers and operations
        0xd5 => Branch::No,
        0xd6 | 0xd7 => branch_reg(w, r),
        _ => Branch::Refuse(Refusal::UnknownBranch),
    }
}

/// Unconditional branch (register): `1101011 opc op2 op3 Rn op4`.
fn branch_reg(w: u32, r: &Regs) -> Branch {
    let opc = w >> 21 & 0xf;
    let (op2, op3, rn, op4) = (w >> 16 & 0x1f, w >> 10 & 0x3f, w >> 5 & 0x1f, w & 0x1f);
    if op2 != 0x1f {
        return Branch::Refuse(Refusal::UnknownBranch);
    }
    // op3 = 000000, op4 = 0: the plain form; op3 = 00001M with op4 = 11111: the zero-modifier
    // authenticating form (`braaz`, `blraaz`, `retaa` with Rn = 11111).
    let plain = op3 == 0 && op4 == 0;
    let auth_z = op3 >> 1 == 1 && op4 == 0x1f;
    match opc {
        0 | 1 if plain || auth_z => Branch::Indirect(r.x(rn), opc == 1),
        2 if plain => Branch::Indirect(r.x(rn), false),
        2 if auth_z && rn == 0x1f => Branch::Indirect(r.x(30), false),
        // braa, brab, blraa, blrab: Rn the target, op4 the modifier register
        8 | 9 if op3 >> 1 == 1 => Branch::Indirect(r.x(rn), opc == 9),
        _ => Branch::Refuse(Refusal::UnknownBranch),
    }
}

/// The successor of the instruction `w` at `pc`, the thread's registers in `r`; `code` holds
/// the words after it (from `pc + 4`, as many as could be read, up to `PAIR_MAX`), which only
/// a load-exclusive looks at.
pub fn next(pc: u64, w: u32, r: &Regs, code: &[u32]) -> Next {
    if w >> 16 == 0 {
        return Next::Refuse(Refusal::Exception); // udf
    }
    if is_load_exclusive(w) {
        return pair(pc, code);
    }
    let (to, link) = match branch(pc, w, r) {
        Branch::No => return Next::At(pc + 4),
        Branch::Refuse(why) => return Next::Refuse(why),
        Branch::Cond(false, _) => return Next::At(pc + 4),
        Branch::Cond(true, t) => (t, false),
        Branch::Direct(t, link) => (t, link),
        Branch::Indirect(t, _) if t == pc => return Next::Refuse(Refusal::IndirectSelf),
        Branch::Indirect(t, link) => (t, link),
    };
    if to == pc {
        Next::SelfLoop { link }
    } else {
        Next::At(to)
    }
}

/// Whether `b`, at `at`, branches into `range` when status register `rs` is nonzero (a
/// failed store): `cbnz` or `tbnz #0` on it.
fn retries(b: u32, rs: u32, at: u64, range: core::ops::RangeInclusive<u64>) -> bool {
    if b & 0x1f != rs {
        return false;
    }
    let off = match b >> 24 {
        0x35 | 0xb5 => sext(b >> 5 & 0x7_ffff, 19),
        0x37 if b >> 19 & 0x1f == 0 => sext(b >> 5 & 0x3fff, 14),
        _ => return false,
    };
    range.contains(&at.wrapping_add((off << 2) as u64))
}

/// The stops of the exclusive pair whose load is at `pc`.
fn pair(pc: u64, code: &[u32]) -> Next {
    let zero = [0u64; 31];
    let regs = Regs {
        x: &zero,
        pstate: 0,
    };
    let mut exits = [0u64; EXITS_MAX];
    let mut ne = 0;
    for (i, &w) in code.iter().take(PAIR_MAX).enumerate() {
        let a = pc + 4 * (i as u64 + 1);
        if ends_pair(w) {
            // The store's retry branch, back into the pair: the pair ends after it.
            let retry = exclusive(w) == Some(false)
                && code
                    .get(i + 1)
                    .is_some_and(|&b| retries(b, w >> 16 & 0x1f, a + 4, pc..=a));
            let end = if retry { a + 4 } else { a };
            let mut at = [0u64; EXITS_MAX + 1];
            at[0] = end + 4;
            let mut n = 1;
            for &t in &exits[..ne] {
                // Inside the range (back to the load included): still the pair.
                if (pc..=end).contains(&t) || at[..n].contains(&t) {
                    continue;
                }
                at[n] = t;
                n += 1;
            }
            return Next::Pair { at, n };
        }
        if is_load_exclusive(w) || w >> 16 == 0 {
            return Next::Refuse(Refusal::Pair);
        }
        match branch(a, w, &regs) {
            Branch::No => {}
            Branch::Cond(_, t) => {
                if !exits[..ne].contains(&t) {
                    if ne == EXITS_MAX {
                        return Next::Refuse(Refusal::Pair);
                    }
                    exits[ne] = t;
                    ne += 1;
                }
            }
            _ => return Next::Refuse(Refusal::Pair),
        }
    }
    Next::Refuse(Refusal::Pair)
}

#[cfg(test)]
mod tests;
