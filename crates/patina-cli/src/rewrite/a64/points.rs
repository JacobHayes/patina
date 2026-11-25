//! Switch points on arm64 (DESIGN 2.6): every instruction is one word and `b` reaches ±128 MiB,
//! so every site's count goes in place, on the site itself: its word becomes `b T` (`bl T` for a
//! call, so the link register holds the program's own return address) and nothing but that
//! word changes. There is no interior boundary, so no group.
//!
//! ```text
//! site                          in the text      trampoline T
//! bl  f        (backward)       bl T             count; b f                     KIND_JUMP
//! b   L        (backward)       b  T             count; b L                     KIND_JUMP
//! b.cond, cbz, cbnz, tbz, tbnz  b  T             <same cond> C; b next          KIND_COND
//!              (backward)                        C: count; b L     (taken path only)
//! br  xN, braa...               b  T             count; br xN; b next           KIND_BEFORE
//! cas, swp, ldadd... (LSE)      b  T             count; <the atomic>; b next     KIND_BEFORE
//!
//! count:  stp  x16, x17, [sp, #-32]!     two scratch registers, saved below the stack pointer
//!         movz x16, #CELL >> 16, lsl 16  the cell (below 4 GiB, low 16 bits zero)
//!         ldr  x17, [x16]
//!         sub  x17, x17, #1              neither `sub` nor `cbz` writes the flags
//!         str  x17, [x16]
//!         cbz  x17, S
//!         ldp  x16, x17, [sp], #32
//! row:    ...
//! S:      ldp  x16, x17, [sp], #32       restored before the trap: a point sees the program's
//!         udf  #A64_TRAP                 registers exactly
//!         b    row
//! ```
//!
//! The save slot is 32 to 16 bytes below the stack pointer: Linux arm64 has no red zone (the
//! kernel writes a signal frame right below it), but Go keeps its caller's frame pointer in the
//! 8 bytes just below, which the slot leaves alone. A copied instruction runs after the
//! registers are restored; none is PC-relative (a conditional branch is re-aimed), and no
//! landing pad (`bti`, `paciasp`) is ever a site. No site is inside an exclusive pair (after a
//! load-exclusive, up to its store and retry, `proto::step`'s rule), nor a branch into one:
//! the count's stores would clear the exclusive monitor. Nor is any site on the way from a
//! failed store-exclusive back to its load: a store-exclusive fails now and then with no other
//! writer, and the program goes round once more, which a count there would count. Nor is any
//! word whose address code takes: it may read it.
//!
//! The save slot needs the stack pointer 16-byte aligned (Linux checks it on every access
//! through it): a loop that runs with it misaligned, which no compiler emits, gets `SIGBUS`.

use super::code::{Code, ADDR, PAIR, RETRY, TAINT};
use super::insn::{self, Flow, Ind, X16};
use crate::rewrite::plan::{Site, CELL, PAGE};
use proto::plan::{
    A64_COUNT, A64_COUNT_COV, A64_TRAP, COVERAGE_MAP, KIND_BEFORE, KIND_COND, KIND_FAR, KIND_JUMP,
};

pub use crate::rewrite::class::Class;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    InPlace,
    /// In a span a refusal tainted, or a word whose address code takes.
    Tainted,
    /// Inside an exclusive pair, a branch into one, or on the way back from a failed store.
    Exclusive,
    /// Out of reach of its trampoline (a `b` reaches ±128 MiB).
    Far,
}

pub const OUTCOMES: [&str; 5] = ["found", "in-place", "tainted", "exclusive", "far"];

impl Outcome {
    pub fn index(self) -> usize {
        match self {
            Outcome::InPlace => 1,
            Outcome::Tainted => 2,
            Outcome::Exclusive => 3,
            Outcome::Far => 4,
        }
    }
}

pub struct Choice {
    pub class: Class,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the tests find sites by address")
    )]
    pub addr: u64,
    pub outcome: Outcome,
}

/// The site class of the word `w` at `a`; when `coverage` is true, forward direct branches
/// and calls are also instrumented so straight-line control-flow edges populate the bitmap.
pub fn classify_with(a: u64, w: u32, coverage: bool) -> Option<(Class, u8)> {
    match insn::flow(a, w) {
        Flow::Direct { target, link } if coverage || target <= a => Some(if link {
            (Class::BackCall, KIND_JUMP)
        } else {
            (Class::BackBranch, KIND_JUMP)
        }),
        Flow::Cond {
            target,
            hinted: false,
        } if coverage || target <= a => Some((Class::BackBranch, KIND_COND)),
        Flow::Indirect(Ind::Jump) => Some((Class::IndirectJump, KIND_BEFORE)),
        Flow::Plain if insn::atomic(w) => Some((Class::Atomic, KIND_BEFORE)),
        _ => None,
    }
}

/// The count's words, at `t` (the start of the count), its `cbz` aimed at `s`.
pub fn count(t: u64, s: u64) -> [u32; 7] {
    [
        0xa9be_47f0, // stp x16, x17, [sp, #-32]!
        insn::movz_hi(X16, CELL),
        0xf940_0211, // ldr x17, [x16]
        0xd100_0631, // sub x17, x17, #1
        0xf900_0211, // str x17, [x16]
        insn::cbz_x17(t.wrapping_add(20), s),
        RESTORE,
    ]
}

/// The count's words with non-wrapping edge-coverage increment at `COVERAGE_MAP + edge_idx`.
pub fn count_cov(t: u64, s: u64, edge_idx: u16) -> [u32; 13] {
    [
        0xa9be_47f0, // stp x16, x17, [sp, #-32]!
        insn::movz_hi(X16, COVERAGE_MAP),
        0xf280_0000 | ((edge_idx as u32) << 5) | 16, // movk x16, #edge_idx
        0x3940_0211,                                 // ldrb w17, [x16]
        0x1100_0631,                                 // add w17, w17, #1
        0x2a51_2231,                                 // orr w17, w17, w17, lsr #8 (never wraps to 0)
        0x3900_0211,                                 // strb w17, [x16]
        insn::movz_hi(X16, CELL),
        0xf940_0211, // ldr x17, [x16]
        0xd100_0631, // sub x17, x17, #1
        0xf900_0211, // str x17, [x16]
        insn::cbz_x17(t.wrapping_add(44), s),
        RESTORE,
    ]
}

/// `ldp x16, x17, [sp], #32`.
pub const RESTORE: u32 = 0xa8c2_47f0;

/// Where trampolines go: from `after` (a page past the image) upward; with `before`, the
/// sites below its split address get theirs below its end (a page at or before the image's
/// start), downward, the highest site nearest.
#[derive(Clone, Copy)]
pub struct Place {
    pub after: u64,
    pub before: Option<(u64, u64)>,
}

/// Every site in address order with what became of it; the plan's site rows (in order of
/// their trampolines), patched words and the trampolines' span: `tramp` from `tramp_vaddr`
/// (a multiple of the page size; below the image when there are trampolines before it).
pub struct Emitted {
    pub choices: Vec<Choice>,
    pub sites: Vec<Site>,
    pub patched: Vec<(u64, Vec<u8>)>,
    pub tramp_vaddr: u64,
    pub tramp: Vec<u8>,
}

/// `far(site, target)`: whether a call or jump to `target` may go through `x16` (`KIND_FAR`)
/// when a `b` from its trampoline does not reach.
#[cfg_attr(not(test), allow(dead_code))]
pub fn emit(code: &Code, place: Place, far: &dyn Fn(u64, u64) -> bool) -> Emitted {
    emit_with(code, place, None, far)
}

pub fn emit_with(
    code: &Code,
    place: Place,
    cov_sha: Option<&[u8; 32]>,
    far: &dyn Fn(u64, u64) -> bool,
) -> Emitted {
    let coverage = cov_sha.is_some();
    let mut choices = vec![];
    let mut todo = vec![];
    for (a, w) in code.proven() {
        let Some((class, kind)) = classify_with(a, w, coverage) else {
            continue;
        };
        let target = match insn::flow(a, w) {
            Flow::Direct { target, .. } | Flow::Cond { target, .. } => Some(target),
            _ => None,
        };
        // A word whose address code takes (`adr`, an `adrp` pair) may be read through it.
        let outcome = if code.flags(a) & (TAINT | ADDR) != 0 {
            Outcome::Tainted
        } else if code.flags(a) & (PAIR | RETRY) != 0
            || target.is_some_and(|t| code.flags(t) & PAIR != 0)
        {
            Outcome::Exclusive
        } else {
            todo.push((choices.len(), a, w, kind, target));
            Outcome::InPlace
        };
        choices.push(Choice {
            class,
            addr: a,
            outcome,
        });
    }
    let split = place.before.map_or(0, |(_, s)| s);
    let mut made: Vec<(u64, Vec<u32>, Site, u32)> = vec![];
    let mut make =
        |at: &mut u64, up: bool, &(i, a, w, kind, target): &(usize, u64, u32, u8, Option<u64>)| {
            let fits = |t: u64, far_row: bool| {
                trampoline_with(
                    a,
                    w,
                    if far_row { KIND_FAR } else { kind },
                    target,
                    t,
                    cov_sha,
                )
            };
            let far_ok = kind == KIND_JUMP && target.is_some_and(|to| far(a, to));
            let mut got = None;
            for far_row in [false, true] {
                if far_row && !far_ok {
                    break;
                }
                let n = words(if far_row { KIND_FAR } else { kind }, coverage) * 4;
                let t = if up { *at } else { at.wrapping_sub(n) };
                if let Some(x) = fits(t, far_row) {
                    got = Some((t, n, x));
                    break;
                }
            }
            match got {
                Some((t, n, (ws, site, patch))) => {
                    *at = if up { t + n } else { t };
                    made.push((t, ws, site, patch));
                }
                None => choices[i].outcome = Outcome::Far,
            }
        };
    let mut at = place.after;
    for x in todo.iter().filter(|x| x.1 >= split) {
        make(&mut at, true, x);
    }
    let hi = at.next_multiple_of(PAGE);
    let mut lo = place.after;
    if let Some((end, _)) = place.before {
        let mut at = end;
        for x in todo.iter().filter(|x| x.1 < split).rev() {
            make(&mut at, false, x);
        }
        lo = at & !(PAGE - 1);
    }
    made.sort_by_key(|m| m.0.wrapping_sub(lo));
    let mut e = Emitted {
        choices,
        sites: vec![],
        patched: vec![],
        tramp_vaddr: lo,
        tramp: vec![0; hi.wrapping_sub(lo) as usize],
    };
    for (t, ws, mut site, patch) in made {
        let o = t.wrapping_sub(lo) as usize;
        for (k, w) in ws.iter().enumerate() {
            e.tramp[o + 4 * k..o + 4 * k + 4].copy_from_slice(&w.to_le_bytes());
        }
        site.tramp = o as u32;
        e.patched.push((site.addr, patch.to_le_bytes().to_vec()));
        e.sites.push(site);
    }
    e.patched.sort_by_key(|p| p.0);
    e
}

/// Words of a trampoline of `kind`.
fn words(kind: u8, coverage: bool) -> u64 {
    let row = match kind {
        KIND_BEFORE => 2,
        KIND_FAR => 3,
        _ => 1,
    };
    let cond = if kind == KIND_COND { 2 } else { 0 };
    let cnt = if coverage { 13 } else { 7 };
    cond + cnt + row + 3
}

/// The trampoline at `t` for the site `w` at `a` of `kind`: its words, its row, and the word
/// that replaces the site. None when a branch would not reach.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn trampoline(
    a: u64,
    w: u32,
    kind: u8,
    target: Option<u64>,
    t: u64,
) -> Option<(Vec<u32>, Site, u32)> {
    trampoline_with(a, w, kind, target, t, None)
}

pub(super) fn trampoline_with(
    a: u64,
    w: u32,
    kind: u8,
    target: Option<u64>,
    t: u64,
    cov_sha: Option<&[u8; 32]>,
) -> Option<(Vec<u32>, Site, u32)> {
    let mut out = vec![];
    if kind == KIND_COND {
        out.push(insn::cond_to(w, t, t.wrapping_add(8))?);
        out.push(insn::b(t.wrapping_add(4), a + 4, false)?);
    }
    let c = t.wrapping_add(4 * out.len() as u64);
    let r = c.wrapping_add(if cov_sha.is_some() {
        A64_COUNT_COV
    } else {
        A64_COUNT
    });
    let row: Vec<u32> = match kind {
        KIND_BEFORE => vec![w, insn::b(r.wrapping_add(4), a + 4, false)?],
        KIND_FAR => {
            let to = target?;
            vec![
                insn::adrp(X16, r, to)?,
                insn::add_lo12(X16, X16, to),
                insn::br(X16),
            ]
        }
        _ => vec![insn::b(r, target?, false)?],
    };
    let s = r.wrapping_add(4 * row.len() as u64);
    if let Some(sha) = cov_sha {
        let idx = proto::plan::coverage_index(sha, a);
        out.extend(count_cov(c, s, idx));
    } else {
        out.extend(count(c, s));
    }
    out.extend(&row);
    out.extend([RESTORE, A64_TRAP, insn::b(s.wrapping_add(8), r, false)?]);
    debug_assert_eq!(out.len() as u64, words(kind, cov_sha.is_some()));
    let link = matches!(insn::flow(a, w), Flow::Direct { link: true, .. });
    let patch = insn::b(a, t, link)?;
    let site = Site {
        addr: a,
        len: 4,
        kind,
        tramp: 0,
        tramp_len: 4 * out.len() as u16,
        trap: s.wrapping_add(4).wrapping_sub(t) as u16,
        copy: r.wrapping_sub(t) as u16,
    };
    Some((out, site, patch))
}
