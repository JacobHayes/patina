//! Switch points (DESIGN 2.3, 2.4): `select` chooses where counts go, `emit` writes the patches
//! and trampolines.
//!
//! Sites are backward direct branches, backward direct calls, indirect jumps and atomic
//! instructions. A site's count goes, in order of preference:
//!   in place     `call f` → `call T` (T: count; jmp f); backward `jmp L`/`jcc L` (rel32) →
//!                the same aimed at T (T: count; jmp L) when the flags are dead at L; an
//!                atomic of 5 bytes or more → `jmp T` (T: count; the atomic; jmp back) when
//!                the flags are dead at it;
//!   in its block before a relocatable instruction of 5 bytes or more of the straight-line run
//!                that ends at the site (no branch target in between), flags dead there;
//!   at the loop head (backward branches): before such an instruction of the straight-line run
//!                that starts at the branch target;
//!   in a group:  the same two runs (the block's with the site itself, and for an atomic the
//!                straight-line instructions after it), several neighbouring instructions of
//!                5 bytes or more together, the last of which may be a direct branch: they
//!                become one `jmp T` and run as copies in T.
//! Indirect jumps are never patched in place: flags at their targets are unknown.
//!
//! A single instruction's patch has one entry, its first byte. A group's other instruction
//! starts (its interior boundaries) now hold bytes of the jump, and code the rewriter cannot see
//! (a jump-table case block that is dark, an indirect jump) may still jump there. So a group is
//! made only when no known branch target, address taken or landing pad is at an interior
//! boundary, and when every interior boundary can hold a byte that faults (`plan::TRAP_BYTES`):
//! the jump is `2e`×p `e9` d0 d1 d2 d3 then `int3` filler (`layout`), a boundary in the filler is
//! `int3`, one on d0, d1 or d2 gets a trapping byte by where the trampoline is placed (`fit`),
//! and none may be on the prefixes, the opcode or d3. The plan lists each interior boundary
//! (`KIND_INTERIOR`) with the copy of its instruction, where the runtime resumes a jump there.

use super::code::{direct_target, Code, Dec, ADDR, READ, TAINT, TARGET};
use super::flags::dead_at;
use super::par::Par;
use super::plan::{
    Entry, Site, CELL, KIND_BEFORE, KIND_CPUID, KIND_INTERIOR, KIND_JUMP, NO_COPY, PAD_PREFIX,
    PAGE, TRAP_BYTES,
};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind};
use std::collections::{BTreeMap, BTreeSet};

pub use super::class::Class;

/// How a patch changes the code.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form {
    /// `call rel32` → `call T`; T counts and jumps to the original target.
    Call,
    /// `jmp rel32` → `jmp T`, likewise.
    Jmp,
    /// `jcc rel32` → `jcc T` (same condition), likewise on the taken path.
    Jcc,
    /// The instruction, or a group of them → `jmp T` and `int3` filler; T counts, runs a copy
    /// of each, jumps back.
    Before,
}

/// What became of one site.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    InPlace(u64),
    Moved(u64),
    /// Its count is one an earlier site's choice already placed.
    Shared(u64),
    /// A group patch starting at this address holds its count.
    Grouped(u64),
    Tainted,
    FlagsLive,
    NoRoom,
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

impl Choice {
    /// Where the site's count is, if it has one.
    pub fn count_at(&self) -> Option<u64> {
        match self.outcome {
            Outcome::InPlace(x) | Outcome::Moved(x) | Outcome::Shared(x) | Outcome::Grouped(x) => {
                Some(x)
            }
            _ => None,
        }
    }
}

/// The site class of an instruction, if it is one.
pub fn classify(i: &Instruction) -> Option<Class> {
    let back = |t: u64| t <= i.ip();
    match i.flow_control() {
        FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => direct_target(i)
            .filter(|&t| back(t))
            .map(|_| Class::BackBranch),
        FlowControl::Call if i.mnemonic() != Mnemonic::Syscall => direct_target(i)
            .filter(|&t| back(t))
            .map(|_| Class::BackCall),
        FlowControl::IndirectBranch => Some(Class::IndirectJump),
        FlowControl::Next => {
            let xchg_mem = i.mnemonic() == Mnemonic::Xchg
                && (i.op0_kind() == OpKind::Memory || i.op1_kind() == OpKind::Memory);
            (i.has_lock_prefix() || xchg_mem).then_some(Class::Atomic)
        }
        _ => None,
    }
}

/// Can `i` be copied into a trampoline and run there? Straight-line, not a landing pad
/// marker, not a trap, not `hlt`, and none of the instructions the runtime answers or patches
/// where they are (`cpuid`, `rdrand`, `rdseed`, `rdpid`, `pause`, the timestamp counter).
pub fn relocatable(i: &Instruction) -> bool {
    use Mnemonic::*;
    i.flow_control() == FlowControl::Next
        && !matches!(
            i.mnemonic(),
            Hlt | Endbr64 | Endbr32 | Cpuid | Rdrand | Rdseed | Rdpid | Pause | Rdtsc | Rdtscp
        )
        // An x87 instruction records its own address (`fnstenv`, `fxsave` and a signal
        // frame's state show the last one's): a copy's would be the trampoline's.
        && !i.cpuid_features().iter().any(|f| {
            use iced_x86::CpuidFeature::*;
            matches!(f, FPU | FPU287 | FPU287XL_ONLY | FPU387 | FPU387SL_ONLY)
        })
}

/// A direct `jcc` or `jmp` with no prefix (`7x`/`eb` rel8, `0f 8x`/`e9` rel32): the one branch
/// a group may end with, copied as the rel32 form.
pub fn plain_branch(raw: &[u8]) -> bool {
    matches!(
        raw,
        [0x70..=0x7f | 0xeb, _] | [0x0f, 0x80..=0x8f, _, _, _, _] | [0xe9, _, _, _, _]
    )
}

/// How a group's jump fits over its interior boundaries `bounds` (offsets from its start,
/// ascending) in `n` bytes: `p` prefix bytes, then `jmp rel32`; the displacement bytes (of
/// d0..d2) that hold a boundary, as a mask; every boundary past the jump is `int3` filler. None
/// when no `p` keeps every boundary off the prefixes, the opcode and the displacement's high
/// byte. The cheapest mask wins (a constraint on d2 places the trampoline in one 64 KiB stripe
/// of sixteen per 16 MiB, on d1 in one 256-byte stripe of sixteen per 64 KiB).
pub fn layout(bounds: &[usize], n: usize) -> Option<(usize, u8)> {
    (0..=n.saturating_sub(5))
        .filter_map(|p| {
            let mut mask = 0u8;
            for &b in bounds {
                if b <= p || b == p + 4 {
                    return None;
                }
                if b <= p + 3 {
                    mask |= 1 << (b - p - 1);
                }
            }
            Some((p, mask))
        })
        .min_by_key(|&(p, mask)| (mask, p))
}

/// The smallest `t >= t0` such that a jump ending at `e` to `t` has a trapping byte
/// (`TRAP_BYTES`) at each of its displacement's low three bytes that `mask` names.
pub fn fit(t0: u64, e: u64, mask: u8) -> u64 {
    let mut t = t0;
    'again: loop {
        let d = t.wrapping_sub(e);
        for k in (0..3).rev() {
            let unit = 1u64 << (8 * k);
            let b = (d >> (8 * k)) as u8;
            if mask & (1 << k) == 0 || TRAP_BYTES.contains(&b) {
                continue;
            }
            // The next value of this byte that traps, every byte below it zero.
            let high = d & !(unit * 256 - 1);
            let nd = match TRAP_BYTES.iter().find(|&&x| x > b) {
                Some(&x) => high + x as u64 * unit,
                None => high + unit * 256 + TRAP_BYTES[0] as u64 * unit,
            };
            t = t.wrapping_add(nd - d);
            continue 'again;
        }
        return t;
    }
}

struct Select<'c, 'a> {
    code: &'c Code<'a>,
    dec: Dec<'a>,
    /// Each patch by its first byte: its form and length. Patches never overlap.
    patches: BTreeMap<u64, (Form, u8)>,
    /// Since `start`: the lowest address whose patch was asked for, and the patch placed.
    lo: std::cell::Cell<u64>,
    put: Option<(u64, Form, u8)>,
}

impl<'c, 'a> Select<'c, 'a> {
    fn new(code: &'c Code<'a>) -> Select<'c, 'a> {
        Select {
            code,
            dec: code.dec(),
            patches: BTreeMap::new(),
            lo: std::cell::Cell::new(u64::MAX),
            put: None,
        }
    }

    /// The patch whose bytes hold `x` (the one patch that covers it: they never overlap).
    fn owner(&self, x: u64) -> Option<u64> {
        self.lo.set(self.lo.get().min(x));
        let (&a, &(_, n)) = self.patches.range(..=x).next_back()?;
        (x < a + n as u64).then_some(a)
    }

    fn counts_at(&self, x: u64) -> bool {
        self.lo.set(self.lo.get().min(x));
        matches!(self.patches.get(&x), Some((Form::Before, _)))
    }

    fn insert(&mut self, x: u64, form: Form, n: u8) {
        self.patches.insert(x, (form, n));
        self.put = Some((x, form, n));
    }

    /// Where the count of the site at `a` goes: the patch it is in already, or its own choice;
    /// what it asked of the patches placed (`lo`) and placed (`put`).
    fn choose(&mut self, a: u64, i: &Instruction, class: Class) -> Outcome {
        self.lo.set(u64::MAX);
        self.put = None;
        match self.owner(a) {
            Some(x) => Outcome::Shared(x),
            None => self.site(a, i, class),
        }
    }

    /// A count before the instruction at `x`: `Some(true)` placed or already there,
    /// `Some(false)` room but flags live, `None` no room.
    fn before(&mut self, x: u64) -> Option<bool> {
        if self.counts_at(x) {
            return Some(true);
        }
        let i = self.code.insn_in(&mut self.dec, x)?;
        if i.len() < 5
            || !relocatable(&i)
            || self.code.flags(x) & TAINT != 0
            || self.owner(x).is_some()
        {
            return None;
        }
        if !dead_at(self.code, &mut self.dec, x) {
            return Some(false);
        }
        self.insert(x, Form::Before, i.len() as u8);
        Some(true)
    }

    /// Try the instructions of `run` in order: the first that takes the count, and whether
    /// an earlier choice had already placed one there.
    fn first(&mut self, run: &[u64], live: &mut bool) -> Option<(u64, bool)> {
        for &x in run {
            let shared = self.counts_at(x);
            match self.before(x) {
                Some(true) => return Some((x, shared)),
                Some(false) => *live = true,
                None => {}
            }
        }
        None
    }

    /// A group over consecutive instructions of `seq` (a straight-line run in address order):
    /// from the start nearest its end, the shortest of 5 bytes or more whose instructions are
    /// free and untainted, all relocatable but a last plain branch, with no known branch
    /// target or address taken at an interior boundary and a layout; flags dead at its start.
    fn group(&mut self, seq: &[u64], live: &mut bool) -> Option<u64> {
        'start: for i in (0..seq.len()).rev() {
            let (mut n, mut bounds) = (0usize, vec![]);
            for &x in &seq[i..] {
                let Some(ins) = self.code.insn_in(&mut self.dec, x) else {
                    continue 'start;
                };
                let raw = self.code.bytes(x, ins.len()).unwrap_or(&[]);
                let branch = plain_branch(raw);
                if self.code.flags(x) & TAINT != 0
                    || self.owner(x).is_some()
                    || !(relocatable(&ins) || branch)
                    || (n > 0 && self.code.flags(x) & (TARGET | ADDR) != 0)
                {
                    continue 'start;
                }
                if n > 0 {
                    bounds.push(n);
                }
                n += ins.len();
                if n >= 5 || branch {
                    break;
                }
            }
            if n < 5 || bounds.is_empty() || layout(&bounds, n).is_none() {
                continue;
            }
            if !dead_at(self.code, &mut self.dec, seq[i]) {
                *live = true;
                continue;
            }
            self.insert(seq[i], Form::Before, n as u8);
            return Some(seq[i]);
        }
        None
    }

    /// The straight-line run that ends at `s`, nearest first: no branch target between it and
    /// `s`, so every arrival at `s` passed it.
    fn block_before(&mut self, s: u64) -> Vec<u64> {
        let (mut out, mut b) = (vec![], s);
        while out.len() < 16 && self.code.flags(b) & TARGET == 0 {
            let Some(p) = self.code.prev(b) else { break };
            match self.code.insn_in(&mut self.dec, p) {
                Some(i)
                    if i.flow_control() == FlowControl::Next && i.mnemonic() != Mnemonic::Hlt => {}
                _ => break,
            }
            out.push(p);
            b = p;
        }
        out
    }

    /// The straight-line run from `l`: every pass through `l` runs all of it.
    fn run_from(&mut self, mut l: u64, max: usize) -> Vec<u64> {
        let mut out = vec![];
        while out.len() < max {
            let Some(i) = self.code.insn_in(&mut self.dec, l) else {
                break;
            };
            out.push(l);
            if i.flow_control() != FlowControl::Next || i.mnemonic() == Mnemonic::Hlt {
                break;
            }
            l += i.len() as u64;
        }
        out
    }

    fn site(&mut self, s: u64, i: &Instruction, class: Class) -> Outcome {
        if self.code.flags(s) & TAINT != 0 {
            return Outcome::Tainted;
        }
        let raw = self.code.bytes(s, i.len()).unwrap_or(&[]);
        let mut live = false;
        let in_place = match class {
            Class::BackCall if raw.len() == 5 && raw[0] == 0xe8 => Some(Form::Call),
            Class::BackBranch if raw.len() == 5 && raw[0] == 0xe9 => Some(Form::Jmp),
            Class::BackBranch if raw.len() == 6 && raw[0] == 0x0f && raw[1] & 0xf0 == 0x80 => {
                Some(Form::Jcc)
            }
            Class::Atomic if raw.len() >= 5 => Some(Form::Before),
            _ => None,
        };
        match in_place {
            // The flags are dead at a function's entry.
            Some(Form::Call) => {
                self.insert(s, Form::Call, 5);
                return Outcome::InPlace(s);
            }
            Some(f @ (Form::Jmp | Form::Jcc)) => {
                if dead_at(self.code, &mut self.dec, i.near_branch_target()) {
                    self.insert(s, f, raw.len() as u8);
                    return Outcome::InPlace(s);
                }
                live = true;
            }
            Some(Form::Before) => match self.before(s) {
                Some(true) => return Outcome::InPlace(s),
                Some(false) => live = true,
                None => {}
            },
            None => {}
        }
        let block = self.block_before(s);
        let head = (class == Class::BackBranch).then(|| self.run_from(i.near_branch_target(), 8));
        let mut found = self.first(&block, &mut live);
        if let (None, Some(head)) = (found, &head) {
            found = self.first(head, &mut live);
        }
        match found {
            Some((x, true)) => return Outcome::Shared(x),
            Some((x, false)) => return Outcome::Moved(x),
            None => {}
        }
        // A group: the block's run with the site (and, for an atomic, what follows it), then
        // the loop head's.
        let mut seq: Vec<u64> = block.into_iter().rev().collect();
        seq.push(s);
        if class == Class::Atomic {
            let after = self.run_from(s + i.len() as u64, 4);
            let free = after
                .iter()
                .take_while(|&&x| self.code.flags(x) & TARGET == 0)
                .count();
            seq.extend(&after[..free]);
        }
        let mut grouped = self.group(&seq, &mut live);
        if let (None, Some(head)) = (grouped, &head) {
            grouped = self.group(head, &mut live);
        }
        match grouped {
            Some(x) => Outcome::Grouped(x),
            None if live => Outcome::FlagsLive,
            None => Outcome::NoRoom,
        }
    }
}

/// Every site, in address order, with where its count goes; and the patches that places (by
/// first byte: form and length).
///
/// A site's choice depends on the choices before it only through the patches it asks about
/// (`owner`, `counts_at`), all at or above the lowest address it asks about. On several
/// threads, each part of the sites is chosen at once from no patches; then in order, a site
/// whose part placed the same patches as the whole order did so far, and that asks about
/// nothing below the end of every patch the parts before it placed, would choose the same and
/// is taken as it is; any other is chosen again on the whole order's patches (and once one
/// such places otherwise, the rest of its part too).
pub fn select(code: &Code, par: &Par) -> (Vec<Choice>, BTreeMap<u64, (Form, u8)>) {
    // Finding the sites is per instruction; choosing where their counts go is in order.
    let sites = code.starts_with(par, |d, a| {
        let i = code.insn_in(d, a)?;
        classify(&i).map(|class| (i, class))
    });
    let mut s = Select::new(code);
    let choice = |a: u64, class: Class, outcome: Outcome| Choice {
        class,
        addr: a,
        outcome,
    };
    if par.threads() == 1 {
        let out = sites
            .iter()
            .map(|&(a, (ref i, class))| choice(a, class, s.choose(a, i, class)))
            .collect();
        return (out, s.patches);
    }
    let bounds = par.parts(sites.len(), |part| part);
    let ahead = par.each(&bounds, |_, part| {
        let mut p = Select::new(code);
        sites[part.clone()]
            .iter()
            .map(|&(a, (ref i, class))| (p.choose(a, i, class), p.lo.get(), p.put))
            .collect::<Vec<_>>()
    });
    let mut out = Vec::with_capacity(sites.len());
    let mut end = 0;
    for (part, ahead) in bounds.into_iter().zip(ahead) {
        let below = end;
        let mut same = true;
        for (&(a, (ref i, class)), (o, lo, put)) in sites[part].iter().zip(ahead) {
            let (o, put) = if same && lo >= below {
                if let Some((x, f, n)) = put {
                    s.patches.insert(x, (f, n));
                }
                (o, put)
            } else {
                let again = s.choose(a, i, class);
                same &= again == o && s.put == put;
                (again, s.put)
            };
            if let Some((x, _, n)) = put {
                end = end.max(x + n as u64);
            }
            out.push(choice(a, class, o));
        }
    }
    (out, s.patches)
}

fn rel32(from_end: u64, to: u64) -> Option<[u8; 4]> {
    i32::try_from(to.wrapping_sub(from_end) as i64)
        .ok()
        .map(i32::to_le_bytes)
}

/// The trampolines and patched bytes for `patches`, in a span placed at `tramp_vaddr`. A patch
/// whose jumps or copied operands would not reach is dropped and returned in `far`.
pub struct Emitted {
    /// In order of their trampolines.
    pub sites: Vec<Site>,
    /// In address order.
    pub entries: Vec<Entry>,
    pub patched: Vec<(u64, Vec<u8>)>,
    /// The span, a multiple of the page size.
    pub tramp: Vec<u8>,
    /// Bytes of trampolines in it.
    pub used: u64,
    pub far: BTreeSet<u64>,
    pub groups: u64,
}

/// Free room of the trampolines' span: offset → end. Placement is first fit among the first
/// intervals at or after the lowest offset that suits, then the top; leftovers shorter than
/// any trampoline are dropped.
struct Space {
    free: BTreeMap<u64, u64>,
}

const SMALLEST: u64 = 19;

impl Space {
    fn take(&mut self, lo: u64, len: u64, place: impl Fn(u64) -> u64) -> u64 {
        let first = self.free.range(..=lo).next_back().map_or(lo, |(&s, _)| s);
        let (s, e, x) = self
            .free
            .range(first..)
            .take(64)
            .chain(self.free.iter().next_back())
            .find_map(|(&s, &e)| {
                let x = place(s.max(lo));
                x.checked_add(len)
                    .is_some_and(|end| end <= e)
                    .then_some((s, e, x))
            })
            .expect("the top interval is unbounded");
        self.free.remove(&s);
        if x - s >= SMALLEST {
            self.free.insert(s, x);
        }
        if e - (x + len) >= SMALLEST || e == u64::MAX {
            self.free.insert(x + len, e);
        }
        x
    }
}

/// One patch's instructions: address, decode, original bytes.
type Insns<'a> = Vec<(u64, Instruction, &'a [u8])>;

pub fn emit(
    code: &Code,
    patches: &BTreeMap<u64, (Form, u8)>,
    tramp_vaddr: u64,
    par: &Par,
) -> Emitted {
    let mut e = Emitted {
        sites: vec![],
        entries: vec![],
        patched: vec![],
        tramp: vec![],
        used: 0,
        far: BTreeSet::new(),
        groups: 0,
    };
    // Each patch's instructions and layout; those whose trampoline's address is constrained
    // are placed first, then the rest fill around them.
    let patches: Vec<(u64, Form, u8)> = patches.iter().map(|(&a, &(f, n))| (a, f, n)).collect();
    let laid = par.parts(patches.len(), |part| {
        let (mut out, mut d) = (vec![], code.dec());
        for &(a, form, n) in &patches[part] {
            let mut ins: Insns = vec![];
            let mut x = a;
            while x < a + n as u64 {
                let Some(i) = code.insn_in(&mut d, x) else {
                    break;
                };
                ins.push((x, i, code.bytes(x, i.len()).unwrap()));
                x += i.len() as u64;
            }
            let bounds: Vec<usize> = ins[1..].iter().map(|&(x, ..)| (x - a) as usize).collect();
            out.push(
                match layout(&bounds, n as usize).filter(|_| x == a + n as u64) {
                    Some((p, mask)) => Ok((mask == 0, a, form, n, ins, p, mask)),
                    None => Err(a),
                },
            );
        }
        out
    });
    let mut work = vec![];
    for w in laid.into_iter().flatten() {
        match w {
            Ok(w) => work.push(w),
            Err(a) => {
                e.far.insert(a);
            }
        }
    }
    work.sort_by_key(|w| (w.0, w.1));
    let mut space = Space {
        free: BTreeMap::from([(0, u64::MAX)]),
    };
    // Where each goes, in order (each place depends on the ones before); then the trampolines
    // themselves, each a function of its own place.
    let (mut cursor, mut next) = (0, None);
    let mut placed = Vec::with_capacity(work.len());
    for (_, a, form, n, ins, p, mask) in work {
        let len = tramp_len(form, &ins);
        let end = a + p as u64 + 5;
        // Constrained trampolines go up from a cursor, in address order: each next one's
        // displacement is smaller, so where one had to skip ahead it goes to the top stripe
        // of that run of trapping values and the ones after it fit right behind it. The rest
        // fill the gaps between them in address order, then go on past them: the pages they
        // touch are few (only pages holding a trampoline are stored).
        let place = |x: u64| {
            let mut t = fit(tramp_vaddr + x, end, mask);
            if mask & 0b110 != 0 {
                // The displacement's highest constrained byte (the mask is not 0 here), and
                // the displacement as `fit` takes it: modulo 2^64, a trampoline below its
                // site included.
                let k = 7 - mask.leading_zeros() as u64;
                let stripe = |t: u64| t.wrapping_sub(end) >> (8 * k);
                if stripe(t) != stripe(tramp_vaddr + x) {
                    while TRAP_BYTES.contains(&(stripe(t) as u8).wrapping_add(1)) {
                        t += 1 << (8 * k);
                    }
                }
            }
            t - tramp_vaddr
        };
        let x = space.take(
            if mask == 0 { next.unwrap_or(0) } else { cursor },
            len,
            place,
        );
        cursor = cursor.max(x + len);
        next = Some(if mask == 0 {
            x + len
        } else {
            next.unwrap_or(x)
        });
        placed.push((x, a, form, n, ins, p));
    }
    let made = par.parts(placed.len(), |part| {
        placed[part]
            .iter()
            .map(|&(x, a, form, n, ref ins, p)| {
                let t = tramp_vaddr + x;
                let (b, mut site) = trampoline(a, ins, form, t)?;
                let mut patch = match form {
                    Form::Call => vec![0xe8],
                    Form::Jmp | Form::Before => {
                        vec![PAD_PREFIX; p].into_iter().chain([0xe9]).collect()
                    }
                    Form::Jcc => vec![0x0f, ins[0].2[1]],
                };
                let d = rel32(a + patch.len() as u64 + 4, t)?;
                patch.extend_from_slice(&d);
                patch.resize(n as usize, 0xcc);
                if ins[1..]
                    .iter()
                    .any(|&(y, ..)| !TRAP_BYTES.contains(&patch[(y - a) as usize]))
                {
                    unreachable!("fit places every interior boundary on a trapping byte");
                }
                site.tramp = x as u32;
                Some((b, site, patch))
            })
            .collect::<Vec<_>>()
    });
    let mut top = 0;
    for ((x, a, _, _, ins, _), m) in placed.iter().zip(made.into_iter().flatten()) {
        let (x, a) = (*x, *a);
        let Some((b, site, patch)) = m else {
            e.far.insert(a);
            continue;
        };
        top = top.max(x + b.len() as u64);
        if e.tramp.len() < top as usize {
            e.tramp.resize(top as usize, 0);
        }
        e.tramp[x as usize..x as usize + b.len()].copy_from_slice(&b);
        e.used += b.len() as u64;
        for &(y, ..) in &ins[1..] {
            e.entries.push(Entry {
                addr: y,
                to: x as u32 + site.copy as u32 + (y - a) as u32,
                kind: KIND_INTERIOR,
            });
        }
        e.groups += (ins.len() > 1) as u64;
        e.sites.push(site);
        e.patched.push((a, patch));
    }
    e.tramp
        .resize(e.tramp.len().next_multiple_of(PAGE as usize), 0);
    e.sites.sort_by_key(|s| s.tramp);
    e.entries.sort_by_key(|n| n.addr);
    e
}

/// Every `cpuid` in eligible code becomes `ud2`, a `KIND_CPUID` entry the runtime answers.
/// Returns the count patched, and the `0F A2` byte pairs left elsewhere in the text: an upper
/// bound on the `cpuid`s in dark or tainted code, which run unanswered.
pub fn cpuid_sites(code: &Code, em: &mut Emitted, par: &Par) -> (u64, u64) {
    // `cpuid` is `0f a2` with no operand: an instruction whose last two bytes are not that is
    // no `cpuid`, and is not decoded again.
    let found: Vec<u64> = code
        .starts_with(par, |d, a| {
            // As for every patch: untainted, its bytes not read as data, no address taken inside.
            let clean = code.flags(a) & (TAINT | READ) == 0
                && code.flags(a + 1) & (READ | ADDR | TARGET) == 0;
            let n = code.len_at(a)?;
            let tail = (n >= 2).then(|| code.bytes(a + n as u64 - 2, 2)).flatten();
            (clean
                && tail == Some(&[0x0f, 0xa2][..])
                && code
                    .insn_in(d, a)
                    .is_some_and(|i| i.mnemonic() == Mnemonic::Cpuid))
            .then_some(())
        })
        .into_iter()
        .map(|(a, ())| a)
        .collect();
    let mut unpatched = 0;
    for r in &code.regions {
        let pairs = r.bytes.len().saturating_sub(1);
        unpatched += par
            .parts(pairs, |part| {
                let mut n = 0u64;
                for o in part {
                    let a = r.addr + o as u64;
                    if r.bytes[o..o + 2] == [0x0f, 0xa2] && found.binary_search(&a).is_err() {
                        n += 1;
                    }
                }
                n
            })
            .iter()
            .sum::<u64>();
    }
    for &a in &found {
        em.entries.push(Entry {
            addr: a,
            to: 0,
            kind: KIND_CPUID,
        });
        em.patched.push((a, vec![0x0f, 0x0b]));
    }
    em.entries.sort_by_key(|n| n.addr);
    (found.len() as u64, unpatched)
}

/// The length of an instruction's copy: a short branch is copied as its rel32 form.
fn copy_len(i: &Instruction, raw: &[u8]) -> usize {
    match raw {
        [0x70..=0x7f, _] => 6,
        [0xeb, _] => 5,
        _ => i.len(),
    }
}

fn tramp_len(form: Form, ins: &Insns) -> u64 {
    let row = match form {
        Form::Before => ins.iter().map(|(_, i, r)| copy_len(i, r)).sum::<usize>() + 5,
        _ => 5,
    };
    (10 + row + 4) as u64
}

/// One trampoline at `t`:
///
/// ```text
/// T:  dec qword [CELL]     48 FF 0C 25 <abs32>
///     jz  S                74 <rel8>
/// R:  the row: jmp <original target>, or <copies of the instructions>; jmp <next>
/// S:  hlt                  F4           a point: the runtime's fault entry (`SIGSEGV`)
///     jmp R                EB <rel8>
/// ```
///
/// A copy is byte for byte but for a RIP-relative displacement (recomputed) and a closing
/// branch (its rel32 form, to the same target).
fn trampoline(a: u64, ins: &Insns, form: Form, t: u64) -> Option<(Vec<u8>, Site)> {
    let mut b = vec![0x48, 0xff, 0x0c, 0x25];
    b.extend_from_slice(&(CELL as u32).to_le_bytes());
    b.extend_from_slice(&[0x74, 0]);
    let r = b.len();
    let mut copy = NO_COPY;
    let (n, back) = if form == Form::Before {
        copy = r as u16;
        for &(x, ref i, raw) in ins {
            let at = t + b.len() as u64;
            if plain_branch(raw) {
                let op = match raw {
                    [0xeb | 0xe9, ..] => vec![0xe9],
                    [0x0f, c, ..] => vec![0x0f, *c],
                    [c, _] => vec![0x0f, 0x80 | (c & 0x0f)],
                    _ => return None,
                };
                let end = at + op.len() as u64 + 4;
                b.extend_from_slice(&op);
                b.extend_from_slice(&rel32(end, i.near_branch_target())?);
                continue;
            }
            let mut c = raw.to_vec();
            if i.is_ip_rel_memory_operand() {
                let mut d = Decoder::with_ip(64, raw, x, DecoderOptions::NONE);
                let ins = d.decode();
                let off = d.get_constant_offsets(&ins);
                let o = off.displacement_offset();
                c[o..o + 4]
                    .copy_from_slice(&rel32(at + raw.len() as u64, i.ip_rel_memory_address())?);
            }
            b.extend_from_slice(&c);
        }
        let n: usize = ins.iter().map(|(_, i, _)| i.len()).sum();
        (n, a + n as u64)
    } else {
        (ins[0].1.len(), ins[0].1.near_branch_target())
    };
    b.push(0xe9);
    b.extend_from_slice(&rel32(t + b.len() as u64 + 4, back)?);
    let trap = b.len();
    b[r - 1] = (trap - r) as u8;
    b.extend_from_slice(&[0xf4, 0xeb]);
    b.push((r as isize - (b.len() as isize + 1)) as i8 as u8);
    let kind = if form == Form::Before {
        KIND_BEFORE
    } else {
        KIND_JUMP
    };
    let site = Site {
        addr: a,
        len: n as u8,
        kind,
        tramp: 0,
        tramp_len: b.len() as u16,
        trap: trap as u16,
        copy,
    };
    Some((b, site))
}
