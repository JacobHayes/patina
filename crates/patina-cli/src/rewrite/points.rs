//! Switch points (DESIGN 2.3): `select` chooses where counts go, `emit` writes the patches and
//! trampolines. Only single-instruction patches: one instruction of at least 5 bytes becomes a
//! jump or call to its trampoline, so no address but the patch's first byte changes meaning.
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
//!                that starts at the branch target.
//! Indirect jumps are never patched in place: flags at their targets are unknown.

use super::code::{direct_target, Code, ADDR, READ, TAINT, TARGET};
use super::flags::dead_at;
use super::plan::{Site, CELL, KIND_BEFORE, KIND_CPUID, KIND_JUMP, NO_COPY};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Class {
    BackBranch,
    BackCall,
    IndirectJump,
    Atomic,
}

impl Class {
    pub const ALL: [Class; 4] = [
        Class::BackBranch,
        Class::BackCall,
        Class::IndirectJump,
        Class::Atomic,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Class::BackBranch => "back-branch",
            Class::BackCall => "back-call",
            Class::IndirectJump => "indirect-jump",
            Class::Atomic => "atomic",
        }
    }
}

/// How a patched instruction changes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form {
    /// `call rel32` → `call T`; T counts and jumps to the original target.
    Call,
    /// `jmp rel32` → `jmp T`, likewise.
    Jmp,
    /// `jcc rel32` → `jcc T` (same condition), likewise on the taken path.
    Jcc,
    /// The instruction → `jmp T` and `int3` padding; T counts, runs a copy, jumps back.
    Before,
}

/// What became of one site.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    InPlace(u64),
    Moved(u64),
    /// Its count is one an earlier site's choice already placed.
    Shared(u64),
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
            Outcome::InPlace(x) | Outcome::Moved(x) | Outcome::Shared(x) => Some(x),
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
/// marker, not a trap, not `hlt`.
pub fn relocatable(i: &Instruction) -> bool {
    i.flow_control() == FlowControl::Next
        && !matches!(
            i.mnemonic(),
            Mnemonic::Hlt | Mnemonic::Endbr64 | Mnemonic::Endbr32
        )
}

struct Select<'c, 'a> {
    code: &'c Code<'a>,
    patches: BTreeMap<u64, Form>,
}

impl Select<'_, '_> {
    /// A count before the instruction at `x`: `Some(true)` placed or already there,
    /// `Some(false)` room but flags live, `None` no room.
    fn before(&mut self, x: u64) -> Option<bool> {
        if self.patches.get(&x) == Some(&Form::Before) {
            return Some(true);
        }
        let i = self.code.insn(x)?;
        if i.len() < 5
            || !relocatable(&i)
            || self.code.flags(x) & TAINT != 0
            || self.patches.contains_key(&x)
        {
            return None;
        }
        if !dead_at(self.code, x) {
            return Some(false);
        }
        self.patches.insert(x, Form::Before);
        Some(true)
    }

    /// Try the instructions of `run` in order: the first that takes the count, and whether
    /// an earlier choice had already placed one there.
    fn first(&mut self, run: Vec<u64>, live: &mut bool) -> Option<(u64, bool)> {
        for x in run {
            let shared = self.patches.get(&x) == Some(&Form::Before);
            match self.before(x) {
                Some(true) => return Some((x, shared)),
                Some(false) => *live = true,
                None => {}
            }
        }
        None
    }

    /// The straight-line run that ends at `s`, nearest first: no branch target between it and
    /// `s`, so every arrival at `s` passed it.
    fn block_before(&self, s: u64) -> Vec<u64> {
        let (mut out, mut b) = (vec![], s);
        while out.len() < 16 && self.code.flags(b) & TARGET == 0 {
            let Some(p) = self.code.prev(b) else { break };
            match self.code.insn(p) {
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
    fn run_from(&self, mut l: u64) -> Vec<u64> {
        let mut out = vec![];
        while out.len() < 8 {
            let Some(i) = self.code.insn(l) else { break };
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
                self.patches.insert(s, Form::Call);
                return Outcome::InPlace(s);
            }
            Some(f @ (Form::Jmp | Form::Jcc)) => {
                if dead_at(self.code, i.near_branch_target()) {
                    self.patches.insert(s, f);
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
        let mut found = self.first(self.block_before(s), &mut live);
        if found.is_none() && class == Class::BackBranch {
            found = self.first(self.run_from(i.near_branch_target()), &mut live);
        }
        match found {
            Some((x, true)) => Outcome::Shared(x),
            Some((x, false)) => Outcome::Moved(x),
            None if live => Outcome::FlagsLive,
            None => Outcome::NoRoom,
        }
    }
}

/// Every site, in address order, with where its count goes; and the patches that places.
pub fn select(code: &Code) -> (Vec<Choice>, BTreeMap<u64, Form>) {
    let mut s = Select {
        code,
        patches: BTreeMap::new(),
    };
    let mut out = vec![];
    for a in code.starts() {
        let Some(i) = code.insn(a) else { continue };
        if let Some(class) = classify(&i) {
            let outcome = if s.patches.get(&a) == Some(&Form::Before) {
                Outcome::Shared(a)
            } else {
                s.site(a, &i, class)
            };
            out.push(Choice {
                class,
                addr: a,
                outcome,
            });
        }
    }
    (out, s.patches)
}

fn rel32(from_end: u64, to: u64) -> Option<[u8; 4]> {
    i32::try_from(to.wrapping_sub(from_end) as i64)
        .ok()
        .map(i32::to_le_bytes)
}

/// The trampolines and patched bytes for `patches`, the blob placed at `tramp_vaddr`. A patch
/// whose jumps or copied operand would not reach is dropped and returned in `far`.
pub struct Emitted {
    pub sites: Vec<Site>,
    pub patched: Vec<(u64, Vec<u8>)>,
    pub tramp: Vec<u8>,
    pub far: BTreeSet<u64>,
}

pub fn emit(code: &Code, patches: &BTreeMap<u64, Form>, tramp_vaddr: u64) -> Emitted {
    let mut e = Emitted {
        sites: vec![],
        patched: vec![],
        tramp: vec![],
        far: BTreeSet::new(),
    };
    for (&a, &form) in patches {
        let Some(i) = code.insn(a) else { continue };
        let n = i.len();
        let raw = code.bytes(a, n).unwrap();
        match trampoline(a, &i, raw, form, tramp_vaddr + e.tramp.len() as u64) {
            Some((t, mut site, patch)) => {
                site.tramp = e.tramp.len() as u32;
                e.tramp.extend_from_slice(&t);
                e.sites.push(site);
                e.patched.push((a, patch));
            }
            None => {
                e.far.insert(a);
            }
        }
    }
    e
}

/// Every `cpuid` in eligible code becomes `ud2`, a `KIND_CPUID` site the runtime answers, merged
/// into `em`'s sites in address order (its trampoline offset is the next trampoline's, so the
/// offsets stay in row order). Returns the count patched, and the `0F A2` byte pairs left
/// elsewhere in the text: an upper bound on the `cpuid`s in dark or tainted code, which run
/// unanswered.
pub fn cpuid_sites(code: &Code, em: &mut Emitted) -> (u64, u64) {
    let mut found = vec![];
    for a in code.starts() {
        // As for every patch: untainted, its bytes not read as data, no address taken inside.
        let clean =
            code.flags(a) & (TAINT | READ) == 0 && code.flags(a + 1) & (READ | ADDR | TARGET) == 0;
        if clean
            && code
                .insn(a)
                .is_some_and(|i| i.mnemonic() == Mnemonic::Cpuid)
        {
            found.push(a);
        }
    }
    let mut unpatched = 0;
    for r in &code.regions {
        for (o, w) in r.bytes.windows(2).enumerate() {
            if w == [0x0f, 0xa2] && found.binary_search(&(r.addr + o as u64)).is_err() {
                unpatched += 1;
            }
        }
    }
    let mut sites = Vec::with_capacity(em.sites.len() + found.len());
    let mut jumps = std::mem::take(&mut em.sites).into_iter().peekable();
    for &a in &found {
        while let Some(s) = jumps.next_if(|s| s.addr < a) {
            sites.push(s);
        }
        let next = jumps.peek().map_or(em.tramp.len() as u32, |s| s.tramp);
        sites.push(Site {
            addr: a,
            len: 2,
            kind: KIND_CPUID,
            tramp: next,
            tramp_len: 0,
            trap: 0,
            copy: NO_COPY,
        });
        em.patched.push((a, vec![0x0f, 0x0b]));
    }
    sites.extend(jumps);
    em.sites = sites;
    (found.len() as u64, unpatched)
}

/// One trampoline at `t`:
///
/// ```text
/// T:  dec qword [CELL]     48 FF 0C 25 <abs32>
///     jz  S                74 <rel8>
/// R:  the row: jmp <original target>, or <copy of the instruction>; jmp <next>
/// S:  ud2                  0F 0B        a point: the runtime's fault entry
///     jmp R                EB <rel8>
/// ```
fn trampoline(
    a: u64,
    i: &Instruction,
    raw: &[u8],
    form: Form,
    t: u64,
) -> Option<(Vec<u8>, Site, Vec<u8>)> {
    let n = raw.len();
    let next = a + n as u64;
    let mut b = vec![0x48, 0xff, 0x0c, 0x25];
    b.extend_from_slice(&(CELL as u32).to_le_bytes());
    b.extend_from_slice(&[0x74, 0]);
    let r = b.len();
    let mut copy = NO_COPY;
    let back = if form == Form::Before {
        copy = r as u16;
        let mut c = raw.to_vec();
        if i.is_ip_rel_memory_operand() {
            let mut d = Decoder::with_ip(64, raw, a, DecoderOptions::NONE);
            let ins = d.decode();
            let off = d.get_constant_offsets(&ins);
            let at = off.displacement_offset();
            let new_end = t + (r + n) as u64;
            c[at..at + 4].copy_from_slice(&rel32(new_end, i.ip_rel_memory_address())?);
        }
        b.extend_from_slice(&c);
        next
    } else {
        i.near_branch_target()
    };
    b.push(0xe9);
    b.extend_from_slice(&rel32(t + b.len() as u64 + 4, back)?);
    let trap = b.len();
    b[r - 1] = (trap - r) as u8;
    b.extend_from_slice(&[0x0f, 0x0b, 0xeb]);
    b.push((r as isize - (b.len() as isize + 1)) as i8 as u8);
    let mut patch = match form {
        Form::Call => vec![0xe8],
        Form::Jmp | Form::Before => vec![0xe9],
        Form::Jcc => vec![0x0f, raw[1]],
    };
    patch.extend_from_slice(&rel32(a + patch.len() as u64 + 4, t)?);
    patch.resize(n, 0xcc);
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
    Some((b, site, patch))
}
