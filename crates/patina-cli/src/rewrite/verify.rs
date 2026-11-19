//! The plan verifier: an independent check of a plan against its file. It shares the ELF fact
//! reader, the plan reader and the instruction decoder with the rewriter, and none of its
//! decisions: it finds code its own way (control flow from the anchors, and each extent decoded
//! linearly from its start until a byte code reads or names, without the rewriter's
//! refusals) and checks that
//!   - the plan is for this file, its cell is the runtime's, and its trampolines lie outside
//!     the image;
//!   - every byte the plan changes lies in a patched instruction, and every patched instruction
//!     is one whole instruction of code found here, that no known branch enters, no code reads,
//!     and no other decode overlaps or disagrees with;
//!   - every patch is a jump, call or same-condition branch to its own trampoline, and every
//!     trampoline counts, traps to its own `ud2`, and goes on to the original target, or runs an
//!     exact copy of the instruction (same operand address) and returns right after it;
//!   - no site table entry points outside the plan.
//!
//! The rewriter's flag liveness and its taint are not re-checked here (its unit tests cover
//! them); a plan this accepts patches only whole instructions of code, each with a well-formed
//! trampoline.

use super::elf::{Elf, Text};
use super::plan::{Plan, CELL, KIND_BEFORE, KIND_CPUID, KIND_JUMP, NO_COPY, PAGE};
use iced_x86::{
    Code as Op, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};

/// Per-byte facts of one text range, found here.
struct Seen {
    t: Text,
    /// The length of an instruction found by control flow starting here.
    flow: Vec<u8>,
    /// The length of an instruction found by an extent's linear decode starting here.
    linear: Vec<u8>,
    /// 1: a direct branch, call or anchor lands here; 2: code reads here; 4: code takes this
    /// address (`lea`, or an immediate when not PIE).
    mark: Vec<u8>,
}

fn decode(bytes: &[u8], ip: u64) -> Instruction {
    Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE).decode()
}

struct Finder<'a> {
    elf: &'a Elf<'a>,
    seen: Vec<Seen>,
}

impl Finder<'_> {
    fn mark(&mut self, a: u64, m: u8) {
        if let Some((i, o)) = self.at(a) {
            self.seen[i].mark[o] |= m;
        }
    }
}

impl Finder<'_> {
    fn at(&self, a: u64) -> Option<(usize, usize)> {
        let i = self
            .seen
            .partition_point(|s| s.t.addr <= a)
            .checked_sub(1)?;
        let o = a.wrapping_sub(self.seen[i].t.addr) as usize;
        (o < self.seen[i].t.len).then_some((i, o))
    }

    fn insn(&self, a: u64) -> Option<Instruction> {
        let (i, o) = self.at(a)?;
        let i = decode(&self.elf.bytes(&self.seen[i].t)[o..], a);
        (!i.is_invalid()).then_some(i)
    }

    /// Record what `ins` reaches and reads; its direct target, if any.
    fn note(&mut self, ins: &Instruction) -> Option<u64> {
        let read = ins
            .is_ip_rel_memory_operand()
            .then(|| ins.ip_rel_memory_address());
        let m = if ins.mnemonic() == Mnemonic::Lea {
            4
        } else {
            2
        };
        if let Some(r) = read {
            self.mark(r, m);
        }
        // Not PIE: `[disp32]` and `tbl(,%rax,8)` read there; an immediate may be an address.
        if self.elf.exec {
            for k in 0..ins.op_count() {
                let kind = ins.op_kind(k);
                let tls = matches!(ins.segment_prefix(), Register::FS | Register::GS);
                if kind == OpKind::Memory && ins.memory_base() == Register::None && !tls {
                    self.mark(ins.memory_displacement64(), m);
                }
                if matches!(
                    kind,
                    OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64
                ) {
                    self.mark(ins.immediate(k), 4);
                }
            }
        }
        let t = (ins.op0_kind() == OpKind::NearBranch64).then(|| ins.near_branch_target())?;
        let (i, o) = self.at(t)?;
        self.seen[i].mark[o] |= 1;
        Some(t)
    }

    /// Control flow from `work`; a decode that would overlap one already made stops.
    fn flow(&mut self, mut work: Vec<u64>) {
        for &a in &work {
            if let Some((i, o)) = self.at(a) {
                self.seen[i].mark[o] |= 1;
            }
        }
        while let Some(mut a) = work.pop() {
            while let Some((i, o)) = self.at(a) {
                if self.seen[i].flow[o] != 0 {
                    break;
                }
                let Some(ins) = self.insn(a) else { break };
                let n = ins.len();
                let s = &self.seen[i];
                let lo = o.saturating_sub(14);
                let overlap = o + n > s.t.len
                    || s.flow[o + 1..o + n].iter().any(|&l| l != 0)
                    || (lo..o).any(|p| p + s.flow[p] as usize > o);
                if overlap {
                    break;
                }
                self.seen[i].flow[o] = n as u8;
                if let Some(t) = self.note(&ins) {
                    work.push(t);
                }
                match ins.flow_control() {
                    FlowControl::Next
                    | FlowControl::Call
                    | FlowControl::IndirectCall
                    | FlowControl::ConditionalBranch
                    | FlowControl::XbeginXabortXend
                        if ins.mnemonic() != Mnemonic::Hlt => {}
                    _ => break,
                }
                a += n as u64;
            }
        }
    }

    /// Each extent decoded linearly from its start to its end or an invalid instruction; the
    /// direct targets of what it decoded.
    fn linear(&mut self) -> Vec<u64> {
        let mut targets = vec![];
        for k in 0..self.elf.extents.len() {
            let (mut a, hi) = self.elf.extents[k];
            while a < hi {
                let Some((i, o)) = self.at(a) else { break };
                let s = &self.seen[i];
                if s.flow[o] == 0 && s.mark[o] & 6 != 0 {
                    break;
                }
                let Some(ins) = self.insn(a) else { break };
                let n = ins.len();
                if o + n > self.seen[i].t.len {
                    break;
                }
                if self.seen[i].linear[o] == 0 {
                    self.seen[i].linear[o] = n as u8;
                }
                targets.extend(self.note(&ins));
                a += n as u64;
            }
        }
        targets
    }
}

/// The bytes of `len` at `vaddr` as the plan maps them.
fn plan_bytes(plan: &Plan, vaddr: u64, len: usize) -> Option<&[u8]> {
    let p = plan
        .pages
        .iter()
        .find(|p| vaddr >= p.vaddr && vaddr + len as u64 <= p.vaddr + p.bytes.len() as u64)?;
    let o = (vaddr - p.vaddr) as usize;
    Some(&p.bytes[o..o + len])
}

/// Every way `plan` fails to be a sound plan for `data`; empty when it is one.
pub fn verify(data: &[u8], plan: &Plan) -> Vec<String> {
    let mut bad = vec![];
    let elf = match Elf::parse(data) {
        Ok(e) => e,
        Err(e) => return vec![e],
    };
    if plan.sha256 != elf.sha256 {
        return vec!["the plan is for another file (SHA-256 differs)".into()];
    }
    let in_image = |a: u64, n: u64| {
        elf.loads
            .iter()
            .any(|l| a < l.vaddr + l.memsz && l.vaddr < a + n)
    };
    let blob = (plan.tramp_vaddr, plan.tramp.len() as u64);
    if in_image(blob.0, blob.1.max(1)) {
        bad.push(format!("trampolines at {:#x} overlap the image", blob.0));
    }
    if plan.cell != CELL
        || in_image(plan.cell, 8)
        || (plan.cell < blob.0 + blob.1 && blob.0 < plan.cell + 8)
    {
        bad.push(format!(
            "cell {:#x} is not the runtime's, or not free",
            plan.cell
        ));
    }
    let mut f = Finder {
        elf: &elf,
        seen: elf
            .text
            .iter()
            .map(|&t| Seen {
                t,
                flow: vec![0; t.len],
                linear: vec![0; t.len],
                mark: vec![0; t.len],
            })
            .collect(),
    };
    f.flow(elf.anchors.clone());
    let more = f.linear();
    f.flow(more);

    // The site table: in order, disjoint, inside the plan.
    let mut ranges: Vec<(u64, u64)> = vec![];
    let mut tramps: Vec<(u64, u64)> = vec![];
    for s in &plan.sites {
        let end = s.addr.saturating_add(s.len as u64);
        if ranges.last().is_some_and(|&(_, e)| e > s.addr) {
            bad.push(format!(
                "site {:#x}: out of order or overlapping the previous one",
                s.addr
            ));
        }
        ranges.push((s.addr, end));
        if s.kind == KIND_CPUID {
            if let Err(e) = check_cpuid(&f, plan, s) {
                bad.push(format!("site {:#x}: {e}", s.addr));
            }
            continue;
        }
        let (t0, t1) = (s.tramp as u64, s.tramp as u64 + s.tramp_len as u64);
        if t1 > plan.tramp.len() as u64 || s.trap as u64 + 2 > s.tramp_len as u64 {
            bad.push(format!("site {:#x}: trampoline outside the blob", s.addr));
            continue;
        }
        tramps.push((t0, t1));
        if let Err(e) = check_site(&f, plan, s.addr, s.len as usize, s) {
            bad.push(format!("site {:#x}: {e}", s.addr));
        }
    }
    tramps.sort_unstable();
    if tramps.windows(2).any(|w| w[0].1 > w[1].0) {
        bad.push("two trampolines overlap".into());
    }

    // Every changed byte lies in a patched instruction.
    for p in &plan.pages {
        for (k, page) in p.bytes.chunks(PAGE as usize).enumerate() {
            let v = p.vaddr + k as u64 * PAGE;
            let Some(orig) = elf.original_page(v) else {
                bad.push(format!("page {v:#x}: not in an executable segment"));
                continue;
            };
            for (o, (&a, &b)) in orig.iter().zip(page).enumerate() {
                let at = v + o as u64;
                if a != b {
                    let r = ranges.partition_point(|&(s, _)| s <= at);
                    if r == 0 || ranges[r - 1].1 <= at {
                        bad.push(format!(
                            "byte {at:#x}: changed outside every patched instruction"
                        ));
                        break;
                    }
                }
            }
        }
    }
    bad
}

/// A `KIND_CPUID` site: a `cpuid` found as code, now `ud2` in place, with no trampoline.
fn check_cpuid(f: &Finder, plan: &Plan, s: &super::plan::Site) -> Result<(), String> {
    check_place(f, s.addr, s.len as usize)?;
    if f.insn(s.addr).map(|i| i.mnemonic()) != Some(Mnemonic::Cpuid) || s.len != 2 {
        return Err("a cpuid site that is not a cpuid".into());
    }
    if plan_bytes(plan, s.addr, 2) != Some(&[0x0f, 0x0b][..]) {
        return Err("the cpuid is not replaced by ud2".into());
    }
    if s.tramp_len != 0 || s.trap != 0 || s.copy != NO_COPY {
        return Err("a cpuid site with a trampoline".into());
    }
    Ok(())
}

/// The patched instruction at `a`, `n` bytes, is one found as code, and nothing else decodes,
/// branches into, reads or takes an address inside it.
fn check_place(f: &Finder, a: u64, n: usize) -> Result<(), String> {
    let (i, o) = f.at(a).ok_or("not in an executable section")?;
    let seen = &f.seen[i];
    if o + n > seen.t.len {
        return Err("runs past the end of its section".into());
    }
    if seen.flow[o] as usize != n && seen.linear[o] as usize != n {
        return Err(
            "not an instruction start of this length in code found by control flow or an extent"
                .into(),
        );
    }
    if (o + 1..o + n).any(|p| seen.flow[p] != 0 || seen.linear[p] != 0)
        || (o.saturating_sub(14)..o)
            .any(|p| p + seen.flow[p] as usize > o || p + seen.linear[p] as usize > o)
    {
        return Err("another decode overlaps the patched instruction".into());
    }
    if seen.flow[o] != 0 && seen.linear[o] != 0 && seen.flow[o] != seen.linear[o] {
        return Err("control flow and an extent decode it differently".into());
    }
    if (o + 1..o + n).any(|p| seen.mark[p] & 1 != 0) {
        return Err("a known branch lands inside the patched instruction".into());
    }
    if (o..o + n).any(|p| seen.mark[p] & 2 != 0) || (o + 1..o + n).any(|p| seen.mark[p] & 4 != 0) {
        return Err("code reads the patched bytes or takes an address inside them".into());
    }
    Ok(())
}

fn check_site(
    f: &Finder,
    plan: &Plan,
    a: u64,
    n: usize,
    s: &super::plan::Site,
) -> Result<(), String> {
    check_place(f, a, n)?;
    let (i, o) = f.at(a).ok_or("not in an executable section")?;
    let seen = &f.seen[i];
    let orig = f.insn(a).ok_or("undecodable")?;
    let patched = plan_bytes(plan, a, n).ok_or("patched bytes not in the plan's pages")?;
    let pi = decode(patched, a);
    let t = plan.tramp_vaddr + s.tramp as u64;
    let tb = &plan.tramp[s.tramp as usize..s.tramp as usize + s.tramp_len as usize];
    let ti = |off: usize| decode(&tb[off.min(tb.len())..], t + off as u64);
    // T: dec qword [cell]; je S, the count exactly as the runtime expects it (no prefix)
    let dec = ti(0);
    let mut count = vec![0x48, 0xff, 0x0c, 0x25];
    count.extend_from_slice(&(plan.cell as u32).to_le_bytes());
    if tb.get(..8) != Some(&count[..]) || dec.code() != Op::Dec_rm64 {
        return Err("the trampoline does not start by counting in the cell".into());
    }
    let je = ti(dec.len());
    let trap = t + s.trap as u64;
    if je.mnemonic() != Mnemonic::Je || je.near_branch_target() != trap {
        return Err("the count does not branch to the site's trap".into());
    }
    let r = dec.len() + je.len();
    // The row, then S: ud2; jmp R, ending the trampoline.
    let mut row_end = r;
    match s.kind {
        KIND_JUMP => {
            let same = pi.len() == n && pi.code() == orig.code();
            let branch = matches!(
                orig.flow_control(),
                FlowControl::Call
                    | FlowControl::UnconditionalBranch
                    | FlowControl::ConditionalBranch
            );
            if !same
                || !branch
                || orig.op0_kind() != OpKind::NearBranch64
                || pi.near_branch_target() != t
            {
                return Err(
                    "the patch is not the same branch or call aimed at its trampoline".into(),
                );
            }
            if s.copy != NO_COPY {
                return Err("a jump site with a copied instruction".into());
            }
            let j = ti(r);
            if j.mnemonic() != Mnemonic::Jmp || j.near_branch_target() != orig.near_branch_target()
            {
                return Err("the trampoline does not go on to the original target".into());
            }
            row_end += j.len();
        }
        KIND_BEFORE => {
            let pad = matches!(orig.mnemonic(), Mnemonic::Endbr64 | Mnemonic::Endbr32);
            if orig.flow_control() != FlowControl::Next || orig.mnemonic() == Mnemonic::Hlt || pad {
                return Err("the copied instruction is not straight-line".into());
            }
            if pi.code() != Op::Jmp_rel32_64
                || pi.len() != 5
                || pi.near_branch_target() != t
                || patched[5..].iter().any(|&b| b != 0xcc)
            {
                return Err("the patch is not a jump to its trampoline padded with int3".into());
            }
            if s.copy as usize != r {
                return Err("the copy is not where the site table says".into());
            }
            let c = ti(r);
            let ob = f.elf.bytes(&seen.t);
            let (cb, obytes) = (&tb[r..(r + n).min(tb.len())], &ob[o..o + n]);
            let disp = if orig.is_ip_rel_memory_operand() {
                let mut d = Decoder::with_ip(64, obytes, a, DecoderOptions::NONE);
                let x = d.decode();
                let k = d.get_constant_offsets(&x);
                Some(k.displacement_offset()..k.displacement_offset() + k.displacement_size())
            } else {
                None
            };
            let differs = (0..n).any(|k| {
                cb.get(k) != Some(&obytes[k]) && !disp.as_ref().is_some_and(|d| d.contains(&k))
            });
            if c.len() != n || c.code() != orig.code() || differs {
                return Err("the copy differs from the instruction".into());
            }
            if orig.is_ip_rel_memory_operand()
                && c.ip_rel_memory_address() != orig.ip_rel_memory_address()
            {
                return Err("the copy addresses other memory than the instruction".into());
            }
            let j = ti(r + n);
            if j.mnemonic() != Mnemonic::Jmp || j.near_branch_target() != a + n as u64 {
                return Err("the trampoline does not return right after the instruction".into());
            }
            row_end += n + j.len();
        }
        k => return Err(format!("unknown kind {k}")),
    }
    let ud2 = ti(row_end);
    let back = ti(row_end + ud2.len());
    if row_end != s.trap as usize
        || ud2.mnemonic() != Mnemonic::Ud2
        || back.mnemonic() != Mnemonic::Jmp
        || back.near_branch_target() != t + r as u64
    {
        return Err("the trap is not `ud2` then a jump back to the row".into());
    }
    if row_end + ud2.len() + back.len() != tb.len() {
        return Err("the trampoline's length is not its instructions'".into());
    }
    Ok(())
}
