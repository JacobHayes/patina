//! The plan verifier: an independent check of a plan against its file. It shares the ELF fact
//! reader, the plan reader and the instruction decoder with the rewriter, and none of its
//! decisions: it finds code its own way (control flow from the anchors, and each extent decoded
//! linearly from its start until a byte code reads or names, without the rewriter's
//! refusals) and checks that
//!   - the plan is for this file, its cell is the runtime's, and its trampolines lie outside
//!     the image;
//!   - every byte the plan changes lies in a patch, and every patched instruction is one whole
//!     instruction of code found here, that no known branch enters, no code reads, and no other
//!     decode overlaps or disagrees with;
//!   - every patch is a jump, call or same-condition branch to its own trampoline, and every
//!     trampoline counts, traps to its own `hlt`, and goes on to the original target, or runs an
//!     exact copy of each patched instruction (same operand address; a closing direct branch to
//!     the same target) and returns right after them;
//!   - a group (a patch of several instructions): all straight-line but a last direct branch;
//!     at every interior boundary (each instruction start but the first) a byte that faults
//!     whatever follows it, no known branch target and no address taken, and an entry that
//!     resumes at the copy of that instruction; no other entry;
//!   - no site table entry points outside the plan.
//!
//! The rewriter's flag liveness and its taint are not re-checked here (its unit tests cover
//! them); a plan this accepts patches only whole instructions of code, each with a well-formed
//! trampoline.

use super::elf::{Elf, Text};
use super::par::Par;
use super::plan::{
    Entry, Plan, CELL, KIND_BEFORE, KIND_CPUID, KIND_INTERIOR, KIND_JUMP, NO_COPY, PAD_PREFIX,
    PAGE, TRAP_BYTES,
};
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

pub struct Found<'a> {
    elf: &'a Elf<'a>,
    seen: Vec<Seen>,
}

impl Found<'_> {
    fn mark(&mut self, a: u64, m: u8) {
        if let Some((i, o)) = self.at(a) {
            self.seen[i].mark[o] |= m;
        }
    }
}

impl<'a> Found<'a> {
    fn at(&self, a: u64) -> Option<(usize, usize)> {
        let i = self
            .seen
            .partition_point(|s| s.t.addr <= a)
            .checked_sub(1)?;
        let o = a.wrapping_sub(self.seen[i].t.addr) as usize;
        (o < self.seen[i].t.len).then_some((i, o))
    }

    /// `insn` with a decoder per text range kept (`decoders`): making a decoder costs about
    /// as much as one decode.
    fn insn_in(&self, decs: &mut [Decoder], a: u64) -> Option<Instruction> {
        let (i, o) = self.at(a)?;
        let d = &mut decs[i];
        d.set_position(o).ok()?;
        d.set_ip(a);
        let i = d.decode();
        (!i.is_invalid()).then_some(i)
    }

    fn decoders(&self) -> Vec<Decoder<'a>> {
        self.seen
            .iter()
            .map(|s| Decoder::with_ip(64, self.elf.bytes(&s.t), s.t.addr, DecoderOptions::NONE))
            .collect()
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
    fn flow(&mut self, mut work: Vec<u64>, decs: &mut [Decoder]) {
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
                let Some(ins) = self.insn_in(decs, a) else {
                    break;
                };
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
    fn linear(&mut self, decs: &mut [Decoder]) -> Vec<u64> {
        let mut targets = vec![];
        for k in 0..self.elf.extents.len() {
            let (mut a, hi) = self.elf.extents[k];
            while a < hi {
                let Some((i, o)) = self.at(a) else { break };
                let s = &self.seen[i];
                if s.flow[o] == 0 && s.mark[o] & 6 != 0 {
                    break;
                }
                let Some(ins) = self.insn_in(decs, a) else {
                    break;
                };
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

/// The bytes of `len` at `vaddr` as the plan maps them (its page runs are in address order,
/// as `Plan::from_bytes` checks).
fn plan_bytes(plan: &Plan, vaddr: u64, len: usize) -> Option<&[u8]> {
    let k = plan
        .pages
        .partition_point(|p| p.vaddr <= vaddr)
        .checked_sub(1)?;
    let p = &plan.pages[k];
    if vaddr + len as u64 > p.vaddr + p.bytes.len() as u64 {
        return None;
    }
    let o = (vaddr - p.vaddr) as usize;
    Some(&p.bytes[o..o + len])
}

impl<'a> Found<'a> {
    /// The code of `elf` by this verifier's own rules: control flow from the anchors, each
    /// extent linearly, control flow from what those reach. Needs no plan, so it runs while
    /// the plan is made.
    pub fn new(elf: &'a Elf<'a>) -> Found<'a> {
        let mut f = Found {
            elf,
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
        let mut decs = f.decoders();
        f.flow(elf.anchors.clone(), &mut decs);
        let more = f.linear(&mut decs);
        f.flow(more, &mut decs);
        f
    }
}

/// Every way `plan` fails to be a sound plan for `data`; empty when it is one.
#[cfg(test)]
pub fn verify(data: &[u8], plan: &Plan) -> Vec<String> {
    match Elf::parse(data) {
        Ok(elf) => check(&Found::new(&elf), plan, &Par::one()),
        Err(e) => vec![e],
    }
}

/// Every way `plan` fails to be a sound plan for the file whose code `f` found; empty when it
/// is one. Sites and pages are checked in parts on `par`'s threads, the findings in order.
pub fn check(f: &Found, plan: &Plan, par: &Par) -> Vec<String> {
    let mut bad = vec![];
    let elf = f.elf;
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

    if plan
        .pages
        .windows(2)
        .any(|w| w[0].vaddr + w[0].bytes.len() as u64 > w[1].vaddr)
    {
        bad.push("the page runs are not in address order".into());
    }
    // The site table: in order of the trampolines, disjoint, inside the plan; the entries in
    // address order, each a cpuid or an interior boundary some group has.
    let mut ranges: Vec<(u64, u64)> = vec![];
    let mut tramps: Vec<(u64, u64)> = vec![];
    let mut interiors: Vec<(u64, u32)> = vec![];
    if plan.sites.windows(2).any(|w| w[0].tramp > w[1].tramp) {
        bad.push("the site rows are not in order of their trampolines".into());
    }
    let checked = par.parts(plan.sites.len(), |part| {
        plan.sites[part]
            .iter()
            .map(|s| {
                let t1 = s.tramp as u64 + s.tramp_len as u64;
                if t1 > plan.tramp.len() as u64 || s.trap as u64 + 2 > s.tramp_len as u64 {
                    return Err(None);
                }
                check_site(f, plan, s.addr, s.len as usize, s).map_err(Some)
            })
            .collect::<Vec<_>>()
    });
    for (s, c) in plan.sites.iter().zip(checked.into_iter().flatten()) {
        ranges.push((s.addr, s.addr.saturating_add(s.len as u64)));
        let (t0, t1) = (s.tramp as u64, s.tramp as u64 + s.tramp_len as u64);
        match c {
            Err(None) => {
                bad.push(format!("site {:#x}: trampoline outside the span", s.addr));
                continue;
            }
            Ok(inner) => interiors.extend(inner),
            Err(Some(e)) => bad.push(format!("site {:#x}: {e}", s.addr)),
        }
        tramps.push((t0, t1));
    }
    if plan.entries.windows(2).any(|w| w[0].addr >= w[1].addr) {
        bad.push("the entries are not in address order".into());
    }
    interiors.sort_unstable();
    let mut listed = vec![];
    for n in &plan.entries {
        match n.kind {
            KIND_CPUID => {
                ranges.push((n.addr, n.addr.saturating_add(2)));
                if let Err(e) = check_cpuid(f, plan, n) {
                    bad.push(format!("entry {:#x}: {e}", n.addr));
                }
            }
            KIND_INTERIOR => listed.push((n.addr, n.to)),
            k => bad.push(format!("entry {:#x}: unknown kind {k}", n.addr)),
        }
    }
    if listed != interiors {
        bad.push(
            "the interior entries are not exactly the groups' interior boundaries and copies"
                .into(),
        );
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|w| w[0].1 > w[1].0) {
        bad.push("two patches overlap".into());
    }
    tramps.sort_unstable();
    if tramps.windows(2).any(|w| w[0].1 > w[1].0) {
        bad.push("two trampolines overlap".into());
    }

    // Every changed byte lies in a patched instruction.
    let pages: Vec<(u64, &[u8])> = plan
        .pages
        .iter()
        .flat_map(|p| {
            p.bytes
                .chunks(PAGE as usize)
                .enumerate()
                .map(|(k, page)| (p.vaddr + k as u64 * PAGE, page))
        })
        .collect();
    let paged = par.parts(pages.len(), |part| {
        let mut bad = vec![];
        for &(v, page) in &pages[part] {
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
        bad
    });
    bad.extend(paged.into_iter().flatten());
    bad
}

/// A `KIND_CPUID` entry: a `cpuid` found as code, now `ud2` in place.
fn check_cpuid(f: &Found, plan: &Plan, n: &Entry) -> Result<(), String> {
    check_place(f, n.addr, 2)?;
    if f.insn(n.addr).map(|i| i.mnemonic()) != Some(Mnemonic::Cpuid) {
        return Err("a cpuid entry that is not a cpuid".into());
    }
    if plan_bytes(plan, n.addr, 2) != Some(&[0x0f, 0x0b][..]) {
        return Err("the cpuid is not replaced by ud2".into());
    }
    if n.to != 0 {
        return Err("a cpuid entry with a trampoline".into());
    }
    Ok(())
}

/// Instructions that fault in 64-bit user mode before they do anything.
fn faults(i: &Instruction) -> bool {
    use Mnemonic::*;
    matches!(
        i.mnemonic(),
        Int3 | Hlt | Cli | Sti | In | Out | Insb | Insw | Insd | Outsb | Outsw | Outsd
    )
}

/// May `i` run as a copy in a trampoline: straight-line, not a landing pad marker or `hlt`,
/// and none of the instructions the runtime answers or patches in place.
fn straight(i: &Instruction) -> bool {
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

/// The patched instruction at `a`, `n` bytes, is one found as code, and nothing else decodes,
/// branches into, reads or takes an address inside it.
fn check_place(f: &Found, a: u64, n: usize) -> Result<(), String> {
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

/// A site's patch and trampoline; for a group, its interior entries as they must be listed
/// (address, trampoline offset of the copy).
fn check_site(
    f: &Found,
    plan: &Plan,
    a: u64,
    n: usize,
    s: &super::plan::Site,
) -> Result<Vec<(u64, u32)>, String> {
    let (i, o) = f.at(a).ok_or("not in an executable section")?;
    let seen = &f.seen[i];
    let ob = f.elf.bytes(&seen.t);
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
    let mut inner = vec![];
    // The row, then S: ud2; jmp R, ending the trampoline.
    let mut row_end = r;
    match s.kind {
        KIND_JUMP => {
            check_place(f, a, n)?;
            let orig = f.insn(a).ok_or("undecodable")?;
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
            // The patched instructions, decoded here: each found as code and not entered,
            // together exactly the patch.
            let mut ins = vec![];
            let mut k = 0;
            while k < n {
                let x = a + k as u64;
                let i = f.insn(x).ok_or("undecodable")?;
                check_place(f, x, i.len())?;
                ins.push((k, i));
                k += i.len();
            }
            if k != n {
                return Err("the patch does not end at an instruction boundary".into());
            }
            let last = ins.len() - 1;
            for (j, &(k, ref i)) in ins.iter().enumerate() {
                let raw = &ob[o + k..o + k + i.len()];
                let plain = matches!(
                    raw,
                    [0x70..=0x7f | 0xeb, _] | [0x0f, 0x80..=0x8f, _, _, _, _] | [0xe9, _, _, _, _]
                );
                if !(straight(i) || (j == last && plain)) {
                    return Err("a copied instruction is not straight-line".into());
                }
            }
            // The patch: `2e` prefixes, a jump to the trampoline, `int3` filler.
            let p = patched.iter().take_while(|&&b| b == PAD_PREFIX).count();
            if pi.code() != Op::Jmp_rel32_64
                || pi.len() != p + 5
                || pi.near_branch_target() != t
                || patched[p + 5..].iter().any(|&b| b != 0xcc)
            {
                return Err("the patch is not a jump to its trampoline padded with int3".into());
            }
            if s.copy as usize != r {
                return Err("the copy is not where the site table says".into());
            }
            // Each interior boundary: a byte that faults, no known entry, an entry row.
            for &(k, _) in &ins[1..] {
                let at = decode(&patched[k..], a + k as u64);
                if !TRAP_BYTES.contains(&patched[k]) || !faults(&at) {
                    return Err(format!(
                        "interior boundary {:#x} holds {:#04x}, which does not fault",
                        a + k as u64,
                        patched[k]
                    ));
                }
                if seen.mark[o + k] & 5 != 0 {
                    return Err(format!(
                        "a known branch or address names interior boundary {:#x}",
                        a + k as u64
                    ));
                }
                inner.push((a + k as u64, s.tramp + (r + k) as u32));
            }
            // The copies, each at its offset in the patch; a closing branch in its rel32 form.
            let mut end = r;
            for &(k, ref orig) in &ins {
                let at = r + k;
                let c = ti(at);
                let obytes = &ob[o + k..o + k + orig.len()];
                if orig.flow_control() != FlowControl::Next {
                    let cb = &tb[at..(at + 2).min(tb.len())];
                    let form = matches!(cb, [0xe9, _] | [0x0f, 0x80..=0x8f]);
                    if !form
                        || c.mnemonic() != orig.mnemonic()
                        || c.condition_code() != orig.condition_code()
                        || c.op0_kind() != OpKind::NearBranch64
                        || c.near_branch_target() != orig.near_branch_target()
                    {
                        return Err("the copied branch differs from the instruction".into());
                    }
                    end = at + c.len();
                    continue;
                }
                let cb = &tb[at..(at + orig.len()).min(tb.len())];
                let disp = if orig.is_ip_rel_memory_operand() {
                    let mut d = Decoder::with_ip(64, obytes, a + k as u64, DecoderOptions::NONE);
                    let x = d.decode();
                    let ko = d.get_constant_offsets(&x);
                    Some(
                        ko.displacement_offset()..ko.displacement_offset() + ko.displacement_size(),
                    )
                } else {
                    None
                };
                let differs = (0..orig.len()).any(|q| {
                    cb.get(q) != Some(&obytes[q]) && !disp.as_ref().is_some_and(|d| d.contains(&q))
                });
                if c.len() != orig.len() || c.code() != orig.code() || differs {
                    return Err("the copy differs from the instruction".into());
                }
                if orig.is_ip_rel_memory_operand()
                    && c.ip_rel_memory_address() != orig.ip_rel_memory_address()
                {
                    return Err("the copy addresses other memory than the instruction".into());
                }
                end = at + c.len();
            }
            let j = ti(end);
            if j.mnemonic() != Mnemonic::Jmp || j.near_branch_target() != a + n as u64 {
                return Err("the trampoline does not return right after the patch".into());
            }
            row_end = end + j.len();
        }
        k => return Err(format!("unknown kind {k}")),
    }
    let hlt = ti(row_end);
    let back = ti(row_end + hlt.len());
    if row_end != s.trap as usize
        || hlt.mnemonic() != Mnemonic::Hlt
        || back.mnemonic() != Mnemonic::Jmp
        || back.near_branch_target() != t + r as u64
    {
        return Err("the trap is not `hlt` then a jump back to the row".into());
    }
    if row_end + hlt.len() + back.len() != tb.len() {
        return Err("the trampoline's length is not its instructions'".into());
    }
    Ok(inner)
}
