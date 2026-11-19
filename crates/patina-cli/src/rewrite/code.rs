//! What is code: the rewriter's eligibility analysis (DESIGN 2.2). Bytes are *proven* code when
//! control flow reaches them from a known function start, *extent* code when they lie inside a
//! function's unwind or symbol extent that proven code did not cover and decode linearly, and
//! *dark* otherwise. A refusal (an undecodable or privileged instruction, two decodes that
//! overlap, an extent whose branches miss, code that reads instruction bytes) taints the span
//! between the neighbouring function starts. Only untainted proven or extent code is eligible
//! for a patch; dark code is counted, never patched.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

/// Per-byte state: 0 not decoded, 1..=15 the start of an instruction of that length, else the
/// interior of one.
const INTERIOR: u8 = 0xff;

/// Per-byte flags.
pub const READ: u8 = 1; // a memory operand of decoded code reads here
pub const ADDR: u8 = 2; // a `lea` or (non-PIE) an immediate takes this address
pub const TARGET: u8 = 4; // a direct branch or call lands here, or an anchor
pub const FUNC: u8 = 8; // an anchor or a direct call target: a function start
pub const TAINT: u8 = 16; // never patched
pub const EXTENT: u8 = 32; // decoded by the extent rule (else proven)

pub struct Region<'a> {
    pub addr: u64,
    pub bytes: &'a [u8],
    st: Vec<u8>,
    fl: Vec<u8>,
}

pub struct Code<'a> {
    pub regions: Vec<Region<'a>>,
    /// Why spans were tainted, by reason.
    pub refusals: Refusals,
    /// Code at its link-time address (not PIE): absolute operands can name its bytes too.
    absolute: bool,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Refusals {
    pub conflict: u64,
    pub invalid: u64,
    pub extent: u64,
    pub read: u64,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Census {
    pub text: u64,
    pub proven: u64,
    pub extent: u64,
    pub padding: u64,
    pub dark: u64,
    pub tainted: u64,
    pub instructions: u64,
}

/// An instruction that compiled code does not contain, so that decoding it means the bytes are
/// not code: privileged (control and debug registers, VMX) and port I/O instructions, far transfers, `int n`
/// (but `int 3` in its two-byte form, which Go's assembler emits for a breakpoint), and segment
/// overrides that 64-bit code has no use for.
fn refused(i: &Instruction) -> bool {
    use Mnemonic::*;
    if i.mnemonic() == Int && i.immediate8() == 3 {
        return false;
    }
    i.is_invalid()
        || matches!(
            i.mnemonic(),
            In | Out
                | Insb
                | Insw
                | Insd
                | Outsb
                | Outsw
                | Outsd
                | Cli
                | Sti
                | Iret
                | Iretd
                | Iretq
                | Retf
                | Lgdt
                | Lidt
                | Lldt
                | Ltr
                | Clts
                | Invd
                | Wbinvd
                | Invlpg
                | Rdmsr
                | Wrmsr
                | Sysret
                | Sysexit
                | Swapgs
                | Int1
                | Into
                | Int
                | Invpcid
                | Xsetbv
                | Rsm
                | Vmcall
                | Vmlaunch
                | Vmresume
                | Vmxoff
                | Vmxon
                | Vmread
                | Vmwrite
                | Vmptrld
                | Vmptrst
                | Vmclear
                | Invept
                | Invvpid
        )
        || (0..i.op_count()).any(|k| {
            i.op_kind(k) == OpKind::Register
                && (i.op_register(k).is_cr() || i.op_register(k).is_dr())
        })
        || i.is_call_far()
        || i.is_jmp_far()
        || i.is_call_far_indirect()
        || i.is_jmp_far_indirect()
        || matches!(i.segment_prefix(), Register::ES | Register::SS)
        || (i.segment_prefix() == Register::DS
            && !matches!(
                i.flow_control(),
                FlowControl::IndirectBranch
                    | FlowControl::IndirectCall
                    | FlowControl::ConditionalBranch
            ))
}

/// The direct target of a branch, call or `xbegin`.
pub fn direct_target(i: &Instruction) -> Option<u64> {
    (i.op0_kind() == OpKind::NearBranch64).then(|| i.near_branch_target())
}

/// Does decoding stop after `i` (no fall-through)?
fn ends_flow(i: &Instruction) -> bool {
    matches!(
        i.flow_control(),
        FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Return
            | FlowControl::Interrupt
            | FlowControl::Exception
    ) || i.mnemonic() == Mnemonic::Hlt
}

pub fn decode_at(bytes: &[u8], base: u64, pos: usize) -> Instruction {
    let mut d = Decoder::with_ip(64, &bytes[pos..], base + pos as u64, DecoderOptions::NONE);
    d.decode()
}

impl<'a> Code<'a> {
    /// The analysis over `text` (address, bytes; sorted, disjoint) from function starts
    /// `anchors` and function extents `extents`.
    pub fn analyze(
        text: &[(u64, &'a [u8])],
        anchors: &[u64],
        extents: &[(u64, u64)],
        absolute: bool,
    ) -> Code<'a> {
        let regions = text
            .iter()
            .map(|&(addr, bytes)| Region {
                addr,
                bytes,
                st: vec![0; bytes.len()],
                fl: vec![0; bytes.len()],
            })
            .collect();
        let mut c = Code {
            regions,
            refusals: Refusals::default(),
            absolute,
        };
        let mut bad = vec![];
        for &a in anchors {
            c.set(a, TARGET | FUNC);
        }
        // Proven code, then extent code and what its branches reach, until nothing is new.
        let mut work: Vec<u64> = anchors.iter().rev().copied().collect();
        loop {
            c.descend(&mut work, &mut bad);
            c.fill(extents, &mut work, &mut bad);
            if work.is_empty() {
                break;
            }
        }
        c.check_extent_branches(&mut bad);
        c.check_reads(&mut bad);
        c.taint(&bad);
        c
    }

    fn find(&self, a: u64) -> Option<(usize, usize)> {
        let i = self
            .regions
            .partition_point(|r| r.addr <= a)
            .checked_sub(1)?;
        let r = &self.regions[i];
        let o = a.wrapping_sub(r.addr) as usize;
        (o < r.bytes.len()).then_some((i, o))
    }

    fn set(&mut self, a: u64, f: u8) {
        if let Some((i, o)) = self.find(a) {
            self.regions[i].fl[o] |= f;
        }
    }

    pub fn flags(&self, a: u64) -> u8 {
        self.find(a).map_or(0, |(i, o)| self.regions[i].fl[o])
    }

    /// The length of the decoded instruction starting at `a`.
    pub fn len_at(&self, a: u64) -> Option<usize> {
        let (i, o) = self.find(a)?;
        let s = self.regions[i].st[o];
        (1..=15).contains(&s).then_some(s as usize)
    }

    /// The decoded instruction at `a`, an instruction start.
    pub fn insn(&self, a: u64) -> Option<Instruction> {
        self.len_at(a)?;
        let (i, o) = self.find(a)?;
        let r = &self.regions[i];
        Some(decode_at(r.bytes, r.addr, o))
    }

    /// The original bytes of `len` bytes at `a`.
    pub fn bytes(&self, a: u64, len: usize) -> Option<&'a [u8]> {
        let (i, o) = self.find(a)?;
        self.regions[i].bytes.get(o..o + len)
    }

    /// The start of the decoded instruction that ends exactly at `a`.
    pub fn prev(&self, a: u64) -> Option<u64> {
        let (i, o) = self.find(a.checked_sub(1)?)?;
        let st = &self.regions[i].st;
        let mut s = o;
        while st[s] == INTERIOR {
            s = s.checked_sub(1)?;
        }
        let l = st[s] as usize;
        ((1..=15).contains(&l) && s + l == o + 1).then(|| self.regions[i].addr + s as u64)
    }

    /// Every decoded instruction start, in address order.
    pub fn starts(&self) -> impl Iterator<Item = u64> + '_ {
        self.regions.iter().flat_map(|r| {
            let mut o = 0;
            std::iter::from_fn(move || {
                while o < r.st.len() {
                    let s = r.st[o];
                    if (1..=15).contains(&s) {
                        let a = r.addr + o as u64;
                        o += s as usize;
                        return Some(a);
                    }
                    o += 1;
                }
                None
            })
        })
    }

    /// The start of the instruction whose interior holds byte `o` of region `i`.
    fn covering(&self, i: usize, mut o: usize) -> u64 {
        let st = &self.regions[i].st;
        while o > 0 && st[o] == INTERIOR {
            o -= 1;
        }
        self.regions[i].addr + o as u64
    }

    /// Mark one decoded instruction; record what it reads, takes the address of, or reaches.
    fn mark(&mut self, i: usize, o: usize, ins: &Instruction, extent: bool, work: &mut Vec<u64>) {
        let r = &mut self.regions[i];
        r.st[o] = ins.len() as u8;
        r.st[o + 1..o + ins.len()].fill(INTERIOR);
        if extent {
            r.fl[o] |= EXTENT;
        }
        if ins.is_ip_rel_memory_operand() {
            let f = if ins.mnemonic() == Mnemonic::Lea {
                ADDR
            } else {
                READ
            };
            self.set(ins.ip_rel_memory_address(), f);
        }
        if self.absolute {
            self.mark_absolute(ins);
        }
        if let Some(t) = direct_target(ins) {
            let call = ins.flow_control() == FlowControl::Call;
            if let Some((ti, to)) = self.find(t) {
                self.regions[ti].fl[to] |= TARGET | if call { FUNC } else { 0 };
                // Not yet decoded, or inside an instruction (a conflict, found by `descend`).
                if !(1..=15).contains(&self.regions[ti].st[to]) {
                    work.push(t);
                }
            }
        }
    }

    /// Not PIE: an absolute memory operand (`[disp32]`, `tbl(,%rax,8)`) reads at its
    /// displacement, and an immediate may be an address taken.
    fn mark_absolute(&mut self, ins: &Instruction) {
        let lea = ins.mnemonic() == Mnemonic::Lea;
        for k in 0..ins.op_count() {
            match ins.op_kind(k) {
                OpKind::Memory
                    if ins.memory_base() == Register::None
                        && !matches!(ins.segment_prefix(), Register::FS | Register::GS) =>
                {
                    self.set(ins.memory_displacement64(), if lea { ADDR } else { READ })
                }
                OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64 => {
                    self.set(ins.immediate(k), ADDR)
                }
                _ => {}
            }
        }
    }

    /// Follow control flow from every address in `work`.
    fn descend(&mut self, work: &mut Vec<u64>, bad: &mut Vec<u64>) {
        while let Some(a) = work.pop() {
            let Some((i, mut o)) = self.find(a) else {
                continue;
            };
            loop {
                let r = &self.regions[i];
                if o >= r.bytes.len() || (1..=15).contains(&r.st[o]) {
                    break;
                }
                let ip = r.addr + o as u64;
                if r.st[o] == INTERIOR {
                    self.refusals.conflict += 1;
                    bad.extend([ip, self.covering(i, o)]);
                    break;
                }
                let ins = decode_at(r.bytes, r.addr, o);
                let n = ins.len();
                if refused(&ins) || o + n > r.bytes.len() {
                    self.refusals.invalid += 1;
                    bad.push(ip);
                    break;
                }
                if let Some(k) = r.st[o + 1..o + n].iter().position(|&s| s != 0) {
                    self.refusals.conflict += 1;
                    bad.extend([ip, r.addr + (o + 1 + k) as u64]);
                    break;
                }
                self.mark(i, o, &ins, false, work);
                if ends_flow(&ins) {
                    break;
                }
                o += n;
            }
        }
    }

    /// Extent code: inside each extent, decode linearly what proven code left. A read or
    /// address-taken byte ends the extent's decode (it is data); a refusal drops what this
    /// extent decoded and taints it. Branch targets found go to `work`.
    fn fill(&mut self, extents: &[(u64, u64)], work: &mut Vec<u64>, bad: &mut Vec<u64>) {
        for &(lo, hi) in extents {
            let Some((i, mut o)) = self.find(lo) else {
                continue;
            };
            let r = &self.regions[i];
            let end = (hi.min(r.addr + r.bytes.len() as u64) - r.addr) as usize;
            let mut new: Vec<(usize, Instruction)> = vec![];
            let mut ok = true;
            while o < end {
                let s = r.st[o];
                if (1..=15).contains(&s) {
                    o += s as usize;
                    continue;
                }
                if s == INTERIOR {
                    ok = false;
                    break;
                }
                if r.fl[o] & (READ | ADDR) != 0 {
                    break;
                }
                let ins = decode_at(r.bytes, r.addr, o);
                let n = ins.len();
                if refused(&ins)
                    || o + n > end
                    || r.st[o + 1..o + n].iter().any(|&s| s != 0)
                    || r.fl[o + 1..o + n]
                        .iter()
                        .any(|&f| f & (READ | ADDR | TARGET) != 0)
                {
                    ok = false;
                    break;
                }
                new.push((o, ins));
                o += n;
            }
            if !ok {
                self.refusals.extent += 1;
                bad.extend([lo, r.addr + o as u64]);
                continue;
            }
            for (o, ins) in new {
                self.mark(i, o, &ins, true, work);
            }
        }
    }

    /// Every direct branch of extent code lands on a decoded instruction.
    fn check_extent_branches(&mut self, bad: &mut Vec<u64>) {
        let starts: Vec<u64> = self.starts().collect();
        for a in starts {
            if self.flags(a) & EXTENT == 0 {
                continue;
            }
            let t = self.insn(a).as_ref().and_then(direct_target);
            if let Some(t) = t.filter(|&t| self.find(t).is_some() && self.len_at(t).is_none()) {
                self.refusals.extent += 1;
                bad.extend([a, t]);
            }
        }
    }

    /// Bytes that decoded code reads cannot also be instructions, and an address taken
    /// (`lea`) is not inside one.
    fn check_reads(&mut self, bad: &mut Vec<u64>) {
        for i in 0..self.regions.len() {
            let r = &self.regions[i];
            for o in 0..r.bytes.len() {
                let read = r.fl[o] & READ != 0 && r.st[o] != 0;
                if read || r.fl[o] & ADDR != 0 && r.st[o] == INTERIOR {
                    self.refusals.read += 1;
                    bad.push(self.covering(i, o));
                }
            }
        }
    }

    /// Taint the span between the function starts around each refusal.
    fn taint(&mut self, bad: &[u64]) {
        let mut funcs = vec![];
        for r in &self.regions {
            for (o, &f) in r.fl.iter().enumerate() {
                if f & FUNC != 0 {
                    funcs.push(r.addr + o as u64);
                }
            }
        }
        for &a in bad {
            let Some((i, _)) = self.find(a) else { continue };
            let r = &mut self.regions[i];
            let k = funcs.partition_point(|&f| f <= a);
            let lo = k.checked_sub(1).map_or(r.addr, |k| funcs[k]).max(r.addr);
            let hi = funcs
                .get(k)
                .copied()
                .unwrap_or(u64::MAX)
                .min(r.addr + r.bytes.len() as u64);
            for f in &mut r.fl[(lo - r.addr) as usize..(hi - r.addr) as usize] {
                *f |= TAINT;
            }
        }
    }

    /// Bytes by kind: proven, extent, padding (undecoded `int3`, `nop` forms or zero), dark.
    pub fn census(&self) -> Census {
        let mut c = Census::default();
        for r in &self.regions {
            c.text += r.bytes.len() as u64;
            c.tainted += r.fl.iter().filter(|&&f| f & TAINT != 0).count() as u64;
            let mut o = 0;
            while o < r.bytes.len() {
                let s = r.st[o];
                if (1..=15).contains(&s) {
                    c.instructions += 1;
                    if r.fl[o] & EXTENT != 0 {
                        c.extent += s as u64;
                    } else {
                        c.proven += s as u64;
                    }
                    o += s as usize;
                    continue;
                }
                let ins = decode_at(r.bytes, r.addr, o);
                let n = if matches!(r.bytes[o], 0xcc | 0x00) {
                    1
                } else if !ins.is_invalid() && ins.mnemonic() == Mnemonic::Nop {
                    ins.len().min(r.bytes.len() - o)
                } else {
                    0
                };
                if n > 0 {
                    c.padding += n as u64;
                    o += n;
                } else {
                    c.dark += 1;
                    o += 1;
                }
            }
        }
        c
    }
}
