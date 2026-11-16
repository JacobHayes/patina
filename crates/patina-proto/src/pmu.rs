//! Counter preemption: what the runtime and the launcher agree on, the slice draw, and
//! the control-transfer classifier the runtime's hops use. Design: `crates/patina-cli/ENGINE.md`, "Counter preemption".
//!
//! Kept here (not in `rt`) so that `cargo test -p proto` checks the classifier and the
//! branch-condition evaluator against hand-assembled cases.

use crate::ctl::Config;
use crate::draw::{draw, Stream};
use crate::insn::decode;

/// `perf_event_attr::sig_data` of every counter: tells the runtime's SIGTRAP handler that a
/// `TRAP_PERF` came from its own counter.
pub const SIG_DATA: u64 = 0x5350_4b5f_504d_5531; // "1UMP_KPS"
/// Hardware overflow period between segment decisions (branches). Low enough interrupt rate
/// that the kernel never throttles the event (throttling stops counting).
pub const PERIOD: u64 = 1 << 20;
/// Default branches before N at which the alarm is aimed (larger than any skid measured).
pub const MARGIN_DEFAULT: u64 = 1024;
/// Slices up to `margin + HOP_EXTRA` are reached by hops from the segment start.
pub const HOP_EXTRA: u64 = 1024;
/// Smallest period the runtime programs (avoids interrupt storms).
pub const MIN_REARM: u64 = 64;
/// Defaults of the policy (`crates/patina-cli/ENGINE.md`, "Counter preemption").
pub const SLICE_MIN_DEFAULT: u64 = PERIOD + 2 * MARGIN_DEFAULT;
pub const SLICE_MAX_DEFAULT: u64 = 1 << 22;
pub const SHORT_PERMILLE_DEFAULT: u64 = 20;
pub const SHORT_MAX_DEFAULT: u64 = 256;
pub const CHARGE_PS_DEFAULT: u64 = 1000;

/// AMD `ex_ret_cond`: retired conditional branches (raw event 0xd1).
pub const EVENT_AMD: u64 = 0xd1;
/// Intel `BR_INST_RETIRED.CONDITIONAL` (event 0xc4, umask 0x01). Untested.
pub const EVENT_INTEL: u64 = 0x01c4;

/// How a segment reaches its stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Walk from the segment start (small N).
    Hop,
    /// Program the period to N - margin at the start (one ioctl), then hop.
    Mid,
    /// The free-running period; reprogram when within reach.
    Long,
}

/// Slice length N (>= 1) of the segment keyed by `key`.
pub fn slice(cfg: &Config, key: u64) -> u64 {
    let d = draw(cfg.seed, Stream::Slice, key);
    let short_permille = cfg.pmu_short & 0xffff;
    let short_max = (cfg.pmu_short >> 16).max(1);
    if d % 1000 < short_permille {
        // Short: log-uniform in [1, short_max] (small N, right after a trap, is where
        // check-then-act windows sit).
        return log_uniform(d >> 10, 1, short_max);
    }
    log_uniform(d >> 10, cfg.pmu_slice_min.max(1), cfg.pmu_slice_max)
}

/// Piecewise log-uniform in [lo, hi]: an octave uniformly, then uniform within it.
fn log_uniform(d: u64, lo: u64, hi: u64) -> u64 {
    let hi = hi.max(lo);
    let mut octaves = 0u64;
    while octaves < 63 && (lo << (octaves + 1)) <= hi {
        octaves += 1;
    }
    let o = d % (octaves + 1);
    let base = lo << o;
    let n = base + (d >> 8) % base;
    n.min(hi)
}

pub fn mode(cfg: &Config, n: u64) -> Mode {
    let m = cfg.pmu_margin;
    if n <= m + HOP_EXTRA {
        Mode::Hop
    } else if n < PERIOD + 2 * m {
        Mode::Mid
    } else {
        Mode::Long
    }
}

/// Kind of a conditional branch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cond {
    /// `Jcc` with its condition code (low nibble of the opcode).
    Jcc(u8),
    Loop,
    Loope,
    Loopne,
    Jrcxz,
}

/// A register or memory operand of an indirect `jmp`/`call` (register numbers 0..15 in
/// x86 encoding order: rax rcx rdx rbx rsp rbp rsi rdi r8..r15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    Reg(u8),
    Mem {
        base: Option<u8>,
        index: Option<u8>,
        scale: u8,
        disp: i64,
        rip_rel: bool,
    },
}

/// What the instruction at an address does to control flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cti {
    /// Falls through.
    Plain,
    /// Conditional branch to `target` (absolute).
    Branch(Cond, u64),
    /// Direct `jmp` / `call` (absolute target).
    Jmp(u64),
    Call(u64),
    /// Near `ret` with the extra bytes popped.
    Ret(u16),
    /// Near indirect `jmp` / `call`.
    IndJmp(Operand),
    IndCall(Operand),
    /// Leaves control in a way the runtime does not emulate: run it under a single step.
    Step,
    /// The same, for a conditional branch (counted when the step completes).
    StepCond,
    /// Enters the kernel (and so the runtime): `syscall`, `int*`, `ud2`, `hlt`, `sysenter`.
    Enters,
}

/// x86 register number -> index into the kernel `ucontext` general registers
/// (r8 r9 r10 r11 r12 r13 r14 r15 rdi rsi rbp rbx rdx rax rcx rsp).
pub const GREG_OF: [usize; 16] = [13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7];

/// Classify the instruction at the start of `code`, which sits at address `ip`.
/// Returns its length and kind; `None` if it does not decode.
pub fn classify(code: &[u8], ip: u64) -> Option<(usize, Cti)> {
    let ins = decode(code)?;
    let len = ins.len;
    let next = ip.wrapping_add(len as u64);
    let pre = &code[..ins.op];
    let addr32 = pre.contains(&0x67);
    let seg = pre.iter().any(|&b| b == 0x64 || b == 0x65);
    let rel8 = |at: usize| next.wrapping_add(code[at] as i8 as i64 as u64);
    let rel32 = |at: usize| {
        next.wrapping_add(
            i32::from_le_bytes([code[at], code[at + 1], code[at + 2], code[at + 3]]) as i64 as u64,
        )
    };
    let op = code[ins.op];
    let o = ins.op;
    let cti = match op {
        // 66-prefixed near branches truncate rip to 16 bits on some CPUs: leave them to the CPU.
        0x70..=0x7f | 0xe0..=0xe3 if ins.p66 => Cti::StepCond,
        0xeb | 0xe8 | 0xe9 | 0xc2 | 0xc3 if ins.p66 => Cti::Step,
        0x70..=0x7f => Cti::Branch(Cond::Jcc(op & 0xf), rel8(o + 1)),
        0xe0..=0xe3 if addr32 => Cti::StepCond, // ecx-sized counts: not emulated
        0xe0 => Cti::Branch(Cond::Loopne, rel8(o + 1)),
        0xe1 => Cti::Branch(Cond::Loope, rel8(o + 1)),
        0xe2 => Cti::Branch(Cond::Loop, rel8(o + 1)),
        0xe3 => Cti::Branch(Cond::Jrcxz, rel8(o + 1)),
        0xeb => Cti::Jmp(rel8(o + 1)),
        0xe9 => Cti::Jmp(rel32(o + 1)),
        0xe8 => Cti::Call(rel32(o + 1)),
        0xc3 => Cti::Ret(0),
        0xc2 => Cti::Ret(u16::from_le_bytes([code[o + 1], code[o + 2]])),
        0xca | 0xcb | 0xcf => Cti::Step, // far ret, iret
        0xcc | 0xcd | 0xce | 0xf1 | 0xf4 => Cti::Enters,
        0xff => {
            let m = code[o + 1];
            match (m >> 3) & 7 {
                2 | 4 => {
                    if seg || addr32 || ins.p66 {
                        Cti::Step
                    } else {
                        let opnd = operand(code, o + 1, ins.rex)?;
                        if (m >> 3) & 7 == 2 {
                            Cti::IndCall(opnd)
                        } else {
                            Cti::IndJmp(opnd)
                        }
                    }
                }
                3 | 5 => Cti::Step, // far indirect
                _ => Cti::Plain,
            }
        }
        0x0f => match code[o + 1] {
            0x80..=0x8f if ins.p66 => Cti::StepCond,
            0x80..=0x8f => Cti::Branch(Cond::Jcc(code[o + 1] & 0xf), rel32(o + 2)),
            0x05 | 0x34 | 0x0b | 0x07 | 0x35 => Cti::Enters, // syscall, sysenter, ud2, sysret, sysexit
            0xb9 | 0xff => Cti::Enters,                      // ud1, ud0
            _ => Cti::Plain,
        },
        // xbegin: its abort path is a transfer (no RTM on AMD: #UD, which enters the runtime).
        0xc7 if code.get(o + 1) == Some(&0xf8) => Cti::Step,
        _ => Cti::Plain,
    };
    Some((len, cti))
}

/// The ModRM operand at `code[at]` (64-bit addressing).
fn operand(code: &[u8], at: usize, rex: u8) -> Option<Operand> {
    let m = *code.get(at)?;
    let (md, rm) = (m >> 6, m & 7);
    let rexb = (rex & 1) << 3;
    let rexx = (rex & 2) << 2;
    if md == 3 {
        return Some(Operand::Reg(rm | rexb));
    }
    let mut i = at + 1;
    let (mut base, mut index, mut scale) = (None, None, 0u8);
    let mut rip_rel = false;
    if rm == 4 {
        let sib = *code.get(i)?;
        i += 1;
        scale = sib >> 6;
        let idx = ((sib >> 3) & 7) | rexx;
        if idx != 4 {
            index = Some(idx);
        }
        let b = sib & 7;
        if !(md == 0 && b == 5) {
            base = Some(b | rexb);
        }
    } else if md == 0 && rm == 5 {
        rip_rel = true;
    } else {
        base = Some(rm | rexb);
    }
    let disp = match md {
        0 if rip_rel || (rm == 4 && base.is_none()) => {
            let d = i32::from_le_bytes([
                *code.get(i)?,
                *code.get(i + 1)?,
                *code.get(i + 2)?,
                *code.get(i + 3)?,
            ]);
            d as i64
        }
        1 => *code.get(i)? as i8 as i64,
        2 => i32::from_le_bytes([
            *code.get(i)?,
            *code.get(i + 1)?,
            *code.get(i + 2)?,
            *code.get(i + 3)?,
        ]) as i64,
        _ => 0,
    };
    Some(Operand::Mem {
        base,
        index,
        scale,
        disp,
        rip_rel,
    })
}

const CF: u64 = 1 << 0;
const PF: u64 = 1 << 2;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const OF: u64 = 1 << 11;

/// Is `Jcc` with condition code `cc` taken under `eflags`?
pub fn jcc_taken(cc: u8, eflags: u64) -> bool {
    let f = |b: u64| eflags & b != 0;
    let r = match cc >> 1 {
        0 => f(OF),
        1 => f(CF),
        2 => f(ZF),
        3 => f(CF) || f(ZF),
        4 => f(SF),
        5 => f(PF),
        6 => f(SF) != f(OF),
        _ => f(ZF) || (f(SF) != f(OF)),
    };
    r != (cc & 1 != 0)
}

/// Evaluate a conditional branch: returns (taken, new rcx).
pub fn eval(c: Cond, eflags: u64, rcx: u64) -> (bool, u64) {
    match c {
        Cond::Jcc(cc) => (jcc_taken(cc, eflags), rcx),
        Cond::Jrcxz => (rcx == 0, rcx),
        Cond::Loop | Cond::Loope | Cond::Loopne => {
            let n = rcx.wrapping_sub(1);
            let z = eflags & ZF != 0;
            let t = n != 0
                && match c {
                    Cond::Loope => z,
                    Cond::Loopne => !z,
                    _ => true,
                };
            (t, n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_branches() {
        // jne -3 (75 fd) at 0x1000: target 0x1002 - 3
        assert_eq!(
            classify(&[0x75, 0xfd], 0x1000),
            Some((2, Cti::Branch(Cond::Jcc(5), 0xfff)))
        );
        // jg rel32 +0x10 (0f 8f 10 00 00 00)
        assert_eq!(
            classify(&[0x0f, 0x8f, 0x10, 0, 0, 0], 0x1000),
            Some((6, Cti::Branch(Cond::Jcc(0xf), 0x1016)))
        );
        // bnd jne (f2 75 02)
        assert_eq!(
            classify(&[0xf2, 0x75, 0x02], 0x10),
            Some((3, Cti::Branch(Cond::Jcc(5), 0x15)))
        );
        // loop, jrcxz
        assert_eq!(
            classify(&[0xe2, 0xfe], 0x10),
            Some((2, Cti::Branch(Cond::Loop, 0x10)))
        );
        assert_eq!(
            classify(&[0xe3, 0x01], 0x10),
            Some((2, Cti::Branch(Cond::Jrcxz, 0x13)))
        );
        assert_eq!(
            classify(&[0x67, 0xe3, 0x01], 0x10),
            Some((3, Cti::StepCond))
        );
        // call rel32, jmp rel8, ret, ret 8
        assert_eq!(
            classify(&[0xe8, 0xfb, 0xff, 0xff, 0xff], 0x100),
            Some((5, Cti::Call(0x100)))
        );
        assert_eq!(classify(&[0xeb, 0x00], 0x100), Some((2, Cti::Jmp(0x102))));
        assert_eq!(classify(&[0xc3], 0), Some((1, Cti::Ret(0))));
        assert_eq!(classify(&[0xc2, 0x08, 0x00], 0), Some((3, Cti::Ret(8))));
        // call *%rax (ff d0), jmp *%r11 (41 ff e3), notrack jmp *%rax (3e ff e0)
        assert_eq!(
            classify(&[0xff, 0xd0], 0),
            Some((2, Cti::IndCall(Operand::Reg(0))))
        );
        assert_eq!(
            classify(&[0x41, 0xff, 0xe3], 0),
            Some((3, Cti::IndJmp(Operand::Reg(11))))
        );
        assert_eq!(
            classify(&[0x3e, 0xff, 0xe0], 0),
            Some((3, Cti::IndJmp(Operand::Reg(0))))
        );
        // jmp *0x10(%rip) (ff 25 10 00 00 00), call *(%rax,%rbx,8) (ff 14 d8), jmp *0x8(%rsp) (ff 64 24 08)
        assert_eq!(
            classify(&[0xff, 0x25, 0x10, 0, 0, 0], 0),
            Some((
                6,
                Cti::IndJmp(Operand::Mem {
                    base: None,
                    index: None,
                    scale: 0,
                    disp: 0x10,
                    rip_rel: true
                })
            ))
        );
        assert_eq!(
            classify(&[0xff, 0x14, 0xd8], 0),
            Some((
                3,
                Cti::IndCall(Operand::Mem {
                    base: Some(0),
                    index: Some(3),
                    scale: 3,
                    disp: 0,
                    rip_rel: false
                })
            ))
        );
        assert_eq!(
            classify(&[0xff, 0x64, 0x24, 0x08], 0),
            Some((
                4,
                Cti::IndJmp(Operand::Mem {
                    base: Some(4),
                    index: None,
                    scale: 0,
                    disp: 8,
                    rip_rel: false
                })
            ))
        );
        // jmp *%fs:0x10 -> step; syscall, ud2, int3 -> enters; inc rax plain
        assert_eq!(
            classify(&[0x64, 0xff, 0x24, 0x25, 0x10, 0, 0, 0], 0).map(|c| c.1),
            Some(Cti::Step)
        );
        assert_eq!(classify(&[0x0f, 0x05], 0).map(|c| c.1), Some(Cti::Enters));
        assert_eq!(classify(&[0x0f, 0x0b], 0).map(|c| c.1), Some(Cti::Enters));
        assert_eq!(classify(&[0xcc], 0).map(|c| c.1), Some(Cti::Enters));
        assert_eq!(
            classify(&[0x48, 0xff, 0xc0], 0).map(|c| c.1),
            Some(Cti::Plain)
        );
        // rep movsb plain; push (ff /6) plain
        assert_eq!(classify(&[0xf3, 0xa4], 0).map(|c| c.1), Some(Cti::Plain));
        assert_eq!(classify(&[0xff, 0x30], 0).map(|c| c.1), Some(Cti::Plain));
    }

    #[test]
    fn conditions() {
        // je taken with ZF; jne not
        assert!(jcc_taken(4, ZF));
        assert!(!jcc_taken(5, ZF));
        // jl: SF != OF
        assert!(jcc_taken(0xc, SF));
        assert!(!jcc_taken(0xc, SF | OF));
        // jle: ZF or SF != OF; jg the inverse
        assert!(jcc_taken(0xe, ZF));
        assert!(!jcc_taken(0xf, ZF));
        assert!(jcc_taken(0xf, 0));
        // jbe / ja
        assert!(jcc_taken(6, CF));
        assert!(jcc_taken(7, 0));
        // jp / jnp, jo / jno, js / jns
        assert!(jcc_taken(0xa, PF) && !jcc_taken(0xb, PF));
        assert!(jcc_taken(0, OF) && !jcc_taken(1, OF));
        assert!(jcc_taken(8, SF) && !jcc_taken(9, SF));
        assert_eq!(eval(Cond::Loop, 0, 1), (false, 0));
        assert_eq!(eval(Cond::Loop, 0, 5), (true, 4));
        assert_eq!(eval(Cond::Loope, 0, 5), (false, 4));
        assert_eq!(eval(Cond::Loopne, 0, 5), (true, 4));
        assert_eq!(eval(Cond::Jrcxz, 0, 0), (true, 0));
    }

    #[test]
    fn slices() {
        let mut cfg = Config::default_with_seed(7);
        cfg.pmu_slice_min = SLICE_MIN_DEFAULT;
        cfg.pmu_slice_max = SLICE_MAX_DEFAULT;
        cfg.pmu_short = SHORT_PERMILLE_DEFAULT | (SHORT_MAX_DEFAULT << 16);
        cfg.pmu_margin = MARGIN_DEFAULT;
        let (mut short, mut long) = (0, 0);
        for k in 0..20_000u64 {
            let n = slice(&cfg, k);
            assert_eq!(n, slice(&cfg, k));
            if n <= SHORT_MAX_DEFAULT {
                assert!(n >= 1);
                assert_eq!(mode(&cfg, n), Mode::Hop);
                short += 1;
            } else {
                assert!((SLICE_MIN_DEFAULT..=SLICE_MAX_DEFAULT).contains(&n));
                assert_eq!(mode(&cfg, n), Mode::Long);
                long += 1;
            }
        }
        // about 2% short
        assert!(short > 250 && short < 600, "{short}");
        assert!(long > 19_000);
    }
}
