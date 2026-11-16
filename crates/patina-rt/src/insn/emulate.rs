//! SIGILL at a patched site: emulate the original instruction.
//!
//! The faulting instruction starts at the saved instruction pointer; the prefixes the CPU
//! actually decoded (`66`, `F3`, REX) are read from there up to the `ud2`, whose address must
//! be in the side table. `rdrand`/`rdseed` get a value from the seeded entropy stream keyed by
//! the event's `seq`, and the carry flag set (OF, SF, ZF, AF, PF cleared, as the instructions
//! do). Any other `ud2` is not ours: the guest's own SIGILL.

use crate::entry::{charge, maybe_yield};
use crate::state::{config, thread};
use crate::sys::sig::{self, SigInfo};
use crate::trap::{reg::*, TrapFrame};
use proto::ctl::{INSN_RDPID, INSN_RDRAND, INSN_RDSEED};
use proto::{draw, Stream};

pub const CODE_RDRAND: u32 = 0x0fc706;
pub const CODE_RDSEED: u32 = 0x0fc707;
pub const CODE_RDPID: u32 = 0xf30fc707;

/// Hardware register number -> index in the saved `gregs`.
const GREG: [usize; 16] = [
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, 3, 4, 5, 6, 7,
];

const EFL_CF: u64 = 1 << 0;
const EFL_ARITH: u64 = (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);

pub fn try_emulate(frame: &mut TrapFrame, sig: i32, _info: &SigInfo) -> bool {
    if sig as u64 != sig::SIGILL {
        return false;
    }
    let rip = frame.gregs[RIP];
    // Prefixes the CPU decoded, then the ud2 we wrote.
    let (mut p66, mut pf3, mut rex) = (false, false, 0u8);
    let mut op = rip;
    let mut found = false;
    for _ in 0..15 {
        let b = unsafe { *(op as *const u8) };
        match b {
            0x66 => p66 = true,
            0xf3 => pf3 = true,
            0xf2 | 0xf0 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x67 => {}
            0x40..=0x4f => {
                rex = b;
                op += 1;
                continue;
            }
            0x0f => {
                found = true;
                break;
            }
            _ => return false,
        }
        rex = 0;
        op += 1;
    }
    if !found {
        return false;
    }
    if super::patch::lookup(op).is_none() {
        return false;
    }
    if unsafe { *((op + 1) as *const u8) } != 0x0b {
        return false;
    }
    let modrm = unsafe { *((op + 2) as *const u8) };
    let reg = (modrm >> 3) & 7;
    let (code, idx) = match (reg, pf3) {
        (6, false) => (CODE_RDRAND, INSN_RDRAND),
        (7, false) => (CODE_RDSEED, INSN_RDSEED),
        (7, true) => (CODE_RDPID, INSN_RDPID),
        _ => return false,
    };
    let ts = thread();
    charge(ts);
    crate::insn::count_emulated(idx);
    let c = crate::state::ctl();
    crate::insn::bump(&c.stats.insn_emulations, 1);
    let dst = GREG[((modrm & 7) | if rex & 1 != 0 { 8 } else { 0 }) as usize];
    let val = if idx == INSN_RDPID {
        0 // the CPU number, as rdtscp's auxiliary value: 0
    } else {
        draw(config().seed, Stream::Entropy, ts.seq)
    };
    let old = frame.gregs[dst];
    // 64-bit: the whole register; 16-bit: the upper 48 bits stay; 32-bit: zero-extended.
    let v = if idx == INSN_RDPID || rex & 8 != 0 {
        val
    } else if p66 {
        (old & !0xffff) | (val & 0xffff)
    } else {
        val & 0xffff_ffff
    };
    frame.gregs[dst] = v;
    if idx != INSN_RDPID {
        frame.gregs[EFL] = (frame.gregs[EFL] & !EFL_ARITH) | EFL_CF;
    }
    frame.gregs[RIP] = op + 3;
    crate::log::insn(code, rip, v);
    maybe_yield(ts);
    true
}
