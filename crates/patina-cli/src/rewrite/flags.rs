//! Flag liveness for the count (DESIGN 2.3). A count is `dec qword [cell]`, which writes OF, SF,
//! ZF, AF and PF (not CF); it goes only where those five are dead: on every path forward from
//! the point, each is written before anything reads it.

use super::code::{direct_target, Code, Dec, FUNC, TAINT};
use iced_x86::{FlowControl, Instruction, Mnemonic, OpKind, Register, RflagsBits};

/// The flags a count writes.
pub const COUNT_FLAGS: u32 =
    RflagsBits::OF | RflagsBits::SF | RflagsBits::ZF | RflagsBits::AF | RflagsBits::PF;

/// Instructions followed before giving up (the answer is then "live").
const BUDGET: usize = 64;

/// The flags `i` certainly writes. A shift or rotate by `cl`, or by an immediate that masks to
/// zero, and a `rep`-prefixed string comparison leave the flags alone when the count is zero,
/// so they write nothing for certain. Flags left undefined count as written: no correct
/// program reads them.
pub fn writes(i: &Instruction) -> u32 {
    use Mnemonic::*;
    let shift = matches!(
        i.mnemonic(),
        Shl | Sal | Shr | Sar | Rol | Ror | Rcl | Rcr | Shld | Shrd
    );
    if shift {
        let n = i.op_count() - 1;
        let by_cl = i.op_kind(n) == OpKind::Register && i.op_register(n) == Register::CL;
        let mask = if i.op0_register().size() == 8 || i.memory_size().size() == 8 {
            0x3f
        } else {
            0x1f
        };
        let imm = matches!(i.op_kind(n), OpKind::Immediate8 | OpKind::Immediate8_2nd);
        if by_cl || (imm && i.immediate(n) & mask == 0) {
            return 0;
        }
    }
    if (i.has_rep_prefix() || i.has_repne_prefix()) && i.is_string_instruction() {
        return 0;
    }
    i.rflags_written() | i.rflags_cleared() | i.rflags_set() | i.rflags_undefined()
}

/// Are the count's five flags dead on entry to the decoded instruction at `at`? Paths are
/// followed through fall-through and direct branches; a path ends well at a return or at a
/// direct call of a function (flags are dead across both in every ABI in use); anything else
/// (an indirect jump, a trap, `syscall`, code not decoded or tainted, the budget) is live.
pub fn dead_at<'a>(code: &Code<'a>, d: &mut Dec<'a>, at: u64) -> bool {
    let mut work = vec![(at, COUNT_FLAGS)];
    let mut seen: Vec<(u64, u32)> = vec![];
    let mut steps = 0;
    while let Some((a, need)) = work.pop() {
        if seen.contains(&(a, need)) {
            continue;
        }
        seen.push((a, need));
        steps += 1;
        if steps > BUDGET || code.flags(a) & TAINT != 0 {
            return false;
        }
        let Some(i) = code.insn_in(d, a) else {
            return false;
        };
        if i.rflags_read() & need != 0 {
            return false;
        }
        let need = need & !writes(&i);
        if need == 0 {
            continue;
        }
        let next = a + i.len() as u64;
        match i.flow_control() {
            FlowControl::Next if i.mnemonic() != Mnemonic::Hlt => work.push((next, need)),
            FlowControl::Return => {}
            FlowControl::Call if i.mnemonic() != Mnemonic::Syscall => match direct_target(&i) {
                Some(t) if t != next && code.flags(t) & FUNC != 0 => {}
                _ => return false,
            },
            FlowControl::ConditionalBranch => match direct_target(&i) {
                Some(t) => work.extend([(t, need), (next, need)]),
                None => return false,
            },
            FlowControl::UnconditionalBranch => match direct_target(&i) {
                Some(t) => work.push((t, need)),
                None => return false,
            },
            _ => return false,
        }
    }
    true
}
