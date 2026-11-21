//! The decoder against the assembler: `CODE` is `tests.s` as assembled (the words and their
//! disassembly), so every encoding below is the assembler's, not typed by hand.

use super::*;

// Generated from tests.s: clang --target=aarch64-linux-gnu
// -march=armv9.5-a+cmpbr+pauth-lr+lse+hbc -c, then llvm-objdump -d; the word at index i is at
// BASE + 4 * i. Each line: the assembler's word and its disassembly.
#[rustfmt::skip]
pub const CODE: &[u32] = &[
    0x14000001, // 0x000 b <c_b_t>
    0x97ffffff, // 0x004 bl <t>
    0x14000000, // 0x008 b <c_bself>
    0x94000000, // 0x00c bl <c_blself>
    0x54ffff80, // 0x010 b.eq <t>
    0x54ffffac, // 0x014 b.gt <c_bself>
    0x54000001, // 0x018 b.ne <c_bnes>
    0x54ffff36, // 0x01c bc.vs <t>
    0x34ffff03, // 0x020 cbz w3, <t>
    0xb4fffee3, // 0x024 cbz x3, <t>
    0xb5fffec3, // 0x028 cbnz x3, <t>
    0xb4fffebf, // 0x02c cbz xzr, <t>
    0xb60ffe84, // 0x030 tbz x4, #0x21, <t>
    0x3717fe64, // 0x034 tbnz w4, #0x2, <t>
    0xd61f00a0, // 0x038 br x5
    0xd63f00c0, // 0x03c blr x6
    0xd65f03c0, // 0x040 ret
    0xd65f00e0, // 0x044 ret x7
    0xd71f08a9, // 0x048 braa x5, x9
    0xd61f08bf, // 0x04c braaz x5
    0xd73f08df, // 0x050 blraa x6, sp
    0xd63f0cdf, // 0x054 blrabz x6
    0xd65f0bff, // 0x058 retaa
    0xd65f0fff, // 0x05c retab
    0xd4000001, // 0x060 svc #0
    0xd4200020, // 0x064 brk #0x1
    0x00007061, // 0x068 udf #0x7061
    0xd4400000, // 0x06c hlt #0
    0xd69f03e0, // 0x070 eret
    0xd503201f, // 0x074 nop
    0x8b020020, // 0x078 add x0, x1, x2
    0xf9400420, // 0x07c ldr x0, [x1, #0x8]
    0xd5033fdf, // 0x080 isb
    0xd53bd040, // 0x084 mrs x0, TPIDR_EL0
    0x88e0fc41, // 0x088 casal w0, w1, [x2]
    0xf8200041, // 0x08c ldadd x0, x1, [x2]
    0xb8208041, // 0x090 swp w0, w1, [x2]
    0x48207c82, // 0x094 casp x0, x1, x2, x3, [x4]
    0x88dffc20, // 0x098 ldar w0, [x1]
    0x889ffc20, // 0x09c stlr w0, [x1]
    0xb8bfc020, // 0x0a0 ldapr w0, [x1]
    0xf4013ae0, // 0x0a4 cbgt x0, x1, <t>
    0x5500055f, // 0x0a8 retaasppc <t>
    0x885ffc01, // 0x0ac ldaxr w1, [x0]
    0x8802fc03, // 0x0b0 stlxr w2, w3, [x0]
    0x35ffffc2, // 0x0b4 cbnz w2, <p_plain>
    0x885ffc01, // 0x0b8 ldaxr w1, [x0]
    0x6b04003f, // 0x0bc cmp w1, w4
    0x54000061, // 0x0c0 b.ne <p_cas_out>
    0x8802fc05, // 0x0c4 stlxr w2, w5, [x0]
    0x35ffff82, // 0x0c8 cbnz w2, <p_cas>
    0xd65f03c0, // 0x0cc ret
    0xc85f7c01, // 0x0d0 ldxr x1, [x0]
    0x97ffffcb, // 0x0d4 bl <t>
    0xc8027c01, // 0x0d8 stxr w2, x1, [x0]
    0xc85f7c01, // 0x0dc ldxr x1, [x0]
    0xd503201f, // 0x0e0 nop
    0xd503201f, // 0x0e4 nop
    0xd503201f, // 0x0e8 nop
    0xd503201f, // 0x0ec nop
    0xd503201f, // 0x0f0 nop
    0xd503201f, // 0x0f4 nop
    0xd503201f, // 0x0f8 nop
    0xd503201f, // 0x0fc nop
    0xd503201f, // 0x100 nop
    0xd503201f, // 0x104 nop
    0xd503201f, // 0x108 nop
    0xd503201f, // 0x10c nop
    0xd503201f, // 0x110 nop
    0xd503201f, // 0x114 nop
    0xd503201f, // 0x118 nop
    0xd503201f, // 0x11c nop
    0xd503201f, // 0x120 nop
    0xd503201f, // 0x124 nop
    0xd503201f, // 0x128 nop
    0xd503201f, // 0x12c nop
    0xd503201f, // 0x130 nop
    0xd503201f, // 0x134 nop
    0xd503201f, // 0x138 nop
    0xd503201f, // 0x13c nop
    0xd503201f, // 0x140 nop
    0xd503201f, // 0x144 nop
    0xd503201f, // 0x148 nop
    0xd503201f, // 0x14c nop
    0xd503201f, // 0x150 nop
    0xd503201f, // 0x154 nop
    0xd503201f, // 0x158 nop
    0xd503201f, // 0x15c nop
    0xc8027c01, // 0x160 stxr w2, x1, [x0]
    0xc85f7c01, // 0x164 ldxr x1, [x0]
    0xd503201f, // 0x168 nop
    0xd503201f, // 0x16c nop
    0xd503201f, // 0x170 nop
    0xd503201f, // 0x174 nop
    0xd503201f, // 0x178 nop
    0xd503201f, // 0x17c nop
    0xd503201f, // 0x180 nop
    0xd503201f, // 0x184 nop
    0xd503201f, // 0x188 nop
    0xd503201f, // 0x18c nop
    0xd503201f, // 0x190 nop
    0xd503201f, // 0x194 nop
    0xd503201f, // 0x198 nop
    0xd503201f, // 0x19c nop
    0xd503201f, // 0x1a0 nop
    0xd503201f, // 0x1a4 nop
    0xd503201f, // 0x1a8 nop
    0xd503201f, // 0x1ac nop
    0xd503201f, // 0x1b0 nop
    0xd503201f, // 0x1b4 nop
    0xd503201f, // 0x1b8 nop
    0xd503201f, // 0x1bc nop
    0xd503201f, // 0x1c0 nop
    0xd503201f, // 0x1c4 nop
    0xd503201f, // 0x1c8 nop
    0xd503201f, // 0x1cc nop
    0xd503201f, // 0x1d0 nop
    0xd503201f, // 0x1d4 nop
    0xd503201f, // 0x1d8 nop
    0xd503201f, // 0x1dc nop
    0xd503201f, // 0x1e0 nop
    0xc8027c01, // 0x1e4 stxr w2, x1, [x0]
    0x885ffc01, // 0x1e8 ldaxr w1, [x0]
    0x35000041, // 0x1ec cbnz w1, <p_clrex_out>
    0xd5033f5f, // 0x1f0 clrex
    0xd503201f, // 0x1f4 nop
    0xc87f8801, // 0x1f8 ldaxp x1, x2, [x0]
    0xc8238801, // 0x1fc stlxp w3, x1, x2, [x0]
    0x885f7c01, // 0x200 ldxr w1, [x0]
    0x35ffffe1, // 0x204 cbnz w1, <p_back>
    0x88027c01, // 0x208 stxr w2, w1, [x0]
    0x885f7c01, // 0x20c ldxr w1, [x0]
    0x885f7c02, // 0x210 ldxr w2, [x0]
    0x88037c01, // 0x214 stxr w3, w1, [x0]
    0x885f7c01, // 0x218 ldxr w1, [x0]
    0x34ffef21, // 0x21c cbz w1, <t>
    0x34ffef22, // 0x220 cbz w2, <c_b_t>
    0x34ffef23, // 0x224 cbz w3, <c_bself>
    0x34ffef24, // 0x228 cbz w4, <c_blself>
    0x34ffef25, // 0x22c cbz w5, <c_beq>
    0x88037c01, // 0x230 stxr w3, w1, [x0]
    0x885f7c01, // 0x234 ldxr w1, [x0]
    0xd4000001, // 0x238 svc #0
    0x88037c01, // 0x23c stxr w3, w1, [x0]
    0x88037c01, // 0x240 stxr w3, w1, [x0]
    0x085f7c01, // 0x244 ldxrb w1, [x0]
    0x3707edc1, // 0x248 tbnz w1, #0x0, <t>
    0x08037c01, // 0x24c stxrb w3, w1, [x0]
    0x52800025, // 0x250 mov w5, #0x1 // =1
    0x885ffc01, // 0x254 ldaxr w1, [x0]
    0x8802fc05, // 0x258 stlxr w2, w5, [x0]
    0x35ffffa2, // 0x25c cbnz w2, <p_pre>
    0x885ffc01, // 0x260 ldaxr w1, [x0]
    0x8802fc05, // 0x264 stlxr w2, w5, [x0]
    0x35ffffc1, // 0x268 cbnz w1, <p_other>
    0x885ffc01, // 0x26c ldaxr w1, [x0]
    0x8802fc05, // 0x270 stlxr w2, w5, [x0]
    0x3707ffc2, // 0x274 tbnz w2, #0x0, <p_tbnz>
    0xc85ffc01, // 0x278 ldaxr x1, [x0]
    0xeb04003f, // 0x27c cmp x1, x4
    0x54000061, // 0x280 b.ne <p_xcas_out>
    0xc8027c05, // 0x284 stxr w2, x5, [x0]
    0x35ffff82, // 0x288 cbnz w2, <p_xcas>
    0xd65f03c0, // 0x28c ret
];
pub const C_B: usize = 0;
pub const C_B_T: usize = 1;
pub const C_BSELF: usize = 2;
pub const C_BLSELF: usize = 3;
pub const C_BEQ: usize = 4;
pub const C_BGT: usize = 5;
pub const C_BNES: usize = 6;
pub const C_BCVS: usize = 7;
pub const C_CBZW: usize = 8;
pub const C_CBZX: usize = 9;
pub const C_CBNZX: usize = 10;
pub const C_CBZZR: usize = 11;
pub const C_TBZ33: usize = 12;
pub const C_TBNZ2: usize = 13;
pub const C_BR: usize = 14;
pub const C_BLR: usize = 15;
pub const C_RET: usize = 16;
pub const C_RETX7: usize = 17;
pub const C_BRAA: usize = 18;
pub const C_BRAAZ: usize = 19;
pub const C_BLRAA: usize = 20;
pub const C_BLRABZ: usize = 21;
pub const C_RETAA: usize = 22;
pub const C_RETAB: usize = 23;
pub const C_SVC: usize = 24;
pub const C_BRK: usize = 25;
pub const C_UDF: usize = 26;
pub const C_HLT: usize = 27;
pub const C_ERET: usize = 28;
pub const C_NOP: usize = 29;
pub const C_ADD: usize = 30;
pub const C_LDR: usize = 31;
pub const C_ISB: usize = 32;
pub const C_MRS: usize = 33;
pub const C_CASAL: usize = 34;
pub const C_LDADD: usize = 35;
pub const C_SWP: usize = 36;
pub const C_CASP: usize = 37;
pub const C_LDAR: usize = 38;
pub const C_STLR: usize = 39;
pub const C_LDAPR: usize = 40;
pub const C_CMPBR: usize = 41;
pub const C_RETASP: usize = 42;
pub const P_PLAIN: usize = 43;
pub const P_CAS: usize = 46;
pub const P_CAS_OUT: usize = 51;
pub const P_CALL: usize = 52;
pub const P_FAR: usize = 55;
pub const P_EDGE: usize = 89;
pub const P_CLREX: usize = 122;
pub const P_CLREX_OUT: usize = 125;
pub const P_XP: usize = 126;
pub const P_BACK: usize = 128;
pub const P_TWO: usize = 131;
pub const P_MANY: usize = 134;
pub const P_SVC: usize = 141;
pub const P_STXR: usize = 144;
pub const P_TBZX: usize = 145;
pub const P_PRE: usize = 148;
pub const P_PRE_L: usize = 149;
pub const P_OTHER: usize = 152;
pub const P_TBNZ: usize = 155;
pub const P_XCAS: usize = 158;
pub const P_XCAS_OUT: usize = 163;

const BASE: u64 = 0x40_0000;

fn at(i: usize) -> u64 {
    BASE + 4 * i as u64
}

/// The successor of `CODE[i]` with registers `x` and flags `nzcv` (pstate bits 31-28).
fn succ(i: usize, x: &[u64; 31], nzcv: u64) -> Next {
    let r = Regs {
        x,
        pstate: nzcv << 28,
    };
    let end = (i + 1 + PAIR_MAX).min(CODE.len());
    next(at(i), CODE[i], &r, &CODE[i + 1..end])
}

const Z: u64 = 0b0100;
const N: u64 = 0b1000;
const V: u64 = 0b0001;

#[test]
fn direct_branches() {
    let x = [0u64; 31];
    assert_eq!(succ(C_B, &x, 0), Next::At(at(C_B_T)));
    assert_eq!(succ(C_B_T, &x, 0), Next::At(at(C_B)));
    assert_eq!(succ(C_BSELF, &x, 0), Next::SelfLoop { link: false });
    assert_eq!(succ(C_BLSELF, &x, 0), Next::SelfLoop { link: true });
}

#[test]
fn conditions() {
    let x = [0u64; 31];
    assert_eq!(succ(C_BEQ, &x, Z), Next::At(at(C_B)));
    assert_eq!(succ(C_BEQ, &x, 0), Next::At(at(C_BEQ + 1)));
    // gt: Z clear and N == V
    assert_eq!(succ(C_BGT, &x, 0), Next::At(at(C_BSELF)));
    assert_eq!(succ(C_BGT, &x, N | V), Next::At(at(C_BSELF)));
    assert_eq!(succ(C_BGT, &x, N), Next::At(at(C_BGT + 1)));
    assert_eq!(succ(C_BGT, &x, Z), Next::At(at(C_BGT + 1)));
    assert_eq!(succ(C_BNES, &x, 0), Next::SelfLoop { link: false });
    assert_eq!(succ(C_BNES, &x, Z), Next::At(at(C_BNES + 1)));
    assert_eq!(succ(C_BCVS, &x, V), Next::At(at(C_B)));
    assert_eq!(succ(C_BCVS, &x, 0), Next::At(at(C_BCVS + 1)));
}

#[test]
fn compare_and_test_branches() {
    let mut x = [0u64; 31];
    x[3] = 0x1_0000_0000; // w3 is zero, x3 is not
    assert_eq!(succ(C_CBZW, &x, 0), Next::At(at(C_B)));
    assert_eq!(succ(C_CBZX, &x, 0), Next::At(at(C_CBZX + 1)));
    assert_eq!(succ(C_CBNZX, &x, 0), Next::At(at(C_B)));
    assert_eq!(succ(C_CBZZR, &x, 0), Next::At(at(C_B)));
    x[4] = 1 << 33;
    assert_eq!(succ(C_TBZ33, &x, 0), Next::At(at(C_TBZ33 + 1)));
    assert_eq!(succ(C_TBNZ2, &x, 0), Next::At(at(C_TBNZ2 + 1)));
    x[4] = 1 << 2;
    assert_eq!(succ(C_TBZ33, &x, 0), Next::At(at(C_B)));
    assert_eq!(succ(C_TBNZ2, &x, 0), Next::At(at(C_B)));
}

#[test]
fn register_branches_and_their_authenticating_forms() {
    let mut x = [0u64; 31];
    x[5] = 0x5000;
    x[6] = 0x6000;
    x[7] = 0x7000;
    x[9] = 0x9999;
    x[30] = 0x3000;
    for (i, to) in [
        (C_BR, 0x5000),
        (C_BLR, 0x6000),
        (C_RET, 0x3000),
        (C_RETX7, 0x7000),
        (C_BRAA, 0x5000),
        (C_BRAAZ, 0x5000),
        (C_BLRAA, 0x6000),
        (C_BLRABZ, 0x6000),
        (C_RETAA, 0x3000),
        (C_RETAB, 0x3000),
    ] {
        assert_eq!(succ(i, &x, 0), Next::At(to), "{:#x}", CODE[i]);
    }
    x[5] = at(C_BR);
    assert_eq!(succ(C_BR, &x, 0), Next::Refuse(Refusal::IndirectSelf));
}

#[test]
fn refused_and_plain() {
    let x = [0u64; 31];
    for i in [C_SVC, C_BRK, C_UDF, C_HLT] {
        assert_eq!(
            succ(i, &x, 0),
            Next::Refuse(Refusal::Exception),
            "{:#x}",
            CODE[i]
        );
    }
    // eret; branch forms this decoder does not know (compare-and-branch, retaasppc)
    for i in [C_ERET, C_CMPBR, C_RETASP] {
        assert_eq!(
            succ(i, &x, 0),
            Next::Refuse(Refusal::UnknownBranch),
            "{:#x}",
            CODE[i]
        );
    }
    // Not branches; single-instruction atomics and ordered accesses are not pairs.
    for i in [
        C_NOP, C_ADD, C_LDR, C_ISB, C_MRS, C_CASAL, C_LDADD, C_SWP, C_CASP, C_LDAR, C_STLR, C_LDAPR,
    ] {
        assert_eq!(succ(i, &x, 0), Next::At(at(i + 1)), "{:#x}", CODE[i]);
        assert!(!ends_pair(CODE[i]), "{:#x}", CODE[i]);
    }
}

fn stops(i: usize) -> Vec<u64> {
    match succ(i, &[0; 31], 0) {
        Next::Pair { at, n } => at[..n].to_vec(),
        other => panic!("{:#x}: {other:?}", CODE[i]),
    }
}

extern crate std;
use std::vec::Vec;

#[test]
fn exclusive_pairs() {
    // ldaxr; stlxr; cbnz on the status back to the load: the retry is in the pair, one stop
    // after it
    assert_eq!(stops(P_PLAIN), [at(P_PLAIN + 3)]);
    assert_eq!(stops(P_TBNZ), [at(P_TBNZ + 3)]);
    // compare-and-swap with an early exit: after the retry, which is the exit's target too
    assert_eq!(stops(P_CAS), [at(P_CAS_OUT)]);
    assert_eq!(stops(P_XCAS), [at(P_XCAS_OUT)]);
    // a retry to before the load, or a branch on another register: stop after the store
    assert_eq!(stops(P_PRE_L), [at(P_PRE_L + 2)]);
    let mut failed = [0u64; 31];
    failed[2] = 1;
    assert_eq!(succ(P_PRE_L + 2, &failed, 0), Next::At(at(P_PRE)));
    assert_eq!(stops(P_OTHER), [at(P_OTHER + 2)]);
    // clrex ends a pair; its conditional exit is just after it (one stop)
    assert_eq!(stops(P_CLREX), [at(P_CLREX_OUT)]);
    assert_eq!(stops(P_XP), [at(P_XP + 2)]);
    // a branch back to the load stays in the pair
    assert_eq!(stops(P_BACK), [at(P_BACK + 3)]);
    // a store 32 instructions on is in reach
    assert_eq!(stops(P_EDGE), [at(P_EDGE + 33)]);
    assert_eq!(stops(P_TBZX), [at(P_TBZX + 3), at(C_B)]);
    // a store-exclusive alone is an ordinary instruction
    assert_eq!(succ(P_STXR, &[0; 31], 0), Next::At(at(P_STXR + 1)));
}

#[test]
fn exclusive_pairs_refused() {
    // a call inside, no store within 32, a second load, five exits, a system call
    for i in [P_CALL, P_FAR, P_TWO, P_MANY, P_SVC] {
        assert_eq!(succ(i, &[0; 31], 0), Next::Refuse(Refusal::Pair), "at {i}");
    }
    // the words after the load could not all be read: no store in what was
    let r = Regs {
        x: &[0; 31],
        pstate: 0,
    };
    assert_eq!(
        next(at(P_PLAIN), CODE[P_PLAIN], &r, &[]),
        Next::Refuse(Refusal::Pair)
    );
}

#[test]
fn every_word_of_the_branch_group_is_decoded_or_refused() {
    // Over every top byte of the group, with the rest of the word varied: only the system
    // class (0xd5) is "not a branch"; every other word is decoded as a branch or refused.
    let x = [0u64; 31];
    let r = Regs { x: &x, pstate: 0 };
    for top in 0u32..256 {
        if top >> 2 & 7 != 0b101 {
            continue;
        }
        for low in [0u32, 0x1f, 0x3e0, 0x7c00, 0x1f_0000, 0xff_ffff, 0x80_0420] {
            let w = top << 24 | low;
            if matches!(branch(BASE, w, &r), Branch::No) {
                assert_eq!(top, 0xd5, "{w:#x}");
            }
        }
    }
}
