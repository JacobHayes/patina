//! The A64 words the rewriter and its verifier need to tell apart, by their encoding masks
//! (Arm ARM, "A64 instruction set encoding"). Every instruction is one 32-bit word, so a
//! decode is a classification: where control goes, what memory a PC-relative word names, and
//! whether a word is a site, a landing pad or one compiled code never holds. Exclusive pairs
//! are `proto::step`'s (the spin probe's stepper uses the same rule).

/// What a word does to control flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    /// Goes on to the next word (`svc` and system instructions included).
    Plain,
    /// `b` (`link` false) or `bl`.
    Direct { target: u64, link: bool },
    /// `b.cond`, `cbz`, `cbnz`, `tbz`, `tbnz`; `hinted`: `bc.cond`.
    Cond { target: u64, hinted: bool },
    /// `br`, `blr`, `ret` and their authenticating forms.
    Indirect(Ind),
    /// `udf`, `brk`: a trap; nothing after it is reached through it.
    Trap,
    /// A word compiled user code does not hold: an unallocated or reserved encoding,
    /// `hvc`/`smc`/`hlt`/`dcps`, `eret`, `drps`.
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ind {
    Jump,
    Call,
    Ret,
}

fn sext(v: u32, bits: u32) -> i64 {
    ((v as i64) << (64 - bits)) >> (64 - bits)
}

fn rel(pc: u64, words: i64) -> u64 {
    pc.wrapping_add((words << 2) as u64)
}

pub fn flow(pc: u64, w: u32) -> Flow {
    // udf #imm16
    if w >> 16 == 0 {
        return Flow::Trap;
    }
    match w >> 25 & 0xf {
        // Reserved (SME), unallocated.
        0b0000 | 0b0001 | 0b0011 => return Flow::Refused,
        _ => {}
    }
    match w >> 26 {
        0b000101 => {
            return Flow::Direct {
                target: rel(pc, sext(w & 0x3ff_ffff, 26)),
                link: false,
            }
        }
        0b100101 => {
            return Flow::Direct {
                target: rel(pc, sext(w & 0x3ff_ffff, 26)),
                link: true,
            }
        }
        _ => {}
    }
    if w & 0xff00_0000 == 0x5400_0000 {
        return Flow::Cond {
            target: rel(pc, sext(w >> 5 & 0x7_ffff, 19)),
            hinted: w & 0x10 != 0,
        };
    }
    if w & 0x7e00_0000 == 0x3400_0000 {
        return Flow::Cond {
            target: rel(pc, sext(w >> 5 & 0x7_ffff, 19)),
            hinted: false,
        };
    }
    if w & 0x7e00_0000 == 0x3600_0000 {
        return Flow::Cond {
            target: rel(pc, sext(w >> 5 & 0x3fff, 14)),
            hinted: false,
        };
    }
    // Exception generation: `11010100 opc imm16 op2 LL`.
    if w >> 24 == 0xd4 {
        return match (w >> 21 & 7, w & 0x1f) {
            (0, 1) => Flow::Plain, // svc
            (1, 0) => Flow::Trap,  // brk
            _ => Flow::Refused,
        };
    }
    // Unconditional branch (register): `1101011 opc op2 op3 Rn op4`.
    if w >> 25 == 0b110_1011 {
        let (opc, op2, op3, rn, op4) = (
            w >> 21 & 0xf,
            w >> 16 & 0x1f,
            w >> 10 & 0x3f,
            w >> 5 & 0x1f,
            w & 0x1f,
        );
        let plain = op3 == 0 && op4 == 0;
        let auth_z = op3 >> 1 == 1 && op4 == 0x1f;
        return match opc {
            _ if op2 != 0x1f => Flow::Refused,
            0 if plain || auth_z => Flow::Indirect(Ind::Jump),
            1 if plain || auth_z => Flow::Indirect(Ind::Call),
            2 if plain || (auth_z && rn == 0x1f) => Flow::Indirect(Ind::Ret),
            8 if op3 >> 1 == 1 => Flow::Indirect(Ind::Jump),
            9 if op3 >> 1 == 1 => Flow::Indirect(Ind::Call),
            _ => Flow::Refused,
        };
    }
    Flow::Plain
}

/// What a PC-relative word names: `adr` (an address taken), `adrp` (the page only; the
/// address is its pair's, `paired`), a literal load (`ldr`, `ldrsw`, SIMD; bytes read).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcRel {
    Addr(u64),
    Page { page: u64, rd: u32 },
    Read { at: u64, len: u64 },
}

pub fn pc_rel(pc: u64, w: u32) -> Option<PcRel> {
    let imm21 = || sext((w >> 5 & 0x7_ffff) << 2 | (w >> 29 & 3), 21);
    match w & 0x9f00_0000 {
        0x1000_0000 => return Some(PcRel::Addr(pc.wrapping_add(imm21() as u64))),
        0x9000_0000 => {
            return Some(PcRel::Page {
                page: (pc & !0xfff).wrapping_add((imm21() << 12) as u64),
                rd: w & 0x1f,
            })
        }
        _ => {}
    }
    // Load register (literal): `opc 011 V 00 imm19 Rt`.
    if w & 0x3b00_0000 == 0x1800_0000 {
        let (opc, v) = (w >> 30, w >> 26 & 1);
        let len = match (opc, v) {
            (0, _) | (2, 0) => 4,
            (1, _) => 8,
            (2, 1) => 16,
            _ => return None, // prfm, or unallocated
        };
        return Some(PcRel::Read {
            at: rel(pc, sext(w >> 5 & 0x7_ffff, 19)),
            len,
        });
    }
    None
}

/// The memory a word right after `adrp rd` names through `rd`: `add rd', rd, #imm` (an
/// address) or a load or store with an unsigned offset from `rd` (bytes read or written).
pub fn paired(page: u64, rd: u32, w: u32) -> Option<PcRel> {
    if w >> 5 & 0x1f != rd {
        return None;
    }
    // add (immediate), 64-bit: `1 0 0 100010 sh imm12 Rn Rd`
    if w & 0xff80_0000 == 0x9100_0000 {
        let imm = (w >> 10 & 0xfff) as u64;
        let imm = if w >> 22 & 1 == 1 { imm << 12 } else { imm };
        return Some(PcRel::Addr(page.wrapping_add(imm)));
    }
    // Load/store register (unsigned immediate): `size 111 V 01 opc imm12 Rn Rt`
    if w & 0x3b00_0000 == 0x3900_0000 {
        let (size, v, opc) = (w >> 30, w >> 26 & 1, w >> 22 & 3);
        let scale = if v == 1 && opc >= 2 { 4 } else { size };
        let at = page.wrapping_add(((w >> 10 & 0xfff) as u64) << scale);
        return Some(PcRel::Read {
            at,
            len: 1 << scale,
        });
    }
    None
}

/// A single-instruction atomic read-modify-write (FEAT_LSE): `cas`, `casp`, `swp` and the
/// `ld<op>` family (their `st<op>` aliases included); not `ldapr`, nor the `ld64b` family.
pub fn atomic(w: u32) -> bool {
    // Atomic memory operations: `size 111 0 00 A R 1 Rs o3 opc 00 Rn Rt`.
    if w & 0x3f20_0c00 == 0x3820_0000 {
        let (o3, opc) = (w >> 15 & 1, w >> 12 & 7);
        return o3 == 0 || opc == 0;
    }
    // cas: `size 0010001 L 1 Rs o0 11111 Rn Rt`; casp: `0 sz 0010000 L 1 Rs o0 11111 Rn Rt`.
    w & 0x3fa0_7c00 == 0x08a0_7c00 || w & 0xbfa0_7c00 == 0x0820_7c00
}

/// A landing pad of branch target identification: `bti` (any target kind), and `paciasp` and
/// `pacibsp`, which are pads themselves.
pub fn landing_pad(w: u32) -> bool {
    w & 0xffff_ff3f == 0xd503_241f || w == 0xd503_233f || w == 0xd503_237f
}

/// A landing pad that `br x16` may enter on a guarded page: `bti c`, `bti j`, `bti jc`,
/// `paciasp`, `pacibsp` (not a bare `bti`).
pub fn x16_pad(w: u32) -> bool {
    (w & 0xffff_ff3f == 0xd503_241f && w & 0xc0 != 0) || w == 0xd503_233f || w == 0xd503_237f
}

pub use proto::step::{ends_pair, is_load_exclusive};

/// A store-exclusive's status register (`Rs`): `stxr`, `stlxr`, `stxp`, `stlxp`.
pub fn store_status(w: u32) -> Option<u32> {
    (ends_pair(w) && w & 0x3f80_0000 == 0x0800_0000).then_some(w >> 16 & 0x1f)
}

/// Where `b` at `a`, a `cbz` or `cbnz` on register `rs` (the status of the store before it),
/// goes when the store failed (the status is 1): `cbnz`'s target, `cbz`'s next word.
pub fn on_failure(a: u64, b: u32, rs: u32) -> Option<u64> {
    if b & 0x7e00_0000 != 0x3400_0000 || b & 0x1f != rs {
        return None;
    }
    Some(if b & 0x0100_0000 != 0 {
        rel(a, sext(b >> 5 & 0x7_ffff, 19))
    } else {
        a + 4
    })
}

// Encoders.
pub const X16: u32 = 16;
pub const X17: u32 = 17;

/// `b` or `bl` from `pc` to `to`, if in reach (±128 MiB).
pub fn b(pc: u64, to: u64, link: bool) -> Option<u32> {
    let d = to.wrapping_sub(pc) as i64;
    (d % 4 == 0 && (-(1 << 27)..1 << 27).contains(&d))
        .then_some(if link { 0x9400_0000 } else { 0x1400_0000 } | (d >> 2) as u32 & 0x3ff_ffff)
}

/// The conditional branch `w` (from `Flow::Cond`, not hinted) re-aimed from `pc` at `to`, if
/// in its reach.
pub fn cond_to(w: u32, pc: u64, to: u64) -> Option<u32> {
    let d = to.wrapping_sub(pc) as i64 >> 2;
    let (shift, bits) = if w & 0x7e00_0000 == 0x3600_0000 {
        (5, 14)
    } else {
        (5, 19)
    };
    let lim = 1i64 << (bits - 1);
    if !(-lim..lim).contains(&d) {
        return None;
    }
    let mask = ((1u32 << bits) - 1) << shift;
    Some(w & !mask | ((d as u32) << shift & mask))
}

/// `movz xd, #(v >> 16), lsl #16`: `v` with only bits 16..32 set.
pub fn movz_hi(rd: u32, v: u64) -> u32 {
    assert!(v & !0xffff_0000 == 0, "the cell is one movz");
    0xd2a0_0000 | ((v >> 16) as u32) << 5 | rd
}

/// `adrp xd, page(to)` at `pc`, if in reach (±4 GiB).
pub fn adrp(rd: u32, pc: u64, to: u64) -> Option<u32> {
    let d = ((to & !0xfff) as i64).wrapping_sub((pc & !0xfff) as i64) >> 12;
    (-(1 << 20)..1 << 20)
        .contains(&d)
        .then_some(0x9000_0000 | ((d as u32) & 3) << 29 | ((d as u32) >> 2 & 0x7_ffff) << 5 | rd)
}

/// `add xd, xn, #(v & 0xfff)`: the low 12 bits of an address after its `adrp`.
pub fn add_lo12(rd: u32, rn: u32, v: u64) -> u32 {
    0x9100_0000 | ((v & 0xfff) as u32) << 10 | rn << 5 | rd
}

/// `br xn`.
pub fn br(rn: u32) -> u32 {
    0xd61f_0000 | rn << 5
}

/// `cbz x17, to` from `pc`.
pub fn cbz_x17(pc: u64, to: u64) -> u32 {
    let d = (to.wrapping_sub(pc) as i64 >> 2) as u32 & 0x7_ffff;
    0xb400_0000 | d << 5 | X17
}
