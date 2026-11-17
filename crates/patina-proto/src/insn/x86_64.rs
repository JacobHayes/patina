//! Instruction sites: an x86-64 instruction length decoder and the scanner rule that
//! decides which byte patterns are patched. Shared so that `patina __insn-scan` runs the very code
//! the runtime runs (the false-positive audit compares it with a disassembler).
//!
//! The rule: a candidate is the byte pair `0F C7` followed by a register ModRM (mod = 3) whose
//! reg field is 6 or 7 (`rdrand`, `rdseed`, and with an `F3` prefix `rdpid`), or the pair
//! `F3 90` (`pause`). It is accepted only when a linear sweep, started at a known instruction
//! boundary at or before it (the nearest function symbol, else the start of the mapping),
//! lands on an instruction whose opcode bytes are exactly the candidate (for `pause`: an
//! instruction that starts at the `F3` and is those two bytes). Bytes that sit inside another
//! instruction (an immediate, a displacement) or that the sweep skips are rejected and counted.

/// What a confirmed site is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SiteKind {
    Rdrand = 1,
    Rdseed = 2,
    Rdpid = 3,
    Pause = 4,
}

impl SiteKind {
    pub fn name(self) -> &'static str {
        match self {
            SiteKind::Rdrand => "rdrand",
            SiteKind::Rdseed => "rdseed",
            SiteKind::Rdpid => "rdpid",
            SiteKind::Pause => "pause",
        }
    }
}

/// A decoded instruction: its length, where its opcode starts, and the prefixes seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub len: usize,
    /// Offset of the first opcode byte (after legacy prefixes and REX).
    pub op: usize,
    pub p66: bool,
    pub pf3: bool,
    pub pf2: bool,
    /// REX byte, 0 if none.
    pub rex: u8,
}

const fn modrm_len(code: &[u8], at: usize, addr32: bool) -> Option<usize> {
    let _ = addr32; // 32-bit addressing in 64-bit mode has the same ModRM/SIB/displacement shape
    if at >= code.len() {
        return None;
    }
    let m = code[at];
    let (md, rm) = (m >> 6, m & 7);
    let mut n = 1;
    if md == 3 {
        return Some(n);
    }
    if rm == 4 {
        if at + 1 >= code.len() {
            return None;
        }
        let sib = code[at + 1];
        n += 1;
        if md == 0 && sib & 7 == 5 {
            n += 4;
        }
    } else if md == 0 && rm == 5 {
        n += 4; // RIP-relative
    }
    n += match md {
        1 => 1,
        2 => 4,
        _ => 0,
    };
    Some(n)
}

/// Opcodes of the one-byte map that take a ModRM byte (64-bit mode).
const fn one_byte_modrm(op: u8) -> bool {
    match op {
        0x00..=0x3f => op & 7 < 4,
        0x63 | 0x69 | 0x6b => true,
        0x80..=0x8f => true,
        0xc0 | 0xc1 | 0xc6 | 0xc7 => true,
        0xd0..=0xd3 | 0xd8..=0xdf => true,
        0xf6 | 0xf7 | 0xfe | 0xff => true,
        _ => false,
    }
}

/// Length of the immediate (and relative) operand of a one-byte-map opcode.
fn one_byte_imm(op: u8, modrm: u8, osz16: bool, rexw: bool, addr32: bool) -> Option<usize> {
    let iz = if osz16 { 2 } else { 4 };
    Some(match op {
        0x00..=0x3f => match op & 7 {
            4 => 1,
            5 => iz,
            _ => 0,
        },
        0x68 | 0x69 | 0x81 | 0xa9 | 0xc7 => iz,
        0x6a | 0x6b | 0x80 | 0x83 | 0xa8 | 0xc0 | 0xc1 | 0xc6 | 0xcd | 0xe4..=0xe7 => 1,
        0x70..=0x7f | 0xe0..=0xe3 | 0xeb => 1,
        0xe8 | 0xe9 => 4,
        0xa0..=0xa3 => {
            if addr32 {
                4
            } else {
                8
            }
        }
        0xb0..=0xb7 => 1,
        0xb8..=0xbf => {
            if rexw {
                8
            } else {
                iz
            }
        }
        0xc2 | 0xca => 2,
        0xc8 => 3,
        0xf6 => {
            if (modrm >> 3) & 7 < 2 {
                1
            } else {
                0
            }
        }
        0xf7 if (modrm >> 3) & 7 < 2 => iz,
        _ => 0,
    })
}

/// Opcodes invalid in 64-bit mode (one-byte map).
const fn one_byte_invalid(op: u8) -> bool {
    matches!(
        op,
        0x06 | 0x07
            | 0x0e
            | 0x16
            | 0x17
            | 0x1e
            | 0x1f
            | 0x27
            | 0x2f
            | 0x37
            | 0x3f
            | 0x60
            | 0x61
            | 0x82
            | 0x9a
            | 0xce
            | 0xd4
            | 0xd5
            | 0xd6
            | 0xea
    )
}

/// Two-byte map (0F xx): does it take a ModRM, and how long is its immediate?
fn two_byte(op: u8, p66: bool, pf2: bool) -> Option<(bool, usize)> {
    Some(match op {
        0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0b | 0x0e => (false, 0),
        0x30..=0x35 | 0x37 => (false, 0),
        0x77 => (false, 0),
        0x80..=0x8f => (false, 4),
        0xa0 | 0xa1 | 0xa2 | 0xa8 | 0xa9 | 0xaa => (false, 0),
        0xc8..=0xcf => (false, 0),
        0x04 | 0x0a | 0x0c | 0x24..=0x27 | 0x36 | 0x39 | 0x3b..=0x3f => return None,
        0x70..=0x73 | 0xa4 | 0xac | 0xba | 0xc2 | 0xc4 | 0xc5 | 0xc6 => (true, 1),
        0x0f => (true, 1),               // 3DNow!: the opcode is a trailing byte
        0x78 if p66 || pf2 => (true, 2), // extrq / insertq (AMD SSE4a) with two imm8
        _ => (true, 0),
    })
}

/// Immediate length of a VEX/EVEX/XOP instruction by map and opcode.
const fn vex_imm(map: u8, op: u8) -> usize {
    match map {
        1 => match op {
            0x70..=0x73 | 0xc2 | 0xc4 | 0xc5 | 0xc6 => 1,
            _ => 0,
        },
        3 | 8 => 1,
        0x0a => 4,
        _ => 0,
    }
}

/// Decode the instruction at the start of `code` (64-bit mode). `None` when the bytes are
/// not a valid instruction or run past the end.
pub fn decode(code: &[u8]) -> Option<Insn> {
    let mut i = 0;
    let (mut p66, mut pf3, mut pf2, mut addr32, mut rex) = (false, false, false, false, 0u8);
    loop {
        let b = *code.get(i)?;
        match b {
            0x66 => p66 = true,
            0x67 => addr32 = true,
            0xf3 => pf3 = true,
            0xf2 => pf2 = true,
            0xf0 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 => {}
            0x40..=0x4f => {
                // REX; only the last one before the opcode counts (several are legal).
                rex = b;
                i += 1;
                if i > 14 {
                    return None;
                }
                continue;
            }
            _ => break,
        }
        rex = 0;
        i += 1;
        if i > 14 {
            return None;
        }
    }
    let rexw = rex & 8 != 0;
    let osz16 = p66 && !rexw;
    let op_at = i;
    let op = *code.get(i)?;
    i += 1;
    let ins = |len: usize| -> Option<Insn> {
        if len > 15 || len > code.len() {
            None
        } else {
            Some(Insn {
                len,
                op: op_at,
                p66,
                pf3,
                pf2,
                rex,
            })
        }
    };
    match op {
        0x0f => {
            let op2 = *code.get(i)?;
            i += 1;
            match op2 {
                0x38 => {
                    i += 1; // opcode byte
                    let m = modrm_len(code, i, addr32)?;
                    ins(i + m)
                }
                0x3a => {
                    i += 1;
                    let m = modrm_len(code, i, addr32)?;
                    ins(i + m + 1)
                }
                _ => {
                    let (has_modrm, imm) = two_byte(op2, p66, pf2)?;
                    let m = if has_modrm {
                        modrm_len(code, i, addr32)?
                    } else {
                        0
                    };
                    ins(i + m + imm)
                }
            }
        }
        0xc5 | 0xc4 | 0x62 => {
            // VEX2, VEX3, EVEX (always so in 64-bit mode)
            let (map, payload) = match op {
                0xc5 => (1u8, 1),
                0xc4 => (*code.get(i)? & 0x1f, 2),
                _ => (*code.get(i)? & 0x07, 3),
            };
            i += payload;
            let vop = *code.get(i)?;
            i += 1;
            if map == 1 && vop == 0x77 && op != 0x62 {
                return ins(i); // vzeroupper / vzeroall: no ModRM
            }
            let m = modrm_len(code, i, addr32)?;
            ins(i + m + vex_imm(map, vop))
        }
        0x8f => {
            let nb = *code.get(i)?;
            if (nb >> 3) & 7 != 0 {
                // XOP
                let map = nb & 0x1f;
                i += 2;
                let vop = *code.get(i)?;
                let _ = vop;
                i += 1;
                let m = modrm_len(code, i, addr32)?;
                ins(i + m + vex_imm(map, vop))
            } else {
                let m = modrm_len(code, i, addr32)?;
                ins(i + m)
            }
        }
        _ => {
            if one_byte_invalid(op) {
                return None;
            }
            let (m, modrm) = if one_byte_modrm(op) {
                (modrm_len(code, i, addr32)?, *code.get(i)?)
            } else {
                (0, 0)
            };
            let imm = one_byte_imm(op, modrm, osz16, rexw, addr32)?;
            ins(i + m + imm)
        }
    }
}

/// Is `code[off..]` a candidate (`0F C7` with a register ModRM, reg 6 or 7; or `F3 90`)?
#[inline]
pub fn is_candidate(code: &[u8], off: usize) -> bool {
    (off + 2 < code.len()
        && code[off] == 0x0f
        && code[off + 1] == 0xc7
        && code[off + 2] >> 6 == 3
        && (code[off + 2] >> 3) & 7 >= 6)
        || is_pause(code, off)
}

/// `F3 90` at `off`.
#[inline]
fn is_pause(code: &[u8], off: usize) -> bool {
    off + 1 < code.len() && code[off] == 0xf3 && code[off + 1] == 0x90
}

/// Call `f` with every candidate offset in `code`, in order.
pub fn candidates(code: &[u8], mut f: impl FnMut(usize)) {
    // Eight offsets at a time: `w` holds the bytes at them, `n` the bytes after them, and a
    // byte of `eq(w, a) & eq(n, b)` is set where the pair `a b` starts. Only `0F C7` and
    // `F3 90` can start a candidate; offsets so marked get the full test.
    const LO: u64 = 0x0101_0101_0101_0101;
    const HI: u64 = 0x8080_8080_8080_8080;
    // The high bit of each byte of `x` that equals `b`, exactly.
    let eq = |x: u64, b: u64| {
        let t = x ^ (b * LO);
        !(((t & !HI) + !HI) | t) & HI
    };
    let mut i = 0;
    while i + 9 <= code.len() {
        let w = u64::from_le_bytes(code[i..i + 8].try_into().unwrap());
        let n = u64::from_le_bytes(code[i + 1..i + 9].try_into().unwrap());
        let mut m = (eq(w, 0x0f) & eq(n, 0xc7)) | (eq(w, 0xf3) & eq(n, 0x90));
        while m != 0 {
            let j = i + (m.trailing_zeros() / 8) as usize;
            if is_candidate(code, j) {
                f(j);
            }
            m &= m - 1;
        }
        i += 8;
    }
    while i + 1 < code.len() {
        if is_candidate(code, i) {
            f(i);
        }
        i += 1;
    }
}

/// Where the sweep for a candidate at `cand` starts: the nearest function symbol at or before
/// it inside the mapping that starts at `seg`, else `seg` itself. Symbols are run-time
/// addresses (any order).
pub fn sweep_start(cand: u64, seg: u64, syms: impl Iterator<Item = u64>) -> u64 {
    let mut best = seg;
    for s in syms {
        if s <= cand && s > best {
            best = s;
        }
    }
    best
}

/// A confirmed site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Site {
    /// Offset of the instruction's first byte (prefixes included).
    pub start: usize,
    /// Offset of the bytes `ud2` replaces: the `0F` opcode byte, or a `pause`'s `F3`.
    pub op: usize,
    pub len: usize,
    pub kind: Option<SiteKind>,
}

/// The verdict on one candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// An instruction starts here: `kind` is None for `F3 0F C7 /6` (`senduipi`), which is
    /// not one of ours.
    Real(Site),
    /// The bytes lie inside another instruction, at instruction start `at`.
    Inside { at: usize },
    /// The sweep skipped them (undecodable bytes on the way).
    Skipped,
}

/// Classify the candidate at `off` by a linear sweep starting at `from` (an instruction
/// boundary at or before `off`). Undecodable bytes are skipped one at a time, as a
/// linear-sweep disassembler does.
pub fn confirm(code: &[u8], from: usize, off: usize) -> Verdict {
    sweep(code, from, off).0
}

/// `confirm`, and where the sweep stopped: an offset the same sweep reaches, at or before
/// `off` unless the verdict is `Skipped`. A later candidate whose sweep starts at the same
/// `from` may resume there (`confirm(code, from, c2)` = `sweep(code, stop, c2).0`), which
/// keeps a scan of many candidates linear.
pub fn sweep(code: &[u8], from: usize, off: usize) -> (Verdict, usize) {
    let mut pos = from;
    while pos <= off {
        match decode(&code[pos..]) {
            Some(d) => {
                if pos + d.len > off {
                    if pos == off && d.len == 2 && is_pause(code, off) {
                        return (
                            Verdict::Real(Site {
                                start: pos,
                                op: off,
                                len: 2,
                                kind: Some(SiteKind::Pause),
                            }),
                            pos,
                        );
                    }
                    if pos + d.op == off && code[off] == 0x0f && code[off + 1] == 0xc7 {
                        let reg = (code[off + 2] >> 3) & 7;
                        let kind = match (reg, d.pf3) {
                            (6, false) => Some(SiteKind::Rdrand),
                            (7, false) => Some(SiteKind::Rdseed),
                            (7, true) => Some(SiteKind::Rdpid),
                            _ => None,
                        };
                        return (
                            Verdict::Real(Site {
                                start: pos,
                                op: off,
                                len: d.len,
                                kind,
                            }),
                            pos,
                        );
                    }
                    return (Verdict::Inside { at: pos }, pos);
                }
                pos += d.len;
            }
            None => pos += 1,
        }
    }
    (Verdict::Skipped, pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn len(b: &[u8]) -> usize {
        decode(b).map(|d| d.len).unwrap_or(0)
    }

    #[test]
    fn lengths() {
        assert_eq!(len(&[0x0f, 0xc7, 0xf0]), 3); // rdrand eax
        assert_eq!(len(&[0x48, 0x0f, 0xc7, 0xf0]), 4); // rdrand rax
        assert_eq!(len(&[0x66, 0x0f, 0xc7, 0xf8]), 4); // rdseed ax
        assert_eq!(len(&[0xf3, 0x0f, 0xc7, 0xf8]), 4); // rdpid
        assert_eq!(len(&[0xe8, 0, 0, 0, 0]), 5);
        assert_eq!(len(&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8]), 10); // movabs
        assert_eq!(len(&[0x48, 0x8b, 0x05, 0, 0, 0, 0]), 7); // mov rax,[rip+0]
        assert_eq!(len(&[0x8b, 0x44, 0x24, 0x08]), 4); // mov eax,[rsp+8]
        assert_eq!(len(&[0xc5, 0xf8, 0x77]), 3); // vzeroupper
        assert_eq!(len(&[0xc4, 0xe3, 0x79, 0x0f, 0xc1, 0x08]), 6); // vpalignr imm8
        assert_eq!(len(&[0x62, 0xf1, 0x7c, 0x48, 0x10, 0x00]), 6); // vmovups zmm0,[rax]
        assert_eq!(len(&[0x66, 0x0f, 0x3a, 0x0f, 0xc1, 0x08]), 6); // palignr
        assert_eq!(len(&[0xf7, 0xc0, 1, 0, 0, 0]), 6); // test eax, imm32
        assert_eq!(len(&[0xf7, 0xd0]), 2); // not eax
        assert_eq!(len(&[0x0f, 0x31]), 2);
        assert_eq!(len(&[0x0f, 0x01, 0xf9]), 3);
    }

    #[test]
    fn inside_a_call_displacement_is_rejected() {
        // call rel32 whose displacement holds 0F C7 F8 (the libcrypto false positive's shape).
        let code = [0x90, 0xe8, 0x00, 0x0f, 0xc7, 0xf8, 0x90];
        let mut c = [0usize; 4];
        let mut n = 0;
        candidates(&code, |o| {
            c[n] = o;
            n += 1
        });
        assert_eq!(&c[..n], &[3]);
        assert_eq!(confirm(&code, 0, 3), Verdict::Inside { at: 1 });
    }

    #[test]
    fn candidates_are_every_matching_offset() {
        // Pseudo-random bytes rich in 0F, C7, F3 and 90, at every alignment and length.
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let pick = [0x0f, 0xc7, 0xf3, 0x90, 0xf0, 0xf8, 0x00, 0x48];
        let mut bytes = [0u8; 4096];
        for b in bytes.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = pick[(x % 8) as usize];
        }
        for start in 0..9 {
            for end in [start, start + 1, start + 2, start + 9, start + 17, 4096] {
                let code = &bytes[start..end];
                // Every offset reported is a candidate, in order, and none is missed.
                let mut next = 0;
                candidates(code, |o| {
                    assert!(o >= next, "start {start} end {end}: {o} out of order");
                    for m in next..o {
                        assert!(
                            !is_candidate(code, m),
                            "start {start} end {end}: {m} missed"
                        );
                    }
                    assert!(is_candidate(code, o));
                    next = o + 1;
                });
                for m in next..code.len() {
                    assert!(
                        !is_candidate(code, m),
                        "start {start} end {end}: {m} missed"
                    );
                }
            }
        }
    }

    #[test]
    fn pause_sites() {
        // pause; mov eax, 0x90f3 (the pair inside an immediate); pause after a skipped byte.
        let code = [0xf3, 0x90, 0xb8, 0xf3, 0x90, 0, 0, 0xf3, 0x90];
        let mut c = [0usize; 4];
        let mut n = 0;
        candidates(&code, |o| {
            c[n] = o;
            n += 1
        });
        assert_eq!(&c[..n], &[0, 3, 7]);
        assert!(
            matches!(confirm(&code, 0, 0), Verdict::Real(s) if s.kind == Some(SiteKind::Pause) && s.op == 0)
        );
        assert_eq!(confirm(&code, 0, 3), Verdict::Inside { at: 2 });
        assert!(matches!(confirm(&code, 0, 7), Verdict::Real(s) if s.op == 7 && s.len == 2));
    }

    #[test]
    fn real_sites_with_prefixes() {
        let code = [0x90, 0x66, 0x49, 0x0f, 0xc7, 0xf2, 0xc3];
        match confirm(&code, 0, 3) {
            Verdict::Real(s) => {
                assert_eq!(
                    (s.start, s.op, s.len, s.kind),
                    (1, 3, 5, Some(SiteKind::Rdrand))
                );
            }
            v => panic!("{v:?}"),
        }
    }
}
