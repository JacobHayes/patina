//! arm64: every instruction is one 32-bit word at a 4-byte boundary, so the rule is a compare
//! under a mask for each aligned word of an executable section; no length decoder, no sweep.
//!
//! - `RNDR Xt`, `RNDRRS Xt` (`mrs Xt, RNDR` / `RNDRRS`): patched and answered from the seed
//!   (when the host has the instruction, or the run asks for it: `rt::arch::insn`).
//! - `yield`, `wfe`, `wfi`, `isb`: patched as pause points.
//! - `PACGA Xd, Xn, Xm`: counted, not patched (the generic key cannot be disabled; its mask
//!   leaves 32,768 encodings, too many to overwrite where text may hold data).
//! - With counter preemption only: the exclusive instructions (`ldxr`, `ldaxr`, `ldxp`,
//!   `ldaxp`, `stxr`, `stlxr`, `stxp`, `stlxp`, any size, and `clrex`), patched and emulated
//!   so that a store-exclusive never fails spuriously (`rt::arch::insn`'s `exclusive`): a
//!   spurious failure retries the loop, two more branches counted.
//!
//! Data in text: a word that a literal load (`LDR`, `LDRSW`, `LDR` of a SIMD register, by
//! `pc`-relative offset) in the searched words reads is data, whatever it looks like: it is
//! rejected and counted. That is the one kind of data in text a reader can identify without
//! symbols (literal pools); data reached otherwise (a table addressed by `adr`) is not, and
//! a word of it that matches is patched. The census of `tests/insn/06-scanner-audit.sh`
//! measures how often that happens in real files.

/// What a site is. The values index `ctl::InsnCtl::patched`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SiteKind {
    Rndr = 1,
    Rndrrs = 2,
    Pacga = 3,
    Pause = 4,
    Exclusive = 5,
}

impl SiteKind {
    pub fn name(self) -> &'static str {
        match self {
            SiteKind::Rndr => "rndr",
            SiteKind::Rndrrs => "rndrrs",
            SiteKind::Pacga => "pacga",
            SiteKind::Pause => "pause",
            SiteKind::Exclusive => "exclusive",
        }
    }
}

/// The patch: `udf #0x7061`. It raises SIGILL with `pc` at the site; it is not a branch
/// target landing pad, and neither was any instruction it replaces.
pub const UDF: u32 = 0x0000_7061;

pub const YIELD: u32 = 0xd503_203f;
pub const WFE: u32 = 0xd503_205f;
pub const WFI: u32 = 0xd503_207f;
pub const ISB: u32 = 0xd503_3fdf;
/// `mrs Xt, RNDR` and `mrs Xt, RNDRRS` with `Rt` cleared.
pub const RNDR: u32 = 0xd53b_2400;
pub const RNDRRS: u32 = 0xd53b_2420;
const PACGA_MASK: u32 = 0xffe0_fc00;
const PACGA: u32 = 0x9ac0_3000;

/// The kind of the word `w`, if it is a candidate; the exclusive instructions with
/// `exclusive` (counter preemption) only.
#[inline]
pub fn kind_with(w: u32, exclusive: bool) -> Option<SiteKind> {
    if exclusive && (crate::step::is_load_exclusive(w) || crate::step::ends_pair(w)) {
        return Some(SiteKind::Exclusive);
    }
    kind(w)
}

/// The kind of the word `w`, if it is a candidate (without counter preemption).
#[inline]
pub fn kind(w: u32) -> Option<SiteKind> {
    // One compare rejects almost every word: all candidates have one of two top bytes.
    match w >> 24 {
        0xd5 => match w {
            YIELD | WFE | WFI | ISB => Some(SiteKind::Pause),
            _ if w & !0x1f == RNDR => Some(SiteKind::Rndr),
            _ if w & !0x1f == RNDRRS => Some(SiteKind::Rndrrs),
            _ => None,
        },
        0x9a if w & PACGA_MASK == PACGA => Some(SiteKind::Pacga),
        _ => None,
    }
}

/// The bytes a literal load at `pc` reads, as (address, length), when `w` is one.
#[inline]
pub fn literal(pc: u64, w: u32) -> Option<(u64, u64)> {
    if w & 0x3b00_0000 != 0x1800_0000 {
        return None;
    }
    let simd = w & (1 << 26) != 0;
    let len = match (w >> 30, simd) {
        (0, _) => 4,
        (1, _) => 8,
        (2, false) => 4,
        (2, true) => 16,
        _ => return None, // PRFM reads nothing; the SIMD form is unallocated
    };
    let off = (((w >> 5) & 0x7_ffff) as i64) << 45 >> 43; // imm19 * 4, sign-extended
    Some((pc.wrapping_add(off as u64), len))
}

/// Candidates handled per pass over the words.
const BATCH: usize = 256;

/// Call `f(index, Ok(kind))` for each site of `words` (the aligned words from address
/// `base`, in order) and `f(index, Err(kind))` for each candidate that a literal load in
/// `words` reads (data). Candidates go in batches of `BATCH`, each with one pass over `words`
/// for the literal loads.
pub fn sites(words: &[u32], base: u64, f: impl FnMut(usize, Result<SiteKind, SiteKind>)) {
    sites_with(words, base, false, f)
}

/// `sites`, the exclusive instructions included with `exclusive` (`kind_with`).
pub fn sites_with(
    words: &[u32],
    base: u64,
    exclusive: bool,
    mut f: impl FnMut(usize, Result<SiteKind, SiteKind>),
) {
    let mut cand = [0usize; BATCH];
    let mut n = 0;
    let mut i = 0;
    while i <= words.len() {
        if i < words.len() && kind_with(words[i], exclusive).is_some() {
            cand[n] = i;
            n += 1;
        }
        i += 1;
        if n == BATCH || (i > words.len() && n > 0) {
            batch(words, base, exclusive, &cand[..n], &mut f);
            n = 0;
        }
    }
}

fn batch(
    words: &[u32],
    base: u64,
    exclusive: bool,
    cand: &[usize],
    f: &mut impl FnMut(usize, Result<SiteKind, SiteKind>),
) {
    let mut data = [0u64; BATCH / 64];
    let (lo, hi) = (
        base + 4 * cand[0] as u64,
        base + 4 * cand[cand.len() - 1] as u64,
    );
    for (j, &w) in words.iter().enumerate() {
        let Some((t, len)) = literal(base + 4 * j as u64, w) else {
            continue;
        };
        if t.saturating_add(len) <= lo || t > hi {
            continue;
        }
        // The candidates the bytes [t, t + len) cover (at most four words).
        let first = cand.partition_point(|&c| base + 4 * (c as u64) < t);
        for (k, &c) in cand.iter().enumerate().skip(first) {
            if base + 4 * c as u64 >= t + len {
                break;
            }
            data[k / 64] |= 1 << (k % 64);
        }
    }
    for (k, &c) in cand.iter().enumerate() {
        let w = kind_with(words[c], exclusive).unwrap_or(SiteKind::Pause);
        f(
            c,
            if data[k / 64] & (1 << (k % 64)) != 0 {
                Err(w)
            } else {
                Ok(w)
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds() {
        assert_eq!(kind(YIELD), Some(SiteKind::Pause));
        assert_eq!(kind(ISB), Some(SiteKind::Pause));
        assert_eq!(kind(RNDR | 7), Some(SiteKind::Rndr));
        assert_eq!(kind(RNDRRS | 31), Some(SiteKind::Rndrrs));
        assert_eq!(kind(0x9ac2_3020), Some(SiteKind::Pacga)); // pacga x0, x1, x2
        assert_eq!(kind(0xd503_201f), None); // nop
        assert_eq!(kind(0xd503_241f), None); // bti c
        assert_eq!(kind(0xd53b_e040), None); // mrs x0, cntvct_el0 (trapped, not patched)
        assert_eq!(kind(UDF), None);
    }

    #[test]
    fn exclusive_only_with_counters() {
        let ldaxr = 0xc85f_fc20; // ldaxr x0, [x1]
        let stlxr = 0xc802_fc20; // stlxr w2, x0, [x1]
        let ldxp = 0xc87f_0820; // ldxp x0, x2, [x1]
        let clrex = 0xd503_3f5f;
        let ldadd = 0xf820_0020; // ldadd x0, x0, [x1] (an atomic: never a site)
        let casp = 0x4820_7c40; // casp w0, w1, w2, w3, [x2]
        for w in [ldaxr, stlxr, ldxp, clrex] {
            assert_eq!(kind(w), None);
            assert_eq!(kind_with(w, true), Some(SiteKind::Exclusive));
        }
        for w in [ldadd, casp, YIELD] {
            assert_eq!(kind_with(w, true), kind(w));
        }
        let words = [ldaxr, 0xeb03_001f, 0x5400_0061, stlxr, 0x35ff_ffa2];
        let mut n = 0;
        sites_with(&words, 0x1000, true, |_, r| {
            assert_eq!(r, Ok(SiteKind::Exclusive));
            n += 1;
        });
        assert_eq!(n, 2);
        sites(&words, 0x1000, |_, _| n += 1);
        assert_eq!(n, 2);
    }

    #[test]
    fn literal_pool_word_is_data() {
        // ldr x0, #8 at word 0 reads words 2 and 3; word 3 holds the `yield` encoding.
        let ldr_x0_8 = 0x5800_0040;
        let words = [ldr_x0_8, YIELD, 0x1234_5678, YIELD];
        let mut got = [None; 4];
        sites(&words, 0x1000, |i, r| got[i] = Some(r));
        assert_eq!(got[1], Some(Ok(SiteKind::Pause)));
        assert_eq!(got[3], Some(Err(SiteKind::Pause)));
        // A backward literal load (negative offset) is decoded too.
        assert_eq!(literal(0x1010, 0x58ff_ffe0), Some((0x100c, 8)));
    }

    #[test]
    fn batches() {
        let mut words = [YIELD; 3 * BATCH + 5];
        // The last word: a literal load of the first.
        let n = words.len();
        let back = (-(n as i64 - 1) as u32) & 0x7_ffff;
        words[n - 1] = 0x1800_0000 | back << 5; // ldr w0, <word 0>
        let (mut ok, mut data) = (0, 0);
        sites(&words, 0, |_, r| match r {
            Ok(_) => ok += 1,
            Err(_) => data += 1,
        });
        assert_eq!((ok, data), (n - 2, 1));
    }
}
