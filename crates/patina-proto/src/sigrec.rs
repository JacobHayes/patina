//! arm64 signal frames: the context records of `uc_mcontext.__reserved` (`uapi/asm/sigcontext.h`),
//! as the runtime turns the kernel's trap frame into the program's frame and back
//! (`rt/src/arch/aarch64/sigframe.rs`). Pure functions of the 4,096 bytes, so that they are
//! tested on any host (`cargo test -p patina-proto`): no test host has every record.
//!
//! Records by host kind: FP/SIMD everywhere; ESR for a fault with a syndrome; SVE on SVE or
//! SME hosts; TPIDR2 and the ZA header on SME hosts (ZT0 on SME2 while ZA is on); FPMR on
//! hosts with FEAT_FPMR; POE on hosts with FEAT_S1POE. The kernel adds each of the host's
//! records to every frame. What the runtime builds:
//! - FP/SIMD, TPIDR2, FPMR: copied (register values). The handler starts with the interrupted
//!   FP/SIMD and FPMR (the kernel does not reset them for a handler) and TPIDR2 0.
//! - POE: copied (the interrupted `POR_EL0`); the handler starts with `POR_EL0_INIT` (access to
//!   key 0 only), as the kernel sets it.
//! - SVE: the 16-byte header form whenever the state beyond FP/SIMD is zero, else the full form
//!   (the kernel's form depends on its own history).
//! - Anything else (streaming mode, ZA or ZT0 in use, GCS, an extra-context record, an unknown
//!   magic) is a stop (`Bad::Stop`, `signal-context`).

pub const FPSIMD_MAGIC: u32 = 0x4650_8001;
pub const FPSIMD_SIZE: usize = 528;
pub const ESR_MAGIC: u32 = 0x4553_5201;
pub const SVE_MAGIC: u32 = 0x5356_4501;
const SVE_FLAG_SM: u16 = 1;
pub const TPIDR2_MAGIC: u32 = 0x5450_4902;
pub const ZA_MAGIC: u32 = 0x5436_6345;
pub const ZT_MAGIC: u32 = 0x5a54_4e01;
pub const FPMR_MAGIC: u32 = 0x4650_4d52;
pub const POE_MAGIC: u32 = 0x504f_4530;
pub const EXTRA_MAGIC: u32 = 0x4558_5401;
/// TPIDR2, FPMR and POE records: a header and one register.
const REG_SIZE: usize = 16;
/// The `sve_context` and `za_context` headers (magic, size, vector length, flags), and the
/// terminating record.
const HDR: usize = 16;
/// `POR_EL0_INIT`: read, write and execute through key 0 only.
pub const POR_EL0_INIT: u64 = 0x7;

pub type Area = [u8; 4096];

/// Why a frame cannot be built or returned through.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Bad {
    /// State the runtime does not build: the run stops `signal-context` (the record's magic).
    Stop(u32),
    /// The kernel's own frame is malformed: a runtime defect.
    Host,
    /// A program's frame the kernel would refuse (`rt_sigreturn` gives SIGSEGV).
    Refused,
}

/// `SVE_SIG_CONTEXT_SIZE(vq)`: the header, 32 Z registers, 16 P registers and FFR.
pub fn sve_size(vq: usize) -> usize {
    if vq == 0 {
        HDR
    } else {
        HDR + 32 * 16 * vq + 17 * 2 * vq
    }
}

/// `ZA_SIG_CONTEXT_SIZE(vq)`.
fn za_size(vq: usize) -> usize {
    if vq == 0 {
        HDR
    } else {
        HDR + 256 * vq * vq
    }
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd64(b: &[u8], o: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(w)
}
fn header(out: &mut [u8], magic: u32, size: usize, vl: u16) {
    out[..HDR].fill(0);
    out[0..4].copy_from_slice(&magic.to_le_bytes());
    out[4..8].copy_from_slice(&(size as u32).to_le_bytes());
    out[8..10].copy_from_slice(&vl.to_le_bytes());
}
/// A one-register record (TPIDR2, FPMR, POE) at `out`.
fn reg_record(out: &mut [u8], magic: u32, v: u64) {
    header(out, magic, REG_SIZE, 0);
    out[8..16].copy_from_slice(&v.to_le_bytes());
}

/// One context record: magic, offset in `__reserved`, size.
#[derive(Clone, Copy, Default, Debug)]
struct Rec {
    pub magic: u32,
    pub off: usize,
    pub size: usize,
}

/// The record list of a `__reserved` area, with the structure checks of the kernel's
/// `parse_user_sigframe` (16-byte aligned records, sizes inside the area, a zero terminator).
/// ESR records are left out (`rt_sigreturn` ignores them) unless `esr`.
fn parse(b: &Area, esr: bool, out: &mut [Rec; 16]) -> Result<usize, ()> {
    let (mut off, mut n) = (0usize, 0usize);
    loop {
        if b.len() - off < 8 || off % 16 != 0 {
            return Err(());
        }
        let (magic, size) = (rd32(b, off), rd32(b, off + 4) as usize);
        if b.len() - off < size {
            return Err(());
        }
        if magic == 0 {
            return if size == 0 { Ok(n) } else { Err(()) };
        }
        if size < 8 {
            return Err(());
        }
        if magic != ESR_MAGIC || esr {
            if n == out.len() {
                return Err(());
            }
            out[n] = Rec { magic, off, size };
            n += 1;
        }
        off += size;
    }
}

/// The trap frame's records (made by the kernel: a malformed list is a runtime defect).
fn trap_records(t: &Area, out: &mut [Rec; 16]) -> Result<usize, Bad> {
    parse(t, true, out).map_err(|_| Bad::Host)
}

/// What the host's frames hold beyond FP/SIMD, from the trap frame: the SVE record's vector
/// length (hosts with SVE or SME), TPIDR2's value and the ZA record's vector length (SME), the
/// FPMR and POE values.
#[derive(Default)]
struct Host {
    sve_vl: Option<u16>,
    tpidr2: Option<u64>,
    za_vl: Option<u16>,
    fpmr: Option<u64>,
    poe: Option<u64>,
}

fn host(t: &Area) -> Result<Host, Bad> {
    let mut recs = [Rec::default(); 16];
    let n = trap_records(t, &mut recs)?;
    let mut h = Host::default();
    for r in &recs[..n] {
        let src = &t[r.off..r.off + r.size];
        match r.magic {
            FPSIMD_MAGIC | ESR_MAGIC => {}
            SVE_MAGIC if r.size >= HDR => {
                if rd16(src, 10) & SVE_FLAG_SM != 0 {
                    return Err(Bad::Stop(SVE_MAGIC));
                }
                h.sve_vl = Some(rd16(src, 8));
            }
            TPIDR2_MAGIC if r.size == REG_SIZE => h.tpidr2 = Some(rd64(src, 8)),
            FPMR_MAGIC if r.size == REG_SIZE => h.fpmr = Some(rd64(src, 8)),
            POE_MAGIC if r.size == REG_SIZE => h.poe = Some(rd64(src, 8)),
            ZA_MAGIC if r.size == HDR => h.za_vl = Some(rd16(src, 8)),
            m => return Err(Bad::Stop(m)),
        }
    }
    Ok(h)
}

/// Is any of the SVE state beyond FP/SIMD non-zero in this full `sve_context`: the upper bits
/// of a Z register, a P register, FFR?
fn sve_beyond_fpsimd(src: &[u8], vq: usize) -> bool {
    let z = |i: usize| HDR + i * 16 * vq;
    (0..32).any(|i| src[z(i) + 16..z(i) + 16 * vq].iter().any(|&b| b != 0))
        || src[z(32)..sve_size(vq)].iter().any(|&b| b != 0)
}

/// The program's records from the trap frame's (the rules in the module comment). `syndrome`:
/// keep the ESR record.
pub fn program_records(t: &Area, syndrome: bool) -> Result<Area, Bad> {
    let mut out = [0u8; 4096];
    let mut recs = [Rec::default(); 16];
    let n = trap_records(t, &mut recs)?;
    let mut w = 0usize;
    for r in &recs[..n] {
        let src = &t[r.off..r.off + r.size];
        let size = match r.magic {
            FPSIMD_MAGIC => r.size,
            TPIDR2_MAGIC | FPMR_MAGIC | POE_MAGIC if r.size == REG_SIZE => r.size,
            ESR_MAGIC if syndrome => r.size,
            ESR_MAGIC => continue,
            SVE_MAGIC if r.size >= HDR => {
                let (vl, flags) = (rd16(src, 8), rd16(src, 10));
                let vq = vl as usize / 16;
                if flags & SVE_FLAG_SM != 0 {
                    return Err(Bad::Stop(SVE_MAGIC));
                }
                if r.size > HDR && r.size < sve_size(vq) {
                    return Err(Bad::Host);
                }
                if r.size == HDR || !sve_beyond_fpsimd(src, vq) {
                    header(&mut out[w..], SVE_MAGIC, HDR, vl);
                    w += HDR;
                    continue;
                }
                r.size
            }
            ZA_MAGIC if r.size == HDR => r.size,
            m => return Err(Bad::Stop(m)),
        };
        out[w..w + size].copy_from_slice(src);
        if r.magic == SVE_MAGIC {
            // The kernel fills `SVE_SIG_CONTEXT_SIZE` and leaves the rounding up to 16 bytes
            // as whatever its stack held.
            let vq = rd16(src, 8) as usize / 16;
            out[w + sve_size(vq)..w + size].fill(0);
        }
        w += size;
    }
    Ok(out)
}

/// The trap frame's records as the handler starts with them (the kernel loads them when the
/// runtime's handler returns): TPIDR2 0, `POR_EL0` `POR_EL0_INIT`.
pub fn handler_entry(t: &mut Area) -> Result<(), Bad> {
    let mut recs = [Rec::default(); 16];
    let n = trap_records(t, &mut recs)?;
    for r in &recs[..n] {
        match r.magic {
            TPIDR2_MAGIC => t[r.off + 8..r.off + 16].fill(0),
            POE_MAGIC => t[r.off + 8..r.off + 16].copy_from_slice(&POR_EL0_INIT.to_le_bytes()),
            _ => {}
        }
    }
    Ok(())
}

/// The trap frame's new records from the program's frame `g` (validated as the kernel's
/// `parse_user_sigframe` and the `restore_*_context` functions do) and the trap frame's own
/// `t` (what the host has): the kernel loads them when the runtime's handler returns. A
/// register record the program's frame leaves out keeps the value the trap frame has, as
/// the kernel leaves the register.
pub fn records_in(g: &Area, t: &Area) -> Result<Area, Bad> {
    let h = host(t)?;
    let mut recs = [Rec::default(); 16];
    let n = parse(g, false, &mut recs).map_err(|_| Bad::Refused)?;
    let (mut fp, mut sve, mut tp, mut za, mut fpmr, mut poe) = (None, None, None, None, None, None);
    for r in &recs[..n] {
        let slot = match r.magic {
            FPSIMD_MAGIC => &mut fp,
            SVE_MAGIC if h.sve_vl.is_some() => &mut sve,
            TPIDR2_MAGIC if h.tpidr2.is_some() => &mut tp,
            ZA_MAGIC if h.za_vl.is_some() => &mut za,
            FPMR_MAGIC if h.fpmr.is_some() => &mut fpmr,
            POE_MAGIC if h.poe.is_some() => &mut poe,
            // Valid on an SME2 or any host: state the runtime does not build.
            ZT_MAGIC if h.za_vl.is_some() => return Err(Bad::Stop(ZT_MAGIC)),
            EXTRA_MAGIC => return Err(Bad::Stop(EXTRA_MAGIC)),
            // Not a record of this host's (GCS exists on none that runs here: its record would
            // have stopped the run at its first delivery), or unknown.
            _ => return Err(Bad::Refused),
        };
        if slot.is_some() {
            return Err(Bad::Refused);
        }
        *slot = Some(*r);
    }
    let fp = fp.ok_or(Bad::Refused)?;
    if fp.size != FPSIMD_SIZE {
        return Err(Bad::Refused);
    }
    let mut out = [0u8; 4096];
    out[..FPSIMD_SIZE].copy_from_slice(&g[fp.off..fp.off + FPSIMD_SIZE]);
    let mut w = FPSIMD_SIZE;
    if let Some(vl) = h.sve_vl {
        // Without an SVE record the kernel restores FP/SIMD only: the header form.
        let mut full = None;
        if let Some(r) = sve {
            if r.size < HDR {
                return Err(Bad::Refused);
            }
            let (uvl, flags) = (rd16(g, r.off + 8), rd16(g, r.off + 10));
            if flags & SVE_FLAG_SM != 0 {
                let vq = h.za_vl.ok_or(Bad::Refused)? as usize / 16;
                if Some(uvl) != h.za_vl || r.size < sve_size(vq) {
                    return Err(Bad::Refused);
                }
                return Err(Bad::Stop(SVE_MAGIC));
            }
            if uvl != vl {
                return Err(Bad::Refused);
            }
            let vq = vl as usize / 16;
            if r.size > HDR && vq > 0 {
                if r.size < sve_size(vq) {
                    return Err(Bad::Refused);
                }
                // More than `__reserved` holds with the records after it (vector lengths
                // above 512 bits): the kernel's extra-context form.
                if FPSIMD_SIZE + sve_size(vq) + 6 * HDR > g.len() {
                    return Err(Bad::Stop(EXTRA_MAGIC));
                }
                full = Some((r.off, sve_size(vq)));
            }
        }
        match full {
            Some((off, size)) => {
                out[w..w + size].copy_from_slice(&g[off..off + size]);
                let padded = (size + 15) & !15;
                header(&mut out[w..], SVE_MAGIC, padded, vl);
                w += padded;
            }
            None => {
                header(&mut out[w..], SVE_MAGIC, HDR, vl);
                w += HDR;
            }
        }
    }
    // The one-register records (the program's value, else the trap frame's) and the ZA
    // header, in the kernel's order.
    let reg = |have: Option<u64>, rec: Option<Rec>| -> Result<Option<u64>, Bad> {
        let Some(v) = have else {
            return Ok(None);
        };
        Ok(Some(match rec {
            Some(r) if r.size != REG_SIZE => return Err(Bad::Refused),
            Some(r) => rd64(g, r.off + 8),
            None => v,
        }))
    };
    let (tp, fpmr, poe) = (reg(h.tpidr2, tp)?, reg(h.fpmr, fpmr)?, reg(h.poe, poe)?);
    if let Some(v) = tp {
        reg_record(&mut out[w..], TPIDR2_MAGIC, v);
        w += REG_SIZE;
    }
    if let Some(vl) = h.za_vl {
        if let Some(r) = za {
            if r.size < HDR || rd16(g, r.off + 8) != vl {
                return Err(Bad::Refused);
            }
            if r.size > HDR {
                if r.size < za_size(vl as usize / 16) {
                    return Err(Bad::Refused);
                }
                return Err(Bad::Stop(ZA_MAGIC));
            }
        }
        header(&mut out[w..], ZA_MAGIC, HDR, vl);
        w += HDR;
    }
    for (v, magic) in [(fpmr, FPMR_MAGIC), (poe, POE_MAGIC)] {
        if let Some(v) = v {
            reg_record(&mut out[w..], magic, v);
            w += REG_SIZE;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `__reserved` area holding `recs` (magic, payload after the 8-byte head) in order.
    fn area(recs: &[(u32, &[u8])]) -> Area {
        let mut a = [0u8; 4096];
        let mut w = 0;
        for (m, p) in recs {
            let size = (8 + p.len() + 15) & !15;
            a[w..w + 4].copy_from_slice(&m.to_le_bytes());
            a[w + 4..w + 8].copy_from_slice(&(size as u32).to_le_bytes());
            a[w + 8..w + 8 + p.len()].copy_from_slice(p);
            w += size;
        }
        a
    }

    fn fpsimd(fill: u8) -> [u8; FPSIMD_SIZE - 8] {
        [fill; FPSIMD_SIZE - 8]
    }

    fn value(a: &Area, magic: u32) -> Option<u64> {
        let mut recs = [Rec::default(); 16];
        let n = parse(a, true, &mut recs).unwrap();
        recs[..n]
            .iter()
            .find(|r| r.magic == magic)
            .map(|r| rd64(a, r.off + 8))
    }

    /// A trap frame of a host with FPMR and POE (no SVE, no SME): FPMR 0x15, POR_EL0 0x77.
    fn trap() -> Area {
        area(&[
            (FPSIMD_MAGIC, &fpsimd(1)),
            (FPMR_MAGIC, &0x15u64.to_le_bytes()),
            (POE_MAGIC, &0x77u64.to_le_bytes()),
        ])
    }

    #[test]
    fn fpmr_and_poe_are_delivered_and_returned() {
        let t = trap();
        // The program's frame: the interrupted values.
        let p = program_records(&t, false).unwrap();
        assert_eq!(value(&p, FPMR_MAGIC), Some(0x15));
        assert_eq!(value(&p, POE_MAGIC), Some(0x77));
        // The handler: FPMR as interrupted, POR_EL0 POR_EL0_INIT.
        let mut h = t;
        handler_entry(&mut h).unwrap();
        assert_eq!(value(&h, FPMR_MAGIC), Some(0x15));
        assert_eq!(value(&h, POE_MAGIC), Some(POR_EL0_INIT));
        // rt_sigreturn: the frame's values (a handler's change included) are loaded.
        let mut g = p;
        let mut recs = [Rec::default(); 16];
        let n = parse(&g, true, &mut recs).unwrap();
        let fpmr = recs[..n]
            .iter()
            .find(|r| r.magic == FPMR_MAGIC)
            .unwrap()
            .off;
        g[fpmr + 8..fpmr + 16].copy_from_slice(&0x2au64.to_le_bytes());
        let back = records_in(&g, &h).unwrap();
        assert_eq!(value(&back, FPMR_MAGIC), Some(0x2a));
        assert_eq!(value(&back, POE_MAGIC), Some(0x77));
        // Without the records the registers keep the values they have.
        let g = area(&[(FPSIMD_MAGIC, &fpsimd(2))]);
        let back = records_in(&g, &h).unwrap();
        assert_eq!(value(&back, FPMR_MAGIC), Some(0x15));
        assert_eq!(value(&back, POE_MAGIC), Some(POR_EL0_INIT));
    }

    #[test]
    fn bad_register_records_are_refused() {
        let t = trap();
        // A wrong size, a duplicate, and a record of a feature this host does not have.
        let wrong = area(&[(FPSIMD_MAGIC, &fpsimd(0)), (POE_MAGIC, &[0u8; 24])]);
        let twice = area(&[
            (FPSIMD_MAGIC, &fpsimd(0)),
            (FPMR_MAGIC, &[0u8; 8]),
            (FPMR_MAGIC, &[0u8; 8]),
        ]);
        for g in [wrong, twice] {
            assert_eq!(records_in(&g, &t), Err(Bad::Refused));
        }
        let plain = area(&[(FPSIMD_MAGIC, &fpsimd(0))]);
        let g = area(&[(FPSIMD_MAGIC, &fpsimd(0)), (FPMR_MAGIC, &[0u8; 8])]);
        assert_eq!(records_in(&g, &plain), Err(Bad::Refused));
    }

    #[test]
    fn unbuilt_state_stops() {
        for m in [EXTRA_MAGIC, 0x4743_5300] {
            let t = area(&[(FPSIMD_MAGIC, &fpsimd(0)), (m, &[0u8; 24])]);
            assert_eq!(program_records(&t, false), Err(Bad::Stop(m)));
        }
    }
}
