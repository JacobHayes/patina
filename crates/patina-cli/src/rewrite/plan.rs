//! The plan file: what a runtime maps in place of a file's text. A plain data format with no
//! decision in it: the patched text pages, the trampoline blob, and one row per patched
//! instruction saying where its trampoline is and what a trap there means. Addresses are the
//! file's own (link-time) virtual addresses; a loader adds the load bias.
//!
//! ```text
//! header   magic "PATPLAN\0", version, ELF machine, SHA-256 of the file, cell address,
//!          trampoline address and length, counts of the tables below, the patina build
//! pages    (address, length, offset in this file) per run of patched pages
//! sites    (address, trampoline offset, trampoline length, trap offset, copy offset,
//!          instruction length, kind) in address order
//! counts   (name, value): the rewrite's report
//! data     page runs then the trampoline blob, each at a page-aligned offset of this file
//! ```

use crate::cli::Res;

pub const MAGIC: &[u8; 8] = b"PATPLAN\0";
pub const VERSION: u32 = 1;
pub const PAGE: u64 = 4096;
/// The count's cell, which the runtime maps: one word below 2 GiB, so `dec qword [abs32]`
/// reaches it from any image.
pub const CELL: u64 = 0x7fff_0000;

/// The trampoline counts, then jumps to the patched branch's or call's original target (the
/// patched instruction now goes to the trampoline instead).
pub const KIND_JUMP: u8 = 1;
/// The trampoline counts, then runs a copy of the patched instruction, then jumps to the
/// instruction after it (the patched instruction is a jump to the trampoline).
pub const KIND_BEFORE: u8 = 2;
/// `copy` of a site without a copied instruction.
pub const NO_COPY: u16 = u16::MAX;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// The patched instruction: address and length.
    pub addr: u64,
    pub len: u8,
    pub kind: u8,
    /// The trampoline: offset in the blob and length.
    pub tramp: u32,
    pub tramp_len: u16,
    /// Offsets in the trampoline: the trap (a point at this site) and the copy of the patched
    /// instruction, whose original address is `addr`.
    pub trap: u16,
    pub copy: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pages {
    pub vaddr: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub sha256: [u8; 32],
    pub build: String,
    pub cell: u64,
    pub pages: Vec<Pages>,
    pub tramp_vaddr: u64,
    pub tramp: Vec<u8>,
    pub sites: Vec<Site>,
    pub counts: Vec<(String, u64)>,
}

fn align(n: usize) -> usize {
    n.next_multiple_of(PAGE as usize)
}

impl Plan {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut h = vec![];
        h.extend_from_slice(MAGIC);
        h.extend_from_slice(&VERSION.to_le_bytes());
        h.extend_from_slice(&(super::elf::EM_X86_64 as u32).to_le_bytes());
        h.extend_from_slice(&self.sha256);
        for v in [self.cell, self.tramp_vaddr, self.tramp.len() as u64] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        for n in [
            self.pages.len(),
            self.sites.len(),
            self.counts.len(),
            self.build.len(),
        ] {
            h.extend_from_slice(&(n as u32).to_le_bytes());
        }
        h.extend_from_slice(self.build.as_bytes());
        let dir = h.len();
        h.resize(dir + 24 * self.pages.len(), 0);
        for s in &self.sites {
            h.extend_from_slice(&s.addr.to_le_bytes());
            h.extend_from_slice(&s.tramp.to_le_bytes());
            for v in [s.tramp_len, s.trap, s.copy] {
                h.extend_from_slice(&v.to_le_bytes());
            }
            h.extend_from_slice(&[s.len, s.kind]);
        }
        for (k, v) in &self.counts {
            h.extend_from_slice(&(k.len() as u16).to_le_bytes());
            h.extend_from_slice(k.as_bytes());
            h.extend_from_slice(&v.to_le_bytes());
        }
        let mut off = align(h.len());
        for (k, p) in self.pages.iter().enumerate() {
            let e = dir + 24 * k;
            h[e..e + 8].copy_from_slice(&p.vaddr.to_le_bytes());
            h[e + 8..e + 16].copy_from_slice(&(p.bytes.len() as u64).to_le_bytes());
            h[e + 16..e + 24].copy_from_slice(&(off as u64).to_le_bytes());
            off = align(off + p.bytes.len());
        }
        let mut out = h;
        for p in &self.pages {
            out.resize(align(out.len()), 0);
            out.extend_from_slice(&p.bytes);
        }
        out.resize(align(out.len()), 0);
        out.extend_from_slice(&self.tramp);
        out
    }

    pub fn from_bytes(d: &[u8]) -> Res<Plan> {
        let mut r = Cursor { d, pos: 0 };
        if r.take(8)? != MAGIC {
            return Err("not a plan file".into());
        }
        let (version, machine) = (r.u32()?, r.u32()?);
        if version != VERSION || machine != super::elf::EM_X86_64 as u32 {
            return Err(format!(
                "plan version {version} for machine {machine}: not readable here"
            ));
        }
        let sha256 = r.take(32)?.try_into().unwrap();
        let (cell, tramp_vaddr, tramp_len) = (r.u64()?, r.u64()?, r.u64()? as usize);
        let (np, ns, nc, nb) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
        let build = String::from_utf8(r.take(nb as usize)?.to_vec())
            .map_err(|_| "plan: build is not text")?;
        let mut runs = vec![];
        for _ in 0..np {
            runs.push((r.u64()?, r.u64()? as usize, r.u64()? as usize));
        }
        let mut sites = vec![];
        for _ in 0..ns {
            let (addr, tramp) = (r.u64()?, r.u32()?);
            let (tramp_len, trap, copy) = (r.u16()?, r.u16()?, r.u16()?);
            let b = r.take(2)?;
            sites.push(Site {
                addr,
                len: b[0],
                kind: b[1],
                tramp,
                tramp_len,
                trap,
                copy,
            });
        }
        let mut counts = vec![];
        for _ in 0..nc {
            let n = r.u16()? as usize;
            let k = String::from_utf8(r.take(n)?.to_vec())
                .map_err(|_| "plan: count name is not text")?;
            counts.push((k, r.u64()?));
        }
        let mut end = r.pos;
        let mut pages: Vec<Pages> = vec![];
        for (vaddr, len, off) in runs {
            let bytes = Cursor { d, pos: off }.take(len)?.to_vec();
            if off % PAGE as usize != 0
                || off < end
                || vaddr % PAGE != 0
                || len % PAGE as usize != 0
                || vaddr.checked_add(len as u64).is_none()
                || pages
                    .last()
                    .is_some_and(|p| p.vaddr + p.bytes.len() as u64 > vaddr)
            {
                return Err("plan: a page run is not page-aligned, in order and disjoint".into());
            }
            end = off + len;
            pages.push(Pages { vaddr, bytes });
        }
        let toff = align(end);
        let tramp = Cursor { d, pos: toff }.take(tramp_len)?.to_vec();
        if toff + tramp_len != d.len() {
            return Err("plan: trailing bytes".into());
        }
        Ok(Plan {
            sha256,
            build,
            cell,
            pages,
            tramp_vaddr,
            tramp,
            sites,
            counts,
        })
    }
}

struct Cursor<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        let s = self
            .pos
            .checked_add(n)
            .and_then(|e| self.d.get(self.pos..e))
            .ok_or("plan: truncated")?;
        self.pos += n;
        Ok(s)
    }
    fn u16(&mut self) -> Res<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Res<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}
