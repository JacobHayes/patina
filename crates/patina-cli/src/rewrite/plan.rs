//! The plan file: what a runtime maps in place of a file's text. A plain data format with no
//! decision in it: the patched text pages, the trampolines, one row per patch saying where its
//! trampoline is and what a trap there means, and one row per address the runtime answers in
//! place (a `cpuid`, an interior boundary of a group). Addresses are the file's own (link-time)
//! virtual addresses; a loader adds the load bias.
//!
//! ```text
//! header   magic "PATPLAN\0", version, ELF machine, SHA-256 of the file, cell address,
//!          trampolines' address and span, counts of the tables below, the patina build
//! pages    (address, length, offset in this file) per run of patched pages
//! tramps   (offset in the span, length, offset in this file) per run of trampoline pages
//! sites    (address, trampoline offset, trampoline length, trap offset, copy offset,
//!          patch length, kind) in order of their trampolines
//! entries  (address, trampoline offset, kind) in address order
//! counts   (name, value): the rewrite's report
//! data     page runs then trampoline runs, each at a page-aligned offset of this file
//! ```
//!
//! The trampolines' span is sparse: a page of it with no byte of a trampoline is not stored and
//! not mapped (a trampoline whose patch constrains its address can sit megabytes past the
//! others, `points.rs`).

use crate::cli::Res;

pub const MAGIC: &[u8; 8] = b"PATPLAN\0";
pub const VERSION: u32 = 2;
pub const PAGE: u64 = 4096;
/// The count's cell, which the runtime maps: one word below 2 GiB, so `dec qword [abs32]`
/// reaches it from any image.
pub const CELL: u64 = proto::plan::CELL;

/// The trampoline counts, then jumps to the patched branch's or call's original target (the
/// patched instruction now goes to the trampoline instead).
pub const KIND_JUMP: u8 = proto::plan::KIND_JUMP;
/// The trampoline counts, then runs a copy of the patched instructions, then jumps to the
/// instruction after them (the patch is a jump to the trampoline).
pub const KIND_BEFORE: u8 = proto::plan::KIND_BEFORE;
/// Entries: a `cpuid` answered by the runtime (`proto::plan::KIND_CPUID`), and an interior
/// boundary of a group, resumed at its copy (`proto::plan::KIND_INTERIOR`).
pub const KIND_CPUID: u8 = proto::plan::KIND_CPUID;
pub const KIND_INTERIOR: u8 = proto::plan::KIND_INTERIOR;
/// `copy` of a site without a copied instruction.
pub const NO_COPY: u16 = u16::MAX;
/// The bytes that fault in 64-bit user mode whatever follows them, and that are not prefixes:
/// `int3` (`SIGTRAP`), `hlt`, `cli`, `sti` and the port I/O instructions (`SIGSEGV`: a process
/// has no I/O permission; the sandbox refuses `iopl` and `ioperm`). Every interior boundary of
/// a group holds one.
pub const TRAP_BYTES: [u8; 16] = [
    0x6c, 0x6d, 0x6e, 0x6f, 0xcc, 0xe4, 0xe5, 0xe6, 0xe7, 0xec, 0xed, 0xee, 0xef, 0xf4, 0xfa, 0xfb,
];
/// The legacy prefix that pads a group's jump (`2e`, a segment override, ignored on a near
/// `jmp` in 64-bit mode) when that moves its displacement's high byte off a boundary.
pub const PAD_PREFIX: u8 = 0x2e;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    /// The patch: address and length (one instruction, or the group's).
    pub addr: u64,
    pub len: u8,
    pub kind: u8,
    /// The trampoline: offset in the span and length.
    pub tramp: u32,
    pub tramp_len: u16,
    /// Offsets in the trampoline: the trap (a point at this site) and the copy of the patched
    /// instructions, whose original address is `addr`.
    pub trap: u16,
    pub copy: u16,
}

/// An address the runtime answers in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub addr: u64,
    /// `KIND_INTERIOR`: the offset in the trampolines' span to resume at; else 0.
    pub to: u32,
    pub kind: u8,
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
    /// The trampolines' span, a multiple of the page size; zero where no trampoline is.
    pub tramp: Vec<u8>,
    pub sites: Vec<Site>,
    pub entries: Vec<Entry>,
    pub counts: Vec<(String, u64)>,
}

fn align(n: usize) -> usize {
    n.next_multiple_of(PAGE as usize)
}

/// The runs of pages of `span` that hold a nonzero byte: (offset, length).
fn tramp_runs(span: &[u8]) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = vec![];
    for (k, p) in span.chunks(PAGE as usize).enumerate() {
        if p.iter().all(|&b| b == 0) {
            continue;
        }
        let o = k * PAGE as usize;
        match out.last_mut() {
            Some((s, n)) if *s + *n == o => *n += PAGE as usize,
            _ => out.push((o, PAGE as usize)),
        }
    }
    out
}

impl Plan {
    pub fn to_bytes(&self) -> Vec<u8> {
        let truns = tramp_runs(&self.tramp);
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
            truns.len(),
            self.sites.len(),
            self.entries.len(),
            self.counts.len(),
            self.build.len(),
        ] {
            h.extend_from_slice(&(n as u32).to_le_bytes());
        }
        h.extend_from_slice(self.build.as_bytes());
        let dir = h.len();
        h.resize(dir + 24 * (self.pages.len() + truns.len()), 0);
        for s in &self.sites {
            h.extend_from_slice(&s.addr.to_le_bytes());
            h.extend_from_slice(&s.tramp.to_le_bytes());
            for v in [s.tramp_len, s.trap, s.copy] {
                h.extend_from_slice(&v.to_le_bytes());
            }
            h.extend_from_slice(&[s.len, s.kind]);
        }
        for e in &self.entries {
            h.extend_from_slice(&e.addr.to_le_bytes());
            h.extend_from_slice(&e.to.to_le_bytes());
            h.extend_from_slice(&[e.kind, 0, 0, 0]);
        }
        for (k, v) in &self.counts {
            h.extend_from_slice(&(k.len() as u16).to_le_bytes());
            h.extend_from_slice(k.as_bytes());
            h.extend_from_slice(&v.to_le_bytes());
        }
        let mut off = align(h.len());
        let rows = self
            .pages
            .iter()
            .map(|p| (p.vaddr, p.bytes.len()))
            .chain(truns.iter().map(|&(o, n)| (o as u64, n)));
        for (k, (a, n)) in rows.enumerate() {
            let e = dir + 24 * k;
            h[e..e + 8].copy_from_slice(&a.to_le_bytes());
            h[e + 8..e + 16].copy_from_slice(&(n as u64).to_le_bytes());
            h[e + 16..e + 24].copy_from_slice(&(off as u64).to_le_bytes());
            off = align(off + n);
        }
        let mut out = h;
        let data = self
            .pages
            .iter()
            .map(|p| &p.bytes[..])
            .chain(truns.iter().map(|&(o, n)| &self.tramp[o..o + n]));
        for b in data {
            out.resize(align(out.len()), 0);
            out.extend_from_slice(b);
        }
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
        let (cell, tramp_vaddr, span) = (r.u64()?, r.u64()?, r.u64()? as usize);
        let (np, nt, ns, ne, nc, nb) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?, r.u32()?);
        let build = String::from_utf8(r.take(nb as usize)?.to_vec())
            .map_err(|_| "plan: build is not text")?;
        let mut runs = vec![];
        for _ in 0..np + nt {
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
        let mut entries = vec![];
        for _ in 0..ne {
            let (addr, to) = (r.u64()?, r.u32()?);
            let b = r.take(4)?;
            entries.push(Entry {
                addr,
                to,
                kind: b[0],
            });
        }
        let mut counts = vec![];
        for _ in 0..nc {
            let n = r.u16()? as usize;
            let k = String::from_utf8(r.take(n)?.to_vec())
                .map_err(|_| "plan: count name is not text")?;
            counts.push((k, r.u64()?));
        }
        if span % PAGE as usize != 0 {
            return Err("plan: the trampolines' span is not whole pages".into());
        }
        let mut end = r.pos;
        let mut pages: Vec<Pages> = vec![];
        let mut tramp = vec![0u8; span];
        let mut tlast = 0;
        for (k, (a, len, off)) in runs.into_iter().enumerate() {
            let bytes = Cursor { d, pos: off }.take(len)?;
            let text = k < np as usize;
            let ordered = if text {
                pages
                    .last()
                    .is_none_or(|p| p.vaddr + p.bytes.len() as u64 <= a)
            } else {
                a as usize >= tlast && a as usize + len <= span
            };
            if off % PAGE as usize != 0
                || off < end
                || a % PAGE != 0
                || len % PAGE as usize != 0
                || len == 0
                || a.checked_add(len as u64).is_none()
                || !ordered
            {
                return Err("plan: a page run is not page-aligned, in order and disjoint".into());
            }
            end = off + len;
            if text {
                pages.push(Pages {
                    vaddr: a,
                    bytes: bytes.to_vec(),
                });
            } else {
                tramp[a as usize..a as usize + len].copy_from_slice(bytes);
                tlast = a as usize + len;
            }
        }
        if end.max(r.pos) != d.len() {
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
            entries,
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
