//! The facts of an x86_64 or arm64 ELF file that the rewriter and its verifier start from: the
//! executable bytes, the load segments, and where functions start and end (the entry point,
//! function symbols, unwind entries, relocated pointers). Facts only: what is code is decided in
//! `code.rs` (the rewriter) and again, separately, in `verify.rs`.

use super::plan::PAGE;
use crate::cli::Res;
use sha2::{Digest, Sha256};

pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
const PT_GNU_PROPERTY: u32 = 0x6474_e553;
const PF_X: u32 = 1;

/// One `PT_LOAD`.
#[derive(Clone, Copy, Debug)]
pub struct Load {
    pub vaddr: u64,
    pub memsz: u64,
    pub off: u64,
    pub filesz: u64,
    pub flags: u32,
    /// `p_align`.
    pub align: u64,
}

/// An executable range of the file: a `SHF_EXECINSTR` section, or an executable segment when
/// the file has no section headers.
#[derive(Clone, Copy, Debug)]
pub struct Text {
    pub addr: u64,
    pub off: usize,
    pub len: usize,
}

pub struct Elf<'a> {
    pub data: &'a [u8],
    pub sha256: [u8; 32],
    /// `EM_X86_64` or `EM_AARCH64`.
    pub machine: u16,
    pub phoff: usize,
    pub phnum: usize,
    /// `ET_EXEC`: loaded at its link-time addresses, so code may name its addresses absolutely.
    pub exec: bool,
    pub loads: Vec<Load>,
    /// Sorted by address, not overlapping.
    pub text: Vec<Text>,
    /// Function starts inside `text`, sorted, without duplicates.
    pub anchors: Vec<u64>,
    /// Function extents `[start, end)` from unwind entries and sized symbols, sorted.
    pub extents: Vec<(u64, u64)>,
    /// arm64: data inside text by the assembler's mapping symbols (`$d` up to the next `$x`
    /// or `$d`, or the end of its section), sorted.
    pub asm_data: Vec<(u64, u64)>,
    /// arm64: the file's GNU property note asks for branch target identification (its
    /// executable pages are mapped guarded).
    pub bti: bool,
}

/// `GNU_PROPERTY_AARCH64_FEATURE_1_AND` with its BTI bit, in the `NT_GNU_PROPERTY_TYPE_0`
/// note of a `PT_GNU_PROPERTY` segment.
fn property_bti(d: &[u8], seg: &Load) -> bool {
    let (mut o, end) = (
        seg.off as usize,
        seg.off.saturating_add(seg.filesz) as usize,
    );
    while o + 16 <= end {
        let (Ok(nsz), Ok(dsz), Ok(typ)) = (u32_at(d, o), u32_at(d, o + 4), u32_at(d, o + 8)) else {
            return false;
        };
        let desc = o + 12 + (nsz as usize).next_multiple_of(4);
        if typ == 5 && d.get(o + 12..o + 16) == Some(b"GNU\0") {
            let mut p = desc;
            while p + 8 <= desc + dsz as usize {
                let (Ok(pt), Ok(sz)) = (u32_at(d, p), u32_at(d, p + 4)) else {
                    return false;
                };
                if pt == 0xc000_0000 {
                    return u32_at(d, p + 8).is_ok_and(|f| f & 1 != 0);
                }
                p += 8 + (sz as usize).next_multiple_of(8);
            }
        }
        o = desc + (dsz as usize).next_multiple_of(8);
    }
    false
}

fn get<const N: usize>(d: &[u8], o: usize) -> Res<[u8; N]> {
    o.checked_add(N)
        .and_then(|e| d.get(o..e))
        .map(|s| s.try_into().unwrap())
        .ok_or_else(|| format!("truncated ELF file (offset {o:#x})"))
}
pub fn u16_at(d: &[u8], o: usize) -> Res<u16> {
    get::<2>(d, o).map(u16::from_le_bytes)
}
pub fn u32_at(d: &[u8], o: usize) -> Res<u32> {
    get::<4>(d, o).map(u32::from_le_bytes)
}
pub fn u64_at(d: &[u8], o: usize) -> Res<u64> {
    get::<8>(d, o).map(u64::from_le_bytes)
}

struct Section {
    name: u32,
    typ: u32,
    link: u32,
    flags: u64,
    addr: u64,
    off: usize,
    size: usize,
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Res<Elf<'a>> {
        Elf::parse_hashed(data, Sha256::digest(data).into())
    }

    /// `parse`, with the SHA-256 of `data` already known.
    pub fn parse_hashed(data: &'a [u8], sha256: [u8; 32]) -> Res<Elf<'a>> {
        if data.len() < 64 || &data[..4] != b"\x7fELF" {
            return Err("not an ELF file".into());
        }
        if data[4] != 2 || data[5] != 1 {
            return Err("not a 64-bit little-endian ELF file".into());
        }
        let machine = u16_at(data, 0x12)?;
        if machine != EM_X86_64 && machine != EM_AARCH64 {
            return Err(format!(
                "unsupported architecture: ELF machine {machine}, not x86_64 or arm64"
            ));
        }
        let entry = u64_at(data, 0x18)?;
        let phoff = u64_at(data, 0x20)? as usize;
        let (phentsize, phnum) = (u16_at(data, 0x36)? as usize, u16_at(data, 0x38)? as usize);
        if phentsize != 56 {
            return Err("unexpected program header size".into());
        }
        let mut loads = vec![];
        let mut eh_hdr = None;
        let mut bti = false;
        for i in 0..phnum {
            let p = phoff + i * 56;
            let (typ, flags) = (u32_at(data, p)?, u32_at(data, p + 4)?);
            let l = Load {
                off: u64_at(data, p + 8)?,
                vaddr: u64_at(data, p + 0x10)?,
                filesz: u64_at(data, p + 0x20)?,
                memsz: u64_at(data, p + 0x28)?,
                flags,
                align: u64_at(data, p + 0x30)?,
            };
            match typ {
                PT_LOAD => {
                    if l.off
                        .checked_add(l.filesz)
                        .is_none_or(|e| e > data.len() as u64)
                        || l.filesz > l.memsz
                    {
                        return Err("a PT_LOAD outside the file".into());
                    }
                    loads.push(l)
                }
                PT_GNU_EH_FRAME => eh_hdr = Some(l),
                PT_GNU_PROPERTY if machine == EM_AARCH64 => bti = property_bti(data, &l),
                _ => {}
            }
        }
        loads.sort_by_key(|l| l.vaddr);
        let mut e = Elf {
            data,
            sha256,
            machine,
            phoff,
            phnum,
            exec: u16_at(data, 0x10)? == 2,
            loads,
            text: vec![],
            anchors: vec![],
            extents: vec![],
            asm_data: vec![],
            bti,
        };
        let secs = e.sections()?;
        let strtab = secs.get(u16_at(data, 0x3e)? as usize).map(|s| s.off);
        let name = |s: &Section| -> &[u8] {
            let Some(o) = strtab.and_then(|t| t.checked_add(s.name as usize)) else {
                return b"";
            };
            let n = data.get(o..).unwrap_or(&[]);
            &n[..n.iter().position(|&b| b == 0).unwrap_or(n.len())]
        };
        // SHF_ALLOC | SHF_EXECINSTR, SHT_PROGBITS
        for s in &secs {
            if s.typ == 1 && s.flags & 6 == 6 && s.size > 0 && s.off + s.size <= data.len() {
                e.text.push(Text {
                    addr: s.addr,
                    off: s.off,
                    len: s.size,
                });
            }
        }
        // Without section headers, the executable segments; their relocated pointers are not
        // anchors then (below), as the segments may hold read-only data too.
        if secs.is_empty() {
            for l in &e.loads {
                if l.flags & PF_X != 0 && l.filesz > 0 {
                    let t = Text {
                        addr: l.vaddr,
                        off: l.off as usize,
                        len: l.filesz as usize,
                    };
                    e.text.push(t);
                }
            }
        }
        e.text.sort_by_key(|t| t.addr);
        if e.text
            .windows(2)
            .any(|w| w[0].addr + w[0].len as u64 > w[1].addr)
        {
            return Err("overlapping executable sections".into());
        }
        let (mut anchors, mut extents) = (vec![entry], vec![]);
        // arm64 mapping symbols: (address, is data).
        let mut maps: Vec<(u64, bool)> = vec![];
        for s in &secs {
            match s.typ {
                // SHT_SYMTAB, SHT_DYNSYM: STT_FUNC and STT_GNU_IFUNC, defined
                2 | 11 => {
                    let names = secs.get(s.link as usize).map(|t| t.off);
                    for k in 0..s.size / 24 {
                        let o = s.off + k * 24;
                        let (info, shndx) = (data[o + 4], u16_at(data, o + 6)?);
                        let (value, size) = (u64_at(data, o + 8)?, u64_at(data, o + 16)?);
                        if machine == EM_AARCH64 && info & 0xf == 0 && shndx != 0 {
                            let n = names
                                .and_then(|t| t.checked_add(u32_at(data, o).ok()? as usize))
                                .and_then(|n| data.get(n..n + 3));
                            if let Some([b'$', c @ (b'd' | b'x'), 0 | b'.']) = n {
                                maps.push((value, *c == b'd'));
                            }
                        }
                        if matches!(info & 0xf, 2 | 10) && shndx != 0 && value != 0 {
                            anchors.push(value);
                            if size > 0 {
                                extents.push((value, value.saturating_add(size)));
                            }
                        }
                    }
                }
                // SHT_RELA, SHT_RELR, loaded
                4 if s.flags & 2 != 0 => e.rela(s.off, s.size, &mut anchors)?,
                19 if s.flags & 2 != 0 => e.relr(s.off, s.size, &mut anchors)?,
                _ => {}
            }
        }
        // The unwind entries: the `.eh_frame` section, else through `PT_GNU_EH_FRAME`.
        let eh = match secs.iter().find(|s| name(s) == b".eh_frame") {
            Some(s) => Some((s.addr, s.off, s.size)),
            None => eh_hdr.and_then(|h| e.eh_frame_from_hdr(h)),
        };
        if let Some((addr, off, size)) = eh {
            let bytes = data.get(off..off.saturating_add(size)).unwrap_or(&[]);
            eh_frame(bytes, addr, &mut anchors, &mut extents);
        }
        maps.sort_unstable();
        maps.dedup();
        for (k, &(a, d)) in maps.iter().enumerate() {
            let Some(t) = e.text_at(a) else { continue };
            let end = t.addr + t.len as u64;
            let next = maps.get(k + 1).map_or(end, |n| n.0.min(end));
            if d && a < next {
                e.asm_data.push((a, next));
            }
        }
        anchors.retain(|&a| e.in_text(a));
        anchors.sort_unstable();
        anchors.dedup();
        extents.retain(|&(lo, hi)| lo < hi && e.in_text(lo));
        extents.sort_unstable();
        extents.dedup();
        e.anchors = anchors;
        e.extents = extents;
        Ok(e)
    }

    fn sections(&self) -> Res<Vec<Section>> {
        let d = self.data;
        let shoff = u64_at(d, 0x28)? as usize;
        let (shentsize, shnum) = (u16_at(d, 0x3a)? as usize, u16_at(d, 0x3c)? as usize);
        if shoff == 0 || shnum == 0 || shentsize != 64 {
            return Ok(vec![]);
        }
        let mut out = vec![];
        for i in 0..shnum {
            let s = shoff + i * 64;
            let typ = u32_at(d, s + 4)?;
            let (off, size) = (u64_at(d, s + 0x18)? as usize, u64_at(d, s + 0x20)? as usize);
            // SHT_NOBITS holds no file bytes, and its offset need not lie within the file (a
            // tool that moved the section headers may leave it past the end).
            let (off, size) = if typ == 8 {
                (off.min(d.len()), 0)
            } else {
                (off, size)
            };
            if off.checked_add(size).is_none_or(|e| e > d.len()) {
                return Err(format!("section {i} outside the file"));
            }
            out.push(Section {
                name: u32_at(d, s)?,
                typ,
                link: u32_at(d, s + 0x28)?,
                flags: u64_at(d, s + 8)?,
                addr: u64_at(d, s + 0x10)?,
                off,
                size,
            });
        }
        Ok(out)
    }

    /// The text range holding `a`.
    pub fn text_at(&self, a: u64) -> Option<&Text> {
        let i = self.text.partition_point(|t| t.addr <= a).checked_sub(1)?;
        let t = &self.text[i];
        (a < t.addr + t.len as u64).then_some(t)
    }

    /// Whether `lo` and `hi` (`lo <= hi`) are in one function: one unwind entry or sized
    /// symbol holds both, or none of the function starts `starts` (sorted) lies in `(lo, hi]`.
    pub fn one_function(&self, starts: &[u64], lo: u64, hi: u64) -> bool {
        let e = self.extents.partition_point(|&(s, _)| s <= lo);
        let held = e > 0 && self.extents[e - 1].1 > hi;
        let a = starts.partition_point(|&s| s <= hi);
        held || a == 0 || starts[a - 1] <= lo
    }

    pub fn in_text(&self, a: u64) -> bool {
        self.text_at(a).is_some()
    }

    pub fn bytes(&self, t: &Text) -> &'a [u8] {
        &self.data[t.off..t.off + t.len]
    }

    /// The function holding the byte at file offset `off`: the sized `STT_FUNC` symbol that
    /// holds its address, else the nearest one below it (from `.symtab`, else `.dynsym`).
    pub fn function_at_offset(&self, off: u64) -> Option<String> {
        let l = self
            .loads
            .iter()
            .find(|l| off >= l.off && off - l.off < l.filesz)?;
        let a = l.vaddr + (off - l.off);
        let d = self.data;
        let secs = self.sections().ok()?;
        let mut best: Option<(u64, bool, usize)> = None;
        let tables = secs.iter().filter(|s| s.typ == 2);
        for s in tables.chain(secs.iter().filter(|s| s.typ == 11)) {
            let names = secs.get(s.link as usize)?.off;
            for k in 0..s.size / 24 {
                let o = s.off + k * 24;
                let (info, shndx) = (d[o + 4], u16_at(d, o + 6).ok()?);
                let (value, size) = (u64_at(d, o + 8).ok()?, u64_at(d, o + 16).ok()?);
                if !matches!(info & 0xf, 2 | 10) || shndx == 0 || value > a {
                    continue;
                }
                let holds = a - value < size;
                let better = match best {
                    None => true,
                    Some((v, h, _)) => (holds && !h) || (holds == h && value > v),
                };
                if better {
                    best = Some((value, holds, names + u32_at(d, o).ok()? as usize));
                }
            }
            if best.is_some() {
                break;
            }
        }
        let n = d.get(best?.2..)?;
        let n = &n[..n.iter().position(|&b| b == 0)?];
        (!n.is_empty()).then(|| String::from_utf8_lossy(n).into_owned())
    }

    /// Link virtual address corresponding to executable mapping at page-aligned file offset `off`.
    pub fn vaddr_at_offset(&self, off: u64) -> Option<u64> {
        self.loads
            .iter()
            .find(|l| {
                l.flags & PF_X != 0
                    && (l.off & !(PAGE - 1)) <= off
                    && off < l.off.saturating_add(l.filesz.max(1))
            })
            .map(|l| l.vaddr.wrapping_sub(l.off).wrapping_add(off))
    }

    /// All defined function symbols `(vaddr, size, name)` from `.symtab` and `.dynsym`, sorted
    /// by address for fast offline symbolization (`patina profile`).
    pub fn symbols(&self) -> Vec<(u64, u64, String)> {
        let d = self.data;
        let Ok(secs) = self.sections() else {
            return vec![];
        };
        let mut out: Vec<(u64, u64, u8, String)> = vec![];
        // Priority 0 for .symtab (SHT_SYMTAB = 2), 1 for .dynsym (SHT_DYNSYM = 11).
        for (prio, typ) in [(0u8, 2u32), (1u8, 11u32)] {
            for s in secs.iter().filter(|s| s.typ == typ) {
                let Some(names) = secs.get(s.link as usize).map(|t| t.off) else {
                    continue;
                };
                for k in 0..s.size / 24 {
                    let o = s.off + k * 24;
                    let (Ok(shndx), Ok(value), Ok(size), Ok(name_off)) = (
                        u16_at(d, o + 6),
                        u64_at(d, o + 8),
                        u64_at(d, o + 16),
                        u32_at(d, o),
                    ) else {
                        continue;
                    };
                    let info = d[o + 4];
                    if !matches!(info & 0xf, 2 | 10) || shndx == 0 || value == 0 {
                        continue;
                    }
                    let Some(raw) = d.get(names.saturating_add(name_off as usize)..) else {
                        continue;
                    };
                    let Some(end) = raw.iter().position(|&b| b == 0) else {
                        continue;
                    };
                    if end == 0 {
                        continue;
                    }
                    let name = String::from_utf8_lossy(&raw[..end]).into_owned();
                    out.push((value, size, prio, name));
                }
            }
        }
        // Sort by address asc, preferring .symtab (prio 0) and larger non-zero size.
        out.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.2.cmp(&b.2))
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| a.3.cmp(&b.3))
        });
        out.dedup_by_key(|x| x.0);
        out.into_iter().map(|(v, sz, _, n)| (v, sz, n)).collect()
    }

    /// The file offset of the loaded byte at `vaddr`, when the file holds it.
    pub fn file_offset(&self, vaddr: u64) -> Option<usize> {
        let l = self
            .loads
            .iter()
            .find(|l| vaddr >= l.vaddr && vaddr - l.vaddr < l.filesz)?;
        Some((l.off + (vaddr - l.vaddr)) as usize)
    }

    /// The page at `vaddr` (page-aligned) as an executable segment maps it from the file.
    pub fn original_page(&self, vaddr: u64) -> Option<Vec<u8>> {
        let l = self.loads.iter().find(|l| {
            l.flags & PF_X != 0
                && vaddr.saturating_add(PAGE) > l.vaddr
                && vaddr < l.vaddr + l.filesz
        })?;
        let off = usize::try_from(l.off.checked_add(vaddr)?.checked_sub(l.vaddr)?).ok()?;
        let mut page = vec![0; PAGE as usize];
        let src = self.data.get(off..)?;
        let n = src.len().min(PAGE as usize);
        page[..n].copy_from_slice(&src[..n]);
        Some(page)
    }

    /// The end of the highest load segment in memory.
    pub fn image_end(&self) -> u64 {
        self.loads
            .iter()
            .map(|l| l.vaddr + l.memsz)
            .max()
            .unwrap_or(0)
    }

    pub fn image_start(&self) -> u64 {
        self.loads.iter().map(|l| l.vaddr).min().unwrap_or(0)
    }

    fn word(&self, vaddr: u64) -> Option<u64> {
        let o = self.file_offset(vaddr)?;
        u64_at(self.data, o).ok()
    }

    /// `R_X86_64_RELATIVE` and `R_X86_64_IRELATIVE` (arm64: `R_AARCH64_RELATIVE`,
    /// `R_AARCH64_IRELATIVE`): the addend is a code or data address.
    fn rela(&self, off: usize, size: usize, out: &mut Vec<u64>) -> Res<()> {
        let types: [u64; 2] = if self.machine == EM_AARCH64 {
            [1027, 1032]
        } else {
            [8, 37]
        };
        for k in 0..size / 24 {
            let o = off + k * 24;
            if types.contains(&(u64_at(self.data, o + 8)? & 0xffff_ffff)) {
                out.push(u64_at(self.data, o + 16)?);
            }
        }
        Ok(())
    }

    /// Packed relative relocations: the address is in place, in the word relocated.
    fn relr(&self, off: usize, size: usize, out: &mut Vec<u64>) -> Res<()> {
        let mut base = 0u64;
        for k in 0..size / 8 {
            let e = u64_at(self.data, off + k * 8)?;
            if e & 1 == 0 {
                out.extend(self.word(e));
                base = e.wrapping_add(8);
            } else {
                for bit in 0..63 {
                    if (e >> (bit + 1)) & 1 != 0 {
                        out.extend(self.word(base.wrapping_add(8 * bit)));
                    }
                }
                base = base.wrapping_add(63 * 8);
            }
        }
        Ok(())
    }

    /// `.eh_frame_hdr`'s `eh_frame_ptr`: the `.eh_frame` section's address; its size is up to
    /// the end of the segment holding it (the walk stops at the terminator).
    fn eh_frame_from_hdr(&self, h: Load) -> Option<(u64, usize, usize)> {
        let o = h.off as usize;
        let hdr = self.data.get(o..o + 4)?;
        let mut r = Reader {
            d: self.data,
            pos: o + 4,
            vaddr: h.vaddr - o as u64,
        };
        let addr = r.encoded(hdr[1])?;
        let off = self.file_offset(addr)?;
        let l = self
            .loads
            .iter()
            .find(|l| addr >= l.vaddr && addr - l.vaddr < l.filesz)?;
        Some((addr, off, (l.off + l.filesz) as usize - off))
    }
}

/// A cursor over bytes whose file offset `pos` sits at address `vaddr + pos`.
struct Reader<'a> {
    d: &'a [u8],
    pos: usize,
    vaddr: u64,
}

impl Reader<'_> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.d.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        let b = self.d.get(self.pos..self.pos + N)?.try_into().ok()?;
        self.pos += N;
        Some(b)
    }
    fn uleb(&mut self) -> Option<u64> {
        let (mut v, mut shift) = (0u64, 0);
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= ((b & 0x7f) as u64) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
    }
    fn sleb(&mut self) -> Option<i64> {
        let (mut v, mut shift) = (0i64, 0);
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= ((b & 0x7f) as i64) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1i64 << shift;
                }
                return Some(v);
            }
        }
    }
    /// A `DW_EH_PE_*` encoded pointer: absolute or PC-relative (the encodings `.eh_frame`
    /// uses for addresses); any other application is refused.
    fn encoded(&mut self, enc: u8) -> Option<u64> {
        if enc == 0xff {
            return None;
        }
        let at = self.vaddr.wrapping_add(self.pos as u64);
        let v = match enc & 0x0f {
            0x00 | 0x04 | 0x0c => u64::from_le_bytes(self.fixed()?),
            0x01 => self.uleb()?,
            0x02 => u16::from_le_bytes(self.fixed()?) as u64,
            0x03 => u32::from_le_bytes(self.fixed()?) as u64,
            0x09 => self.sleb()? as u64,
            0x0a => i16::from_le_bytes(self.fixed()?) as i64 as u64,
            0x0b => i32::from_le_bytes(self.fixed()?) as i64 as u64,
            _ => return None,
        };
        // Not DW_EH_PE_indirect (0x80): the pointer would be at the address, not be it.
        match enc & 0xf0 {
            0x00 => Some(v),
            0x10 => Some(v.wrapping_add(at)),
            _ => None,
        }
    }
}

/// The pointer encoding of a CIE's FDEs (augmentation `R`; absolute without one).
fn cie_encoding(r: &mut Reader) -> Option<u8> {
    let version = r.u8()?;
    let aug_start = r.pos;
    while r.u8()? != 0 {}
    let aug = r.d[aug_start..r.pos - 1].to_vec();
    if aug.starts_with(b"eh") {
        r.pos += 8;
    }
    r.uleb()?;
    r.sleb()?;
    if version == 1 {
        r.u8()?;
    } else {
        r.uleb()?;
    }
    let mut enc = 0;
    if aug.first() == Some(&b'z') {
        r.uleb()?;
        for &c in &aug[1..] {
            match c {
                b'R' => enc = r.u8()?,
                b'L' => {
                    r.u8()?;
                }
                b'P' => {
                    let pe = r.u8()?;
                    r.encoded(pe & 0x7f)?;
                }
                b'S' | b'B' | b'G' => {}
                _ => return None,
            }
        }
    }
    Some(enc)
}

/// Every FDE of an `.eh_frame` section at `addr`: its start is an anchor and its range an
/// extent. An entry that cannot be read ends the walk (what was read stays).
fn eh_frame(d: &[u8], addr: u64, anchors: &mut Vec<u64>, extents: &mut Vec<(u64, u64)>) {
    let mut encs = std::collections::BTreeMap::new();
    let mut pos = 0usize;
    while pos + 4 <= d.len() {
        let len32 = u32::from_le_bytes(d[pos..pos + 4].try_into().unwrap());
        if len32 == 0 {
            break;
        }
        let (len, hdr) = if len32 == 0xffff_ffff {
            let Some(l) = d.get(pos + 4..pos + 12) else {
                break;
            };
            (u64::from_le_bytes(l.try_into().unwrap()) as usize, 12)
        } else {
            (len32 as usize, 4)
        };
        let start = pos + hdr;
        let Some(end) = start.checked_add(len).filter(|&e| e <= d.len() && len >= 4) else {
            break;
        };
        let body = &d[..end];
        let id = u32::from_le_bytes(d[start..start + 4].try_into().unwrap()) as usize;
        let mut r = Reader {
            d: body,
            pos: start + 4,
            vaddr: addr,
        };
        if id == 0 {
            if let Some(enc) = cie_encoding(&mut r) {
                encs.insert(pos, enc);
            }
        } else if let Some(&enc) = start.checked_sub(id).and_then(|c| encs.get(&c)) {
            let begin = r.encoded(enc);
            let range = r.encoded(enc & 0x0f);
            if let (Some(b), Some(n)) = (begin, range) {
                anchors.push(b);
                extents.push((b, b.saturating_add(n)));
            }
        }
        pos = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A NOBITS section takes no bytes of the file, so its offset may lie past the file's end
    /// (as after patchelf grew a Go binary's headers): the file still parses.
    #[test]
    fn a_nobits_section_may_start_past_the_end_of_the_file() {
        let mut d = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let shoff = u64_at(&d, 0x28).unwrap() as usize;
        let shnum = u16_at(&d, 0x3c).unwrap() as usize;
        let i = (0..shnum)
            .find(|i| u32_at(&d, shoff + i * 64 + 4).unwrap() == 8)
            .expect("a NOBITS section");
        let past = (d.len() as u64 + 0x10000).to_le_bytes();
        d[shoff + i * 64 + 0x18..][..8].copy_from_slice(&past);
        if let Err(e) = Elf::parse(&d) {
            panic!("{e}");
        }
    }
}
