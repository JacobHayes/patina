//! A plan applied to a copy of its file, to run natively without Patina (the differential
//! harness): the plan's pages written over the text, the trampolines as one more read+execute
//! `PT_LOAD` (which also holds the program headers, moved there to make room), and a private
//! cell in a read+write `PT_LOAD` after it. The plan's counts address the one cell at a fixed
//! address that the runtime will provide; here each count is re-encoded, same length, to
//! address this image's own cell (`dec qword [rip+cell]; nop`), so the copy needs nothing
//! mapped before its first instruction runs: executables and shared libraries alike.

use super::elf::{u32_at, Elf};
use super::plan::{Plan, PAGE};
use crate::cli::Res;

/// The patched copy. Its cell starts at `events`: with enough, it runs as the original; with
/// few, it stops on a trampoline's `ud2` once they run out (`SIGILL`).
pub fn apply(data: &[u8], plan: &Plan, events: u64) -> Res<Vec<u8>> {
    let elf = Elf::parse(data)?;
    if !plan.tramp_vaddr.is_multiple_of(PAGE) {
        return Err("trampolines not page-aligned".into());
    }
    let mut out = data.to_vec();
    for p in &plan.pages {
        for (k, page) in p.bytes.chunks(PAGE as usize).enumerate() {
            let v = p.vaddr + k as u64 * PAGE;
            let l = elf
                .loads
                .iter()
                .find(|l| l.flags & 1 != 0 && v + PAGE > l.vaddr && v < l.vaddr + l.filesz)
                .ok_or_else(|| format!("plan page {v:#x} is not in an executable segment"))?;
            let off = (l.off as i64 + (v as i64 - l.vaddr as i64)) as usize;
            let end = (off + PAGE as usize).min(out.len());
            out[off..end].copy_from_slice(&page[..end - off]);
        }
    }
    // Segment 1: trampolines, then the program headers with two more entries.
    let mut seg = plan.tramp.clone();
    seg.resize(seg.len().next_multiple_of(8), 0xcc);
    let (ph_at, ph_len) = (seg.len() as u64, 56 * (elf.phnum as u64 + 2));
    let size = ph_at + ph_len;
    let cell = (plan.tramp_vaddr + size).next_multiple_of(PAGE);
    let mut abs = vec![0x48, 0xff, 0x0c, 0x25];
    abs.extend_from_slice(&(plan.cell as u32).to_le_bytes());
    for s in &plan.sites {
        if s.kind == super::plan::KIND_CPUID {
            // Nothing answers a `cpuid` site natively: the original instruction stays.
            let l = elf
                .loads
                .iter()
                .find(|l| l.flags & 1 != 0 && s.addr >= l.vaddr && s.addr + 2 <= l.vaddr + l.filesz)
                .ok_or_else(|| format!("cpuid site {:#x} outside the text", s.addr))?;
            let o = (l.off + (s.addr - l.vaddr)) as usize;
            out[o..o + 2].copy_from_slice(&[0x0f, 0xa2]);
            continue;
        }
        let t = s.tramp as usize;
        if seg.get(t..t + 8) != Some(&abs[..]) {
            return Err(format!(
                "site {:#x}: the trampoline does not start with the count",
                s.addr
            ));
        }
        let end = plan.tramp_vaddr + t as u64 + 7;
        let d = i32::try_from(cell.wrapping_sub(end) as i64).map_err(|_| "cell out of reach")?;
        seg[t..t + 3].copy_from_slice(&[0x48, 0xff, 0x0d]);
        seg[t + 3..t + 7].copy_from_slice(&d.to_le_bytes());
        seg[t + 7] = 0x90;
    }
    out.resize(out.len().next_multiple_of(PAGE as usize), 0);
    let off = out.len() as u64;
    let cell_off = off + (cell - plan.tramp_vaddr);
    for i in 0..elf.phnum {
        let mut e = data[elf.phoff + i * 56..elf.phoff + (i + 1) * 56].to_vec();
        // PT_PHDR: where the table now is
        if u32_at(&e, 0)? == 6 {
            let v = plan.tramp_vaddr + ph_at;
            for (k, x) in [
                (8, off + ph_at),
                (16, v),
                (24, v),
                (32, ph_len),
                (40, ph_len),
            ] {
                e[k..k + 8].copy_from_slice(&x.to_le_bytes());
            }
        }
        seg.extend(e);
    }
    // PT_LOAD R+X: the trampolines; PT_LOAD R+W: the cell
    for (flags, o, v, n) in [(5u32, off, plan.tramp_vaddr, size), (6, cell_off, cell, 8)] {
        seg.extend_from_slice(&1u32.to_le_bytes());
        seg.extend_from_slice(&flags.to_le_bytes());
        for x in [o, v, v, n, n, PAGE] {
            seg.extend_from_slice(&x.to_le_bytes());
        }
    }
    out.extend_from_slice(&seg);
    out.resize(cell_off as usize, 0);
    out.extend_from_slice(&events.to_le_bytes());
    out[0x20..0x28].copy_from_slice(&(off + ph_at).to_le_bytes());
    out[0x38..0x3a].copy_from_slice(&(elf.phnum as u16 + 2).to_le_bytes());
    Ok(out)
}
