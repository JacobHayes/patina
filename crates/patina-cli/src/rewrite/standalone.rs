//! A plan applied to a copy of its file, to run natively without Patina (the differential
//! harness): the plan's pages written over the text, the trampolines' span as one more
//! read+execute `PT_LOAD` (which also holds the program headers, moved there to make room), and
//! a private cell in a read+write `PT_LOAD` after it. The plan's counts address the one cell at
//! a fixed address that the runtime will provide; here each count is re-encoded, same length, to
//! address this image's own cell (x86_64: `dec qword [rip+cell]; nop`; arm64: `adrp x16, cell`
//! for the `movz`), so the copy needs nothing mapped before its first instruction runs:
//! executables and shared libraries alike.
//!
//! arm64 trampolines before the image (a large image's lower half; DESIGN 2.6) cannot be a
//! segment of the copy: a load segment's address is never below the image's first, and a
//! program's code runs before its entry (a library's constructor calls a function the
//! executable exports, `malloc` in Chromium). Such a plan is refused here; `__rewrite
//! --standalone` plans an arm64 copy with its trampolines after the image only.
//!
//! A jump into a group's interior boundary traps (`int3`: `SIGTRAP`; the others: `SIGSEGV`).
//! In Patina the runtime resumes it at the copy of that instruction; here an executable with
//! such boundaries starts at a stub that installs a handler for both signals which does the
//! same from a table of this image's boundaries, then goes on to the original entry. A trap
//! the table does not name gets the default action, as natively. A program that installs its
//! own handler for either signal replaces this one, and a shared library's boundaries have no
//! handler: there an unexpected entry ends the program with the signal.

use super::elf::{u32_at, u64_at, Elf, EM_AARCH64};
use super::plan::{Plan, KIND_CPUID, KIND_INTERIOR, PAGE};
use crate::cli::Res;
use proto::plan::KIND_COND;

/// Machine code with forward 32- and 8-bit displacements patched once the labels are known.
struct Asm {
    b: Vec<u8>,
    fix: Vec<(usize, usize, usize)>,
    labels: Vec<usize>,
}

impl Asm {
    fn put(&mut self, bytes: &[u8]) -> &mut Self {
        self.b.extend_from_slice(bytes);
        self
    }
    /// The opcode bytes, then a displacement of `n` bytes to label `l`, relative to its end.
    fn to(&mut self, op: &[u8], l: usize, n: usize) -> &mut Self {
        self.put(op);
        self.fix.push((self.b.len(), l, n));
        self.b.resize(self.b.len() + n, 0);
        self
    }
    fn label(&mut self, l: usize) -> &mut Self {
        self.labels[l] = self.b.len();
        self
    }
    fn done(mut self) -> Vec<u8> {
        for (at, l, n) in self.fix {
            let d = self.labels[l] as i64 - (at + n) as i64;
            if n == 1 {
                self.b[at] = i8::try_from(d).expect("short jump in reach") as u8;
            } else {
                self.b[at..at + 4].copy_from_slice(&(d as i32).to_le_bytes());
            }
        }
        self.b
    }
}

/// The entry stub, the handler and its table, placed at link address `at`; `entry` is the
/// original entry point, `table` the (boundary, resume) pairs.
fn redirect(at: u64, entry: u64, table: &[(u64, u64)]) -> (Vec<u8>, u64) {
    const HANDLER: usize = 0;
    const RESTORER: usize = 1;
    const MISS: usize = 2;
    const LOOP: usize = 3;
    const HIT: usize = 4;
    const TABLE: usize = 5;
    const ENTRY: usize = 6;
    const NOT_INT3: usize = 7;
    const SKIP: usize = 8;
    let mut a = Asm {
        b: vec![],
        fix: vec![],
        labels: vec![0; 9],
    };
    // The stub: rt_sigaction(SIGTRAP and SIGSEGV, {handler, SA_SIGINFO | SA_RESTORER |
    // SA_NODEFER, restorer, 0}) from below the stack pointer, `rdx` (the loader's exit
    // function) kept in `r12`.
    a.put(&[0x49, 0x89, 0xd4, 0x48, 0x83, 0xec, 0x20]);
    a.to(&[0x48, 0x8d, 0x05], HANDLER, 4)
        .put(&[0x48, 0x89, 0x04, 0x24]);
    a.put(&[0x48, 0xc7, 0x44, 0x24, 0x08])
        .put(&0x4400_0004u32.to_le_bytes());
    a.to(&[0x48, 0x8d, 0x05], RESTORER, 4)
        .put(&[0x48, 0x89, 0x44, 0x24, 0x10]);
    a.put(&[0x48, 0xc7, 0x44, 0x24, 0x18, 0, 0, 0, 0]);
    for sig in [5u8, 11] {
        a.put(&[0xb8, 13, 0, 0, 0, 0xbf, sig, 0, 0, 0, 0x48, 0x89, 0xe6]);
        a.put(&[0x31, 0xd2, 0x41, 0xba, 8, 0, 0, 0, 0x0f, 0x05]);
    }
    a.put(&[0x48, 0x83, 0xc4, 0x20, 0x4c, 0x89, 0xe2]);
    a.to(&[0xe9], ENTRY, 4);
    a.label(RESTORER).put(&[0xb8, 15, 0, 0, 0, 0x0f, 0x05]);
    // The handler (rdi: the signal, rsi: its siginfo, rdx: the context): a trap from the
    // kernel (si_code SI_KERNEL) at a boundary of the table resumes at its copy.
    a.label(HANDLER).put(&[0x81, 0x7e, 0x08, 0x80, 0, 0, 0]);
    a.to(&[0x0f, 0x85], MISS, 4);
    a.put(&[
        0x48, 0x8b, 0x82, 0xa8, 0, 0, 0, 0x83, 0xff, 0x05, 0x75, 0x03, 0x48, 0xff, 0xc8,
    ]);
    a.to(&[0x48, 0x8d, 0x0d], TABLE, 4);
    a.put(&[0x49, 0x89, 0xc8, 0x49, 0xb9]);
    let table_at = a.b.len() + 8;
    a.put(&[0; 8]);
    a.put(&[0x4d, 0x29, 0xc8, 0x4c, 0x29, 0xc0, 0x41, 0xb9])
        .put(&(table.len() as u32).to_le_bytes());
    a.label(LOOP).put(&[0x4d, 0x85, 0xc9]);
    a.to(&[0x0f, 0x84], MISS, 4);
    a.put(&[0x48, 0x39, 0x01]).to(&[0x74], HIT, 1);
    a.put(&[0x48, 0x83, 0xc1, 0x10, 0x49, 0xff, 0xc9])
        .to(&[0xeb], LOOP, 1);
    a.label(HIT)
        .put(&[0x48, 0x8b, 0x41, 0x08, 0x4c, 0x01, 0xc0]);
    a.put(&[0x48, 0x89, 0x82, 0xa8, 0, 0, 0, 0xc3]);
    // Not ours: the default action, then the trap again (an `int3` is stepped back over), or a
    // signal another sent (not from the kernel) raised again.
    a.label(MISS)
        .put(&[0x44, 0x8b, 0x46, 0x08, 0x49, 0x89, 0xd1, 0x83, 0xff, 0x05]);
    a.to(&[0x75], NOT_INT3, 1);
    a.put(&[0x81, 0x7e, 0x08, 0x80, 0, 0, 0])
        .to(&[0x75], SKIP, 1);
    a.put(&[0x49, 0xff, 0x89, 0xa8, 0, 0, 0]);
    a.label(NOT_INT3).label(SKIP);
    a.put(&[
        0x6a, 0, 0x6a, 0, 0x6a, 0, 0x6a, 0, 0xb8, 13, 0, 0, 0, 0x48, 0x89, 0xe6,
    ]);
    a.put(&[
        0x31, 0xd2, 0x41, 0xba, 8, 0, 0, 0, 0x0f, 0x05, 0x48, 0x83, 0xc4, 0x20,
    ]);
    a.put(&[0x41, 0x81, 0xf8, 0x80, 0, 0, 0, 0x75, 0x01, 0xc3]);
    a.put(&[
        0x89, 0xfe, 0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0x89, 0xc7, 0xb8, 62, 0, 0, 0, 0x0f, 0x05,
    ]);
    a.put(&[0xc3]);
    while !a.b.len().is_multiple_of(8) {
        a.put(&[0xcc]);
    }
    a.label(TABLE);
    for &(from, to) in table {
        a.put(&from.to_le_bytes()).put(&to.to_le_bytes());
    }
    let link_table = at + a.labels[TABLE] as u64;
    a.labels[ENTRY] = (entry as i64 - at as i64) as usize;
    let mut b = a.done();
    b[table_at - 8..table_at].copy_from_slice(&link_table.to_le_bytes());
    (b, at)
}

/// The patched copy. Its cell starts at `events`: with enough, it runs as the original; with
/// few, it stops on a trampoline's trap once they run out (x86_64 `hlt`: `SIGSEGV`; arm64
/// `udf`: `SIGILL`).
pub fn apply(data: &[u8], plan: &Plan, events: u64) -> Res<Vec<u8>> {
    let elf = Elf::parse(data)?;
    if !plan.tramp_vaddr.is_multiple_of(PAGE) {
        return Err("trampolines not page-aligned".into());
    }
    if plan.tramp_vaddr < elf.image_start()
        || plan
            .tramp_vaddr
            .checked_add(plan.tramp.len() as u64)
            .is_none()
    {
        return Err("trampolines before the image: a copy cannot place them".into());
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
    let file_at = |a: u64, n: u64| {
        let l = elf
            .loads
            .iter()
            .find(|l| l.flags & 1 != 0 && a >= l.vaddr && a + n <= l.vaddr + l.filesz)
            .ok_or_else(|| format!("{a:#x} outside the text"))?;
        Ok::<usize, String>((l.off + (a - l.vaddr)) as usize)
    };
    // Nothing answers a `cpuid` natively: the original instruction stays.
    for n in plan.entries.iter().filter(|n| n.kind == KIND_CPUID) {
        let o = file_at(n.addr, 2)?;
        out[o..o + 2].copy_from_slice(&[0x0f, 0xa2]);
    }
    // Segment 1: trampolines, the redirect for an executable with interior boundaries, then
    // the program headers with two more entries.
    let mut seg = plan.tramp.clone();
    let table: Vec<(u64, u64)> = plan
        .entries
        .iter()
        .filter(|n| n.kind == KIND_INTERIOR)
        .map(|n| (n.addr, plan.tramp_vaddr + n.to as u64))
        .collect();
    let entry = u64_at(data, 0x18)?;
    if !table.is_empty() && entry != 0 {
        let (code, at) = redirect(plan.tramp_vaddr + seg.len() as u64, entry, &table);
        seg.extend_from_slice(&code);
        out[0x18..0x20].copy_from_slice(&at.to_le_bytes());
    }
    seg.resize(seg.len().next_multiple_of(8), 0xcc);
    let (ph_at, ph_len) = (seg.len() as u64, 56 * (elf.phnum as u64 + 2));
    let size = ph_at + ph_len;
    let cell = (plan.tramp_vaddr + size).next_multiple_of(PAGE);
    let mut abs = vec![0x48, 0xff, 0x0c, 0x25];
    abs.extend_from_slice(&(plan.cell as u32).to_le_bytes());
    for s in &plan.sites {
        let t = s.tramp as usize;
        if elf.machine == EM_AARCH64 {
            // `movz x16, #CELL >> 16, lsl #16` becomes `adrp x16, cell` (the cell is a page).
            use super::a64::insn::{adrp, movz_hi, X16};
            let at = t + if s.kind == KIND_COND { 8 } else { 0 } + 4;
            if seg.get(at..at + 4) != Some(&movz_hi(X16, plan.cell).to_le_bytes()[..]) {
                return Err(format!("site {:#x}: the trampoline does not count", s.addr));
            }
            let w = adrp(X16, plan.tramp_vaddr + at as u64, cell).ok_or("cell out of reach")?;
            seg[at..at + 4].copy_from_slice(&w.to_le_bytes());
            continue;
        }
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
