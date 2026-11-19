//! The rewriter for arm64 files (DESIGN 2.6). Compiled on every host, so that its tests run
//! everywhere and an arm64 file can be planned and checked on any machine; only an arm64 host
//! runs a plan.

pub mod code;
pub mod insn;
pub mod points;
#[cfg(test)]
mod tests;
pub mod verify;

use super::elf::Elf;
use super::plan::{Pages, Plan, CELL, PAGE};
use crate::cli::Res;
use points::{Outcome, Place};
use std::collections::BTreeMap;

/// Where the trampolines go: right after the image, unless its segments are aligned to more
/// than a page. Then `ld.so` reserves the image's length plus that alignment (or twice the
/// alignment), maps the file at the aligned address inside the reservation, and only then
/// unmaps the rest: the trampolines go past the end of any such reservation, which the
/// runtime leaves room after (`patina-rt` `plans::room`).
fn tramp_vaddr(elf: &Elf) -> u64 {
    let start = elf.image_start() & !(PAGE - 1);
    let len = elf.image_end().next_multiple_of(PAGE) - start;
    let align = elf.loads.iter().map(|l| l.align).max().unwrap_or(0);
    if align <= PAGE {
        return start + len;
    }
    let align = align.next_multiple_of(PAGE);
    start + len.max(align) + align
}

/// The patched text pages: each page holding a patched word, from the file, in runs.
pub fn pages(elf: &Elf, patched: &[(u64, Vec<u8>)]) -> Res<Vec<Pages>> {
    let mut pages: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    for (a, bytes) in patched {
        let p = a & !(PAGE - 1);
        let page = match pages.entry(p) {
            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::btree_map::Entry::Vacant(e) => e.insert(
                elf.original_page(p)
                    .ok_or_else(|| format!("patch at {p:#x} outside every executable segment"))?,
            ),
        };
        let o = (a - p) as usize;
        page[o..o + bytes.len()].copy_from_slice(bytes);
    }
    let mut runs: Vec<Pages> = vec![];
    for (p, bytes) in pages {
        match runs.last_mut() {
            Some(r) if r.vaddr + r.bytes.len() as u64 == p => r.bytes.extend(bytes),
            _ => runs.push(Pages { vaddr: p, bytes }),
        }
    }
    Ok(runs)
}

pub fn make_plan(elf: &Elf, build: &str) -> Res<Plan> {
    plan_placed(elf, build, !elf.exec)
}

/// The plan, with trampolines before the image allowed or not (`below`): a standalone copy
/// cannot place them there.
pub fn plan_placed(elf: &Elf, build: &str, below: bool) -> Res<Plan> {
    let text: Vec<(u64, &[u8])> = elf.text.iter().map(|t| (t.addr, elf.bytes(t))).collect();
    if text.iter().any(|(a, _)| a % 4 != 0) {
        return Err("an executable section that is not word-aligned".into());
    }
    let code = code::Code::analyze(&text, &elf.anchors, &elf.extents, &elf.asm_data);
    // A call or a jump from one function to another's start (an anchor or a call's target;
    // a tail call) may reach a far target through `x16`: the procedure call standard lets a
    // linker's veneer overwrite it there. A call or jump to a label inside a function (no
    // start, or one function holds both ends) may not: no veneer could stand between them.
    // On a guarded page, only where the target is a landing pad for `br x16`.
    let starts = code.starts();
    let far = |at: u64, to: u64| {
        starts.binary_search(&to).is_ok()
            && !elf.one_function(&starts, to, at)
            && (!elf.bti || code.word(to).is_some_and(insn::x16_pad))
    };
    let after = tramp_vaddr(elf);
    let mut em = points::emit(
        &code,
        Place {
            after,
            before: None,
        },
        &far,
    );
    let unreached = |e: &points::Emitted| {
        e.choices
            .iter()
            .filter(|c| c.outcome == Outcome::Far)
            .count()
    };
    // Sites out of reach of trampolines after the image: those in its lower half get theirs
    // before it instead (only where the image is placed at load time, so below it is free).
    if below && unreached(&em) > 0 {
        let start = elf.image_start() & !(PAGE - 1);
        let gap = elf.loads.iter().map(|l| l.align).max().unwrap_or(0);
        let gap = if gap > PAGE {
            gap.next_multiple_of(PAGE)
        } else {
            0
        };
        let split = start + (elf.image_end() - start) / 2;
        let both = points::emit(
            &code,
            Place {
                after,
                before: Some((start.wrapping_sub(gap), split)),
            },
            &far,
        );
        if unreached(&both) < unreached(&em) {
            em = both;
        }
    }
    let tramp_vaddr = em.tramp_vaddr;
    let blob_end = tramp_vaddr.wrapping_add(em.tramp.len() as u64);
    if tramp_vaddr >= elf.image_start() && CELL < blob_end && elf.image_start() < CELL + 8 {
        return Err(format!(
            "the image or its trampolines overlap the cell at {CELL:#x}"
        ));
    }
    let runs = pages(elf, &em.patched)?;
    let c = code.census();
    let f = code.refusals;
    let mut counts: Vec<(String, u64)> = [
        ("text-bytes", c.text),
        ("proven-bytes", c.proven),
        ("extent-bytes", c.extent),
        ("padding-bytes", c.padding),
        ("dark-bytes", c.dark),
        ("tainted-bytes", c.tainted),
        ("instructions", c.instructions),
        ("anchors", elf.anchors.len() as u64),
        ("extents", elf.extents.len() as u64),
        ("data-ranges", elf.asm_data.len() as u64),
        ("refused-invalid", f.invalid),
        ("refused-data", f.data),
        ("refused-read", f.read),
        ("patches", em.sites.len() as u64),
        (
            "trampoline-bytes",
            4 * em.sites.iter().map(|s| s.tramp_len as u64 / 4).sum::<u64>(),
        ),
        ("trampoline-span", em.tramp.len() as u64),
        (
            "far-rows",
            em.sites
                .iter()
                .filter(|s| s.kind == proto::plan::KIND_FAR)
                .count() as u64,
        ),
        (
            "trampolines-before",
            em.sites
                .iter()
                .filter(|s| (s.tramp as u64) < after.wrapping_sub(tramp_vaddr))
                .count() as u64,
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    for class in points::Class::ALL {
        let mut n = [0u64; points::OUTCOMES.len()];
        for ch in em.choices.iter().filter(|ch| ch.class == class) {
            n[0] += 1;
            n[ch.outcome.index()] += 1;
        }
        for (k, what) in points::OUTCOMES.iter().enumerate() {
            counts.push((format!("{}.{what}", class.name()), n[k]));
        }
    }
    Ok(Plan {
        machine: elf.machine,
        sha256: elf.sha256,
        build: build.to_string(),
        cell: CELL,
        pages: runs,
        tramp_vaddr,
        tramp: em.tramp,
        sites: em.sites,
        entries: vec![],
        counts,
    })
}
