//! `patina __rewrite`: the load-time rewriter's host side (ARCHITECTURE.md, "Load-time rewriting"; x86_64 only). It
//! reads an ELF file and makes a plan: the patched text pages, trampolines and a site table
//! that put a count (a switch point) at backward branches, backward calls, indirect jumps and
//! atomic instructions. The launcher's broker (`cache.rs`) makes plans for `--preempt points`;
//! this hidden command is for the tests and the evidence.
//!
//! ```text
//! patina __rewrite FILE [--plan OUT]        plan FILE (OUT: write the plan); print its report
//! patina __rewrite --verify FILE PLAN       check PLAN against FILE independently
//! patina __rewrite --sites PLAN             list PLAN's patched instructions (address, length;
//!                                           each of a group's, then `interior` with the byte
//!                                           at each interior boundary)
//! patina __rewrite --standalone FILE OUT [--events N]
//!                                           plan, verify, and write a copy of FILE that runs
//!                                           natively with the plan applied (the differential);
//!                                           its cell starts at N (default 2^62)
//! ```

use crate::cli::Res;
use std::process::ExitCode;

#[cfg(target_arch = "x86_64")]
pub mod cache;
#[cfg(target_arch = "x86_64")]
mod code;
#[cfg(target_arch = "x86_64")]
mod elf;
#[cfg(target_arch = "x86_64")]
mod flags;
#[cfg(target_arch = "x86_64")]
mod plan;
#[cfg(target_arch = "x86_64")]
mod points;
#[cfg(target_arch = "x86_64")]
mod standalone;
#[cfg(all(test, target_arch = "x86_64"))]
mod tests;
#[cfg(target_arch = "x86_64")]
mod verify;

#[cfg(not(target_arch = "x86_64"))]
pub fn main(_args: &[String]) -> Res<ExitCode> {
    Err("__rewrite: unsupported architecture: the rewriter is x86_64 only".into())
}

#[cfg(target_arch = "x86_64")]
pub use x86::{main, make_plan};

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::code::Code;
    use super::elf::Elf;
    use super::plan::CELL;
    use super::plan::{Pages, Plan, KIND_CPUID, KIND_INTERIOR, PAGE};
    use super::points::{self, Class, Outcome};
    use super::*;
    use std::collections::{btree_map::Entry, BTreeMap};

    /// The plan for the file `data`, made by patina build `build`. A pure function of both.
    pub fn make_plan(data: &[u8], build: &str) -> Res<Plan> {
        let elf = Elf::parse(data)?;
        let text: Vec<(u64, &[u8])> = elf.text.iter().map(|t| (t.addr, elf.bytes(t))).collect();
        let code = Code::analyze(&text, &elf.anchors, &elf.extents, elf.exec);
        let (choices, patches) = points::select(&code);
        let tramp_vaddr = elf.image_end().next_multiple_of(PAGE);
        let mut em = points::emit(&code, &patches, tramp_vaddr);
        let cpuid = points::cpuid_sites(&code, &mut em);
        let blob_end = tramp_vaddr + em.tramp.len() as u64;
        if CELL < blob_end && elf.image_start() < CELL + 8 {
            return Err(format!(
                "the image or its trampolines overlap the cell at {CELL:#x}"
            ));
        }
        // The patched pages: each the original page of the executable segment, patched.
        let mut pages: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for (a, bytes) in &em.patched {
            for (k, &b) in bytes.iter().enumerate() {
                let v = a + k as u64;
                let p = v & !(PAGE - 1);
                let page = match pages.entry(p) {
                    Entry::Occupied(e) => e.into_mut(),
                    Entry::Vacant(e) => e.insert(elf.original_page(p).ok_or_else(|| {
                        format!("patch at {p:#x} outside every executable segment")
                    })?),
                };
                page[(v - p) as usize] = b;
            }
        }
        let mut runs: Vec<Pages> = vec![];
        for (p, bytes) in pages {
            match runs.last_mut() {
                Some(r) if r.vaddr + r.bytes.len() as u64 == p => r.bytes.extend(bytes),
                _ => runs.push(Pages { vaddr: p, bytes }),
            }
        }
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
            ("refused-conflict", f.conflict),
            ("refused-invalid", f.invalid),
            ("refused-extent", f.extent),
            ("refused-read", f.read),
            ("patches", em.sites.len() as u64),
            ("groups", em.groups),
            ("group-interiors", em.entries.len() as u64 - cpuid.0),
            ("cpuid-patched", cpuid.0),
            ("cpuid-unpatched", cpuid.1),
            ("trampoline-bytes", em.used),
            ("trampoline-span", em.tramp.len() as u64),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        for class in Class::ALL {
            let mut n = [0u64; OUTCOMES.len()];
            for ch in choices.iter().filter(|ch| ch.class == class) {
                let k = match ch.outcome {
                    _ if ch.count_at().is_some_and(|x| em.far.contains(&x)) => 8,
                    Outcome::InPlace(_) => 1,
                    Outcome::Moved(_) => 2,
                    Outcome::Shared(_) => 3,
                    Outcome::Grouped(_) => 4,
                    Outcome::Tainted => 5,
                    Outcome::FlagsLive => 6,
                    Outcome::NoRoom => 7,
                };
                n[0] += 1;
                n[k] += 1;
            }
            for (k, what) in OUTCOMES.iter().enumerate() {
                counts.push((format!("{}.{what}", class.name()), n[k]));
            }
        }
        Ok(Plan {
            sha256: elf.sha256,
            build: build.to_string(),
            cell: CELL,
            pages: runs,
            tramp_vaddr,
            tramp: em.tramp,
            sites: em.sites,
            entries: em.entries,
            counts,
        })
    }

    const OUTCOMES: [&str; 9] = [
        "found",
        "in-place",
        "moved",
        "shared",
        "grouped",
        "tainted",
        "flags-live",
        "no-room",
        "far",
    ];

    fn report(name: &str, plan: &Plan, plan_bytes: usize, secs: f64) {
        let get = |k: &str| {
            plan.counts
                .iter()
                .find(|(n, _)| n == k)
                .map_or(0, |(_, v)| *v)
        };
        let text = get("text-bytes").max(1) as f64;
        let pct = |k: &str| 100.0 * get(k) as f64 / text;
        println!(
            "rewrite\t{name}\ttext={}\tproven={:.1}%\textent={:.1}%\tpadding={:.1}%\tdark={:.1}%\ttainted={:.1}%",
            get("text-bytes"),
            pct("proven-bytes"),
            pct("extent-bytes"),
            pct("padding-bytes"),
            pct("dark-bytes"),
            pct("tainted-bytes"),
        );
        for class in Class::ALL {
            let c = class.name();
            let n: Vec<u64> = OUTCOMES.iter().map(|o| get(&format!("{c}.{o}"))).collect();
            let covered = n[1] + n[2] + n[3] + n[4];
            let cells: Vec<String> = OUTCOMES
                .iter()
                .zip(&n)
                .map(|(o, v)| format!("{o}={v}"))
                .collect();
            println!(
                "sites\t{c}\t{}\tcovered={:.1}%",
                cells.join("\t"),
                100.0 * covered as f64 / n[0].max(1) as f64
            );
        }
        println!(
            "plan\tpatches={}\tgroups={}\tinteriors={}\ttrampoline-bytes={}\ttrampoline-span={}\tplan-bytes={plan_bytes}\tseconds={secs:.2}",
            get("patches"),
            get("groups"),
            get("group-interiors"),
            get("trampoline-bytes"),
            get("trampoline-span"),
        );
    }

    fn read(p: &str) -> Res<Vec<u8>> {
        std::fs::read(p).map_err(|e| format!("{p}: {e}"))
    }

    fn write(p: &str, b: &[u8]) -> Res<()> {
        std::fs::write(p, b).map_err(|e| format!("{p}: {e}"))
    }

    fn verified(data: &[u8], plan: &Plan) -> Res<()> {
        let bad = verify::verify(data, plan);
        for b in bad.iter().take(20) {
            eprintln!("verify: {b}");
        }
        match bad.len() {
            0 => Ok(()),
            n => Err(format!("the plan failed verification ({n} findings)")),
        }
    }

    pub fn main(args: &[String]) -> Res<ExitCode> {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        let build = || crate::result::build().map(str::to_string);
        match a.as_slice() {
            ["--verify", file, plan] => {
                let plan = Plan::from_bytes(&read(plan)?)?;
                verified(&read(file)?, &plan)?;
                println!("verify\t{file}\tok\tsites={}", plan.sites.len());
            }
            ["--sites", plan] => {
                let plan = Plan::from_bytes(&read(plan)?)?;
                let mut rows: Vec<(u64, u64)> = vec![];
                for s in &plan.sites {
                    let (a, end) = (s.addr, s.addr + s.len as u64);
                    let inner = plan
                        .entries
                        .iter()
                        .filter(|n| n.kind == KIND_INTERIOR && n.addr > a && n.addr < end);
                    let mut at = a;
                    for n in inner {
                        rows.push((at, n.addr - at));
                        at = n.addr;
                    }
                    rows.push((at, end - at));
                }
                for n in plan.entries.iter().filter(|n| n.kind == KIND_CPUID) {
                    rows.push((n.addr, 2));
                }
                rows.sort_unstable();
                for (a, n) in rows {
                    println!("site\t{a:#x}\t{n}");
                }
                for n in plan.entries.iter().filter(|n| n.kind == KIND_INTERIOR) {
                    let b = plan
                        .pages
                        .iter()
                        .find(|p| n.addr >= p.vaddr && n.addr < p.vaddr + p.bytes.len() as u64)
                        .map_or(0, |p| p.bytes[(n.addr - p.vaddr) as usize]);
                    println!("interior\t{:#x}\t{b:02x}", n.addr);
                }
            }
            ["--standalone", file, out, more @ ..] => {
                let events = match more {
                    [] => 1 << 62,
                    ["--events", n] => n
                        .parse()
                        .map_err(|_| format!("--events {n}: not a number"))?,
                    _ => return Err(format!("__rewrite --standalone: unexpected {more:?}")),
                };
                let data = read(file)?;
                let t0 = std::time::Instant::now();
                let plan = make_plan(&data, &build()?)?;
                let secs = t0.elapsed().as_secs_f64();
                verified(&data, &plan)?;
                write(out, &standalone::apply(&data, &plan, events)?)?;
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o755))
                    .map_err(|e| format!("{out}: {e}"))?;
                report(file, &plan, plan.to_bytes().len(), secs);
            }
            [file] | [file, "--plan", _] if !file.starts_with('-') => {
                let data = read(file)?;
                let t0 = std::time::Instant::now();
                let plan = make_plan(&data, &build()?)?;
                let bytes = plan.to_bytes();
                let secs = t0.elapsed().as_secs_f64();
                if let [_, _, out] = a.as_slice() {
                    write(out, &bytes)?;
                }
                report(file, &plan, bytes.len(), secs);
            }
            _ => {
                return Err(
                    "usage: patina __rewrite FILE [--plan OUT] | --verify FILE PLAN | --sites PLAN | --standalone FILE OUT [--events N]"
                        .into(),
                );
            }
        }
        Ok(ExitCode::SUCCESS)
    }
}
