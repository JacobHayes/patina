//! `patina __rewrite`: the load-time rewriter's host side (ARCHITECTURE.md, "Load-time rewriting"). It
//! reads an x86_64 or arm64 ELF file and makes a plan: the patched text pages, trampolines and a site table
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
//!
//! Each takes `--threads N` (default: the CPUs this process may use, at most 8): a plan is the
//! same bytes on any number.

use crate::cli::Res;
use std::process::ExitCode;

pub mod a64;
pub mod cache;
mod class;
#[cfg(target_arch = "x86_64")]
mod code;
mod elf;
#[cfg(target_arch = "x86_64")]
mod flags;
pub mod par;
mod plan;
#[cfg(target_arch = "x86_64")]
mod points;
mod standalone;
#[cfg(all(test, target_arch = "x86_64"))]
mod tests;
#[cfg(target_arch = "x86_64")]
mod verify;

use class::Class;

use plan::{Plan, KIND_CPUID, KIND_INTERIOR};

/// The ELF machine of the host: the files a run can apply plans to.
#[cfg(target_arch = "x86_64")]
pub const HOST_MACHINE: u16 = elf::EM_X86_64;
#[cfg(target_arch = "aarch64")]
pub const HOST_MACHINE: u16 = elf::EM_AARCH64;

/// The plan for the file `elf`, made by patina build `build`. A pure function of both: the
/// same bytes on any number of threads (`par`). An x86_64 file is planned on an x86_64 host
/// (its decoder is built there only); an arm64 file on any host.
pub fn make_plan(elf: &elf::Elf, build: &str, par: &par::Par) -> Res<Plan> {
    match elf.machine {
        #[cfg(target_arch = "x86_64")]
        elf::EM_X86_64 => x86::make_plan(elf, build, par),
        elf::EM_AARCH64 => a64::make_plan(elf, build, par),
        _ => Err("unsupported architecture: x86_64 files are planned on x86_64 hosts".into()),
    }
}

/// The plan for `elf`, its bytes, and every way it fails to be a sound plan for it (the
/// independent verifier of its architecture; empty when it is one). The verifier finds code
/// its own way while the plan is made, then checks the plan while it is written out.
pub fn plan_verified(
    elf: &elf::Elf,
    build: &str,
    par: &par::Par,
) -> Res<(Plan, Vec<u8>, Vec<String>)> {
    match elf.machine {
        #[cfg(target_arch = "x86_64")]
        elf::EM_X86_64 => {
            let (plan, found) = par.join(|| make_plan(elf, build, par), || verify::Found::new(elf));
            let plan = plan?;
            let (bytes, bad) = par.join(|| plan.to_bytes(), || verify::check(&found, &plan, par));
            Ok((plan, bytes, bad))
        }
        elf::EM_AARCH64 => {
            let (plan, found) = par.join(
                || make_plan(elf, build, par),
                || a64::verify::Found::new(elf),
            );
            let plan = plan?;
            let (bytes, bad) = par.join(
                || plan.to_bytes(),
                || a64::verify::check(&found, &plan, par),
            );
            Ok((plan, bytes, bad))
        }
        _ => Err("unsupported architecture: x86_64 files are planned on x86_64 hosts".into()),
    }
}

/// Every way `plan` fails to be a sound plan for `data` (the independent verifier of its
/// architecture); empty when it is one.
pub fn verify_plan(data: &[u8], plan: &Plan, par: &par::Par) -> Vec<String> {
    let elf = match elf::Elf::parse(data) {
        Ok(e) => e,
        Err(e) => return vec![e],
    };
    match plan.machine {
        #[cfg(target_arch = "x86_64")]
        elf::EM_X86_64 => verify::check(&verify::Found::new(&elf), plan, par),
        elf::EM_AARCH64 => a64::verify::check(&a64::verify::Found::new(&elf), plan, par),
        m => vec![format!("no verifier for ELF machine {m} on this host")],
    }
}

/// The outcome names of a plan's counts, by architecture (`Class.outcome`).
fn outcomes(machine: u16) -> &'static [&'static str] {
    if machine == elf::EM_AARCH64 {
        &a64::points::OUTCOMES
    } else {
        &X86_OUTCOMES
    }
}

/// The outcomes that give a site a count.
const COVERED: [&str; 4] = ["in-place", "moved", "shared", "grouped"];

const X86_OUTCOMES: [&str; 9] = [
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
        let names = outcomes(plan.machine);
        let n: Vec<u64> = names.iter().map(|o| get(&format!("{c}.{o}"))).collect();
        let covered: u64 = COVERED.iter().map(|o| get(&format!("{c}.{o}"))).sum();
        let cells: Vec<String> = names
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

fn verified(data: &[u8], plan: &Plan, par: &par::Par) -> Res<()> {
    let bad = verify_plan(data, plan, par);
    for b in bad.iter().take(20) {
        eprintln!("verify: {b}");
    }
    match bad.len() {
        0 => Ok(()),
        n => Err(format!("the plan failed verification ({n} findings)")),
    }
}

/// The threads a plan uses by default: the CPUs this process may use, at most 8.
pub fn default_threads() -> usize {
    crate::launch::allowed_cpus().len().clamp(1, 8)
}

/// For a debugger (`patina debug`): an ELF file's SHA-256 and the lowest address of its
/// loadable segments (its load bias is where that is mapped, less it).
pub fn image_start(data: &[u8]) -> Res<([u8; 32], u64)> {
    let e = elf::Elf::parse(data)?;
    Ok((e.sha256, e.image_start()))
}

/// For a debugger (`patina debug`): the SHA-256 of the file a plan is for, and each of its
/// trampolines as (start, end, the original instructions' address, their length, the offset
/// of their copy), in the file's addresses.
pub fn trampolines(plan: &[u8]) -> Res<([u8; 32], Vec<[u64; 5]>)> {
    let plan = Plan::from_bytes(plan)?;
    let t = |s: &plan::Site| {
        let lo = plan.tramp_vaddr + s.tramp as u64;
        [
            lo,
            lo + s.tramp_len as u64,
            s.addr,
            s.len as u64,
            s.copy as u64,
        ]
    };
    Ok((plan.sha256, plan.sites.iter().map(t).collect()))
}

pub fn main(args: &[String]) -> Res<ExitCode> {
    let mut a: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut threads = default_threads();
    if let Some(k) = a.iter().position(|&x| x == "--threads") {
        let n = a.get(k + 1).ok_or("--threads needs N")?;
        threads = match n.parse() {
            Ok(n) if n > 0 => n,
            _ => return Err(format!("--threads {n}: a number of at least 1")),
        };
        a.drain(k..k + 2);
    }
    let par = par::Par::new(threads);
    let build = || crate::result::build().map(str::to_string);
    match a.as_slice() {
        ["--verify", file, plan] => {
            let plan = Plan::from_bytes(&read(plan)?)?;
            verified(&read(file)?, &plan, &par)?;
            println!("verify\t{file}\tok\tsites={}", plan.sites.len());
        }
        ["--sites", plan] => {
            let plan = Plan::from_bytes(&read(plan)?)?;
            let mut rows: Vec<(u64, u64)> = vec![];
            // The entries are in address order.
            for s in &plan.sites {
                let (a, end) = (s.addr, s.addr + s.len as u64);
                let from = plan.entries.partition_point(|n| n.addr <= a);
                let inner = plan.entries[from..]
                    .iter()
                    .take_while(|n| n.addr < end)
                    .filter(|n| n.kind == KIND_INTERIOR);
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
                let p = plan.pages.partition_point(|p| p.vaddr <= n.addr);
                let b = p
                    .checked_sub(1)
                    .map(|p| &plan.pages[p])
                    .filter(|p| n.addr < p.vaddr + p.bytes.len() as u64)
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
            let e = elf::Elf::parse(&data)?;
            // arm64: no trampolines before the image (the copy cannot place them there).
            let plan = match e.machine {
                elf::EM_AARCH64 => a64::plan_placed(&e, &build()?, false, &par)?,
                _ => make_plan(&e, &build()?, &par)?,
            };
            let secs = t0.elapsed().as_secs_f64();
            verified(&data, &plan, &par)?;
            write(out, &standalone::apply(&data, &plan, events)?)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("{out}: {e}"))?;
            report(file, &plan, plan.to_bytes().len(), secs);
        }
        [file] | [file, "--plan", _] if !file.starts_with('-') => {
            let data = read(file)?;
            let t0 = std::time::Instant::now();
            let plan = make_plan(&elf::Elf::parse(&data)?, &build()?, &par)?;
            let bytes = plan.to_bytes();
            let secs = t0.elapsed().as_secs_f64();
            if let [_, _, out] = a.as_slice() {
                write(out, &bytes)?;
            }
            report(file, &plan, bytes.len(), secs);
        }
        _ => {
            return Err(
                "usage: patina __rewrite FILE [--plan OUT] | --verify FILE PLAN | --sites PLAN | --standalone FILE OUT [--events N]; each with [--threads N]"
                    .into(),
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::code::Code;
    use super::elf::Elf;
    use super::par::Par;
    use super::plan::CELL;
    use super::plan::{Pages, Plan, PAGE};
    use super::points::{self, Class, Outcome};
    use super::*;
    use std::collections::{btree_map::Entry, BTreeMap};

    /// The plan for the file `elf`, made by patina build `build`. A pure function of both.
    pub fn make_plan(elf: &Elf, build: &str, par: &Par) -> Res<Plan> {
        let text: Vec<(u64, &[u8])> = elf.text.iter().map(|t| (t.addr, elf.bytes(t))).collect();
        let code = Code::analyze(&text, &elf.anchors, &elf.extents, elf.exec, par);
        let (choices, patches) = points::select(&code, par);
        let tramp_vaddr = elf.image_end().next_multiple_of(PAGE);
        let mut em = points::emit(&code, &patches, tramp_vaddr, par);
        let cpuid = points::cpuid_sites(&code, &mut em, par);
        let blob_end = tramp_vaddr + em.tramp.len() as u64;
        if CELL < blob_end && elf.image_start() < CELL + 8 {
            return Err(format!(
                "the image or its trampolines overlap the cell at {CELL:#x}"
            ));
        }
        // The patched pages: each the original page of the executable segment, patched.
        let mut pages: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for (a, bytes) in &em.patched {
            let mut v = *a;
            let end = a + bytes.len() as u64;
            while v < end {
                let p = v & !(PAGE - 1);
                let to = end.min(p + PAGE);
                let page = match pages.entry(p) {
                    Entry::Occupied(e) => e.into_mut(),
                    Entry::Vacant(e) => e.insert(elf.original_page(p).ok_or_else(|| {
                        format!("patch at {p:#x} outside every executable segment")
                    })?),
                };
                page[(v - p) as usize..(to - p) as usize]
                    .copy_from_slice(&bytes[(v - a) as usize..(to - a) as usize]);
                v = to;
            }
        }
        let mut runs: Vec<Pages> = vec![];
        for (p, bytes) in pages {
            match runs.last_mut() {
                Some(r) if r.vaddr + r.bytes.len() as u64 == p => r.bytes.extend(bytes),
                _ => runs.push(Pages { vaddr: p, bytes }),
            }
        }
        let c = code.census(par);
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
            let mut n = [0u64; X86_OUTCOMES.len()];
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
            for (k, what) in X86_OUTCOMES.iter().enumerate() {
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
            entries: em.entries,
            counts,
        })
    }
}
