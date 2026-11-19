//! `patina __insn-scan FILE...`: run the runtime's site scanner (`proto::insn`) over the executable
//! segments (on arm64: sections) of ELF files and print every candidate with its verdict.
//! `patina __insn-scan --decode-check` (x86_64): read `objdump -d -w` instruction lines on stdin
//! and compare the decoder's length with the disassembler's for every instruction.

use crate::cli::Res;
#[cfg(target_arch = "x86_64")]
use proto::insn::{candidates, confirm, decode, Verdict};
#[cfg(target_arch = "x86_64")]
use std::io::BufRead;
use std::process::ExitCode;

fn u16_at(d: &[u8], o: usize) -> u64 {
    u16::from_le_bytes(d[o..o + 2].try_into().unwrap()) as u64
}
fn u32_at(d: &[u8], o: usize) -> u64 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap()) as u64
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}

/// Function starts (link-time): the function symbols of `.symtab` and `.dynsym`, and the
/// functions the `.eh_frame_hdr` table lists (the runtime's sweep starts).
#[cfg(target_arch = "x86_64")]
pub fn func_symbols(d: &[u8]) -> Vec<u64> {
    let mut out = vec![];
    let phoff = u64_at(d, 0x20) as usize;
    let (phentsize, phnum) = (u16_at(d, 0x36) as usize, u16_at(d, 0x38) as usize);
    for i in 0..phnum.min(64) {
        let p = phoff + i * phentsize;
        if p + 56 > d.len() || u32_at(d, p) != proto::insn::PT_GNU_EH_FRAME as u64 {
            continue;
        }
        let (off, vaddr) = (u64_at(d, p + 8) as usize, u64_at(d, p + 0x10));
        let Some(h) = d.get(off..off + 12) else { break };
        if let Some((table, n)) = proto::insn::eh_frame_table(h.try_into().unwrap()) {
            let t = off + table as usize;
            for e in d
                .get(t..t + 8 * n as usize)
                .unwrap_or(&[])
                .as_chunks::<8>()
                .0
            {
                out.push(proto::insn::fde_start(vaddr, e));
            }
        }
        break;
    }
    let shoff = u64_at(d, 0x28) as usize;
    let (shentsize, shnum) = (u16_at(d, 0x3a) as usize, u16_at(d, 0x3c) as usize);
    if shoff == 0 || shoff + shnum * shentsize > d.len() {
        return out;
    }
    for i in 0..shnum {
        let s = shoff + i * shentsize;
        let typ = u32_at(d, s + 4);
        if typ != 2 && typ != 11 {
            continue;
        }
        let (off, size, ent) = (
            u64_at(d, s + 0x18) as usize,
            u64_at(d, s + 0x20) as usize,
            u64_at(d, s + 0x38) as usize,
        );
        if ent == 0 || off + size > d.len() {
            continue;
        }
        for k in 0..size / ent {
            let e = off + k * ent;
            let info = d[e + 4];
            let value = u64_at(d, e + 8);
            if info & 0xf == 2 && value != 0 {
                out.push(value);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(target_arch = "x86_64")]
fn scan_file(path: &str) -> Res<()> {
    let d = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if d.len() < 64 || &d[..4] != b"\x7fELF" {
        return Err(format!("{path}: not an ELF file"));
    }
    let syms = func_symbols(&d);
    let phoff = u64_at(&d, 0x20) as usize;
    let (phentsize, phnum) = (u16_at(&d, 0x36) as usize, u16_at(&d, 0x38) as usize);
    let (mut real, mut inside, mut skipped) = (0, 0, 0);
    for i in 0..phnum {
        let p = phoff + i * phentsize;
        let (typ, flags) = (u32_at(&d, p), u32_at(&d, p + 4));
        if typ != 1 || flags & 1 == 0 {
            continue;
        }
        let (off, va, filesz) = (
            u64_at(&d, p + 8) as usize,
            u64_at(&d, p + 0x10),
            u64_at(&d, p + 0x20) as usize,
        );
        let code = &d[off..off + filesz];
        candidates(code, |c| {
            let cva = va + c as u64;
            let from = proto::insn::sweep_start(cva, va, syms.iter().copied());
            let v = confirm(code, (from - va) as usize, c);
            let (what, kind) = match v {
                Verdict::Real(s) => {
                    real += 1;
                    (
                        format!("real start={:#x} len={}", va + s.start as u64, s.len),
                        s.kind.map(|k| k.name()).unwrap_or("other"),
                    )
                }
                Verdict::Inside { at } => {
                    inside += 1;
                    (format!("inside insn at {:#x}", va + at as u64), "-")
                }
                Verdict::Skipped => {
                    skipped += 1;
                    ("skipped".to_string(), "-")
                }
            };
            println!(
                "cand\t{path}\t{cva:#x}\t{}\t{kind}\tsweep-from={from:#x}",
                what.split(' ').next().unwrap()
            );
            let _ = what;
        });
    }
    println!(
        "total\t{path}\taccepted={real}\trejected-inside={inside}\trejected-skipped={skipped}"
    );
    Ok(())
}

/// arm64: every word of each executable section (`SHF_EXECINSTR`) under the rule. Prints
/// `cand FILE ADDR real|data KIND` for each candidate: `data` when a literal load reads it.
#[cfg(target_arch = "aarch64")]
fn scan_file(path: &str) -> Res<()> {
    let d = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    if d.len() < 64 || &d[..4] != b"\x7fELF" {
        return Err(format!("{path}: not an ELF file"));
    }
    let shoff = u64_at(&d, 0x28) as usize;
    let (shentsize, shnum) = (u16_at(&d, 0x3a) as usize, u16_at(&d, 0x3c) as usize);
    let (mut real, mut data) = (0, 0);
    for i in 0..shnum {
        let s = shoff + i * shentsize;
        if s + 64 > d.len() {
            break;
        }
        let (typ, flags) = (u32_at(&d, s + 4), u64_at(&d, s + 8));
        // SHF_EXECINSTR, not SHT_NOBITS
        if flags & 4 == 0 || typ == 8 {
            continue;
        }
        let (addr, off, size) = (
            u64_at(&d, s + 0x10),
            u64_at(&d, s + 0x18) as usize,
            u64_at(&d, s + 0x20) as usize,
        );
        let skip = ((4 - addr % 4) % 4) as usize;
        let (start, end) = (off + skip, (off + size).min(d.len()));
        if start >= end {
            continue;
        }
        let words: Vec<u32> = d[start..end]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|w| u32::from_le_bytes(*w))
            .collect();
        let base = addr + skip as u64;
        proto::insn::sites(&words, base, |k, r| {
            let (what, kind) = match r {
                Ok(k) => {
                    real += 1;
                    ("real", k)
                }
                Err(k) => {
                    data += 1;
                    ("data", k)
                }
            };
            println!(
                "cand\t{path}\t{:#x}\t{what}\t{}",
                base + 4 * k as u64,
                kind.name()
            );
        });
    }
    println!("total\t{path}\taccepted={real}\trejected-data={data}");
    Ok(())
}

/// Lines like `  401000:\t0f c7 f0             \trdrand %eax`: compare lengths.
#[cfg(target_arch = "x86_64")]
fn decode_check() -> Res<()> {
    let (mut n, mut bad, mut skipped) = (0u64, 0u64, 0u64);
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let mut parts = line.split('\t');
        let (Some(a), Some(hex)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !a.trim_end().ends_with(':') {
            continue;
        }
        let text = parts.next().unwrap_or("").trim().to_string();
        let bytes: Vec<u8> = hex
            .split_whitespace()
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        // objdump prints a REX prefix that is not right before an opcode as its own line, and the
        // bytes of an instruction cut off by the end of a section as `.byte`.
        if bytes.is_empty()
            || text.starts_with("(bad)")
            || text.is_empty()
            || text.starts_with("rex")
            || text.starts_with(".byte")
        {
            skipped += 1;
            continue;
        }
        n += 1;
        let mut buf = bytes.clone();
        buf.extend_from_slice(&[0u8; 16]);
        let got = decode(&buf).map(|d| d.len).unwrap_or(0);
        if got != bytes.len() {
            bad += 1;
            if bad <= 20 {
                println!("mismatch\t{}\t{hex}\t{text}\tdecoder={got}", a.trim());
            }
        }
    }
    println!("decode-check\tinstructions={n}\tmismatches={bad}\tskipped={skipped}");
    Ok(())
}

pub fn main(args: &[String]) -> Res<ExitCode> {
    if args.first().map(String::as_str) == Some("--decode-check") {
        #[cfg(target_arch = "x86_64")]
        decode_check()?;
        #[cfg(not(target_arch = "x86_64"))]
        return Err("--decode-check checks the x86-64 length decoder".into());
        #[cfg(target_arch = "x86_64")]
        return Ok(ExitCode::SUCCESS);
    }
    for p in args {
        scan_file(p)?;
    }
    Ok(ExitCode::SUCCESS)
}
