//! `patina __insn-scan FILE...`: run the runtime's site scanner (`proto::insn`) over the executable
//! segments of ELF files and print every candidate with its verdict.
//! `patina __insn-scan --decode-check`: read `objdump -d -w` instruction lines on stdin and compare
//! the decoder's length with the disassembler's for every instruction.

use crate::cli::Res;
use proto::insn::{candidates, confirm, decode, Verdict};
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

/// Function symbol addresses (link-time) from `.symtab` and `.dynsym`.
pub fn func_symbols(d: &[u8]) -> Vec<u64> {
    let mut out = vec![];
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

/// Lines like `  401000:\t0f c7 f0             \trdrand %eax`: compare lengths.
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
        decode_check()?;
        return Ok(ExitCode::SUCCESS);
    }
    for p in args {
        scan_file(p)?;
    }
    Ok(ExitCode::SUCCESS)
}
