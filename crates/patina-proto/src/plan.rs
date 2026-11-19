//! Load-time plans (`--preempt points`, ARCHITECTURE.md "Load-time rewriting"): what the
//! runtime and the launcher's plan broker agree on. The plan file's format is the host's
//! (`patina-cli/src/rewrite/plan.rs`); the runtime reads only the rows named here, at the
//! offsets the broker's answer gives, and never decodes an instruction.
//!
//! Protocol, on a `SOCK_SEQPACKET` pair whose sandbox end is descriptor
//! `layout::FD_PLAN`: the runtime sends `REQUEST` and the file offset of a mapping (16 bytes)
//! with the mapped file's descriptor (`SCM_RIGHTS`); the broker answers `REPLY_WORDS` words
//! and, when `R_STATUS` is `OK`, a read-only descriptor of the plan file.

/// The request's first 8 bytes.
pub const REQUEST: [u8; 8] = *b"patplan2";

pub const REPLY_WORDS: usize = 13;
/// `OK`, one of the `NONE_*` reasons (no plan for this file: its mappings stay unpatched), or
/// a negated errno (the broker failed: the run cannot go on as asked).
pub const R_STATUS: usize = 0;
/// The link-time address of the requested file offset (`u64::MAX`: no load segment holds it).
pub const R_VADDR: usize = 1;
/// Bytes at the plan file's start that hold the page directories, the site rows and the entry
/// rows (a multiple of the page size; the runtime maps them where the program cannot see them).
pub const R_HDR: usize = 2;
/// Offset and count of the page directory: rows of `RUN_BYTES` (link address, length, offset
/// of the patched pages in the plan file), in address order.
pub const R_RUNS: usize = 3;
pub const R_NRUNS: usize = 4;
/// Offset and count of the site rows (`SITE_BYTES` each), in order of their trampolines.
pub const R_SITES: usize = 5;
pub const R_NSITES: usize = 6;
/// The trampolines' span: link address (the image end rounded up to a page) and length (a
/// multiple of the page size). Only the pages of the trampoline directory are mapped; the rest
/// of the span holds no trampoline.
pub const R_TRAMP_VADDR: usize = 7;
pub const R_TRAMP_LEN: usize = 8;
/// Offset and count of the trampoline directory: rows of `RUN_BYTES` (offset in the span,
/// length, offset in the plan file), in order.
pub const R_TRUNS: usize = 9;
pub const R_NTRUNS: usize = 10;
/// Offset and count of the entry rows (`ENTRY_BYTES` each), in address order.
pub const R_ENTRIES: usize = 11;
pub const R_NENTRIES: usize = 12;

pub const OK: u64 = 0;
/// Not a 64-bit ELF file of this machine with an executable load segment.
pub const NONE_NOT_ELF: u64 = 1;
/// The rewriter refused the file (its report names why).
pub const NONE_REFUSED: u64 = 2;
/// The plan failed the independent verifier: a rewriter defect, the file stays unpatched and
/// the run's report names it.
pub const NONE_UNVERIFIED: u64 = 3;
/// No site in the file.
pub const NONE_EMPTY: u64 = 4;

/// A directory row: address (link address, or offset in the trampolines' span), length,
/// offset in the plan file (`u64` each).
pub const RUN_BYTES: usize = 24;
/// A site row: address `u64`, trampoline offset `u32`, trampoline length, trap offset and
/// copy offset `u16` each, patch length and kind `u8` each.
pub const SITE_BYTES: usize = 20;
pub const SITE_ADDR: usize = 0;
pub const SITE_TRAMP: usize = 8;
pub const SITE_TRAMP_LEN: usize = 12;
pub const SITE_TRAP: usize = 14;
pub const SITE_COPY: usize = 16;
pub const SITE_LEN: usize = 18;
pub const SITE_KIND: usize = 19;
/// An entry row: address `u64`, a trampoline offset `u32`, kind `u8`, 3 bytes of zero.
pub const ENTRY_BYTES: usize = 16;
pub const ENTRY_ADDR: usize = 0;
pub const ENTRY_TO: usize = 8;
pub const ENTRY_KIND: usize = 12;

/// Site kinds. `KIND_JUMP`: the patched branch or call goes to the trampoline, which counts and
/// jumps to the original target (`JUMP_ROW` holds that `jmp rel32`). `KIND_BEFORE`: the
/// patched instructions (one, or a group of straight-line neighbours, the last of which may be
/// a direct branch) became a jump to the trampoline, which counts, runs a copy of each at the
/// copy offset plus its offset in the patch (only the last, a branch, may be longer in the
/// copy) and jumps to the instruction after them.
pub const KIND_JUMP: u8 = 1;
pub const KIND_BEFORE: u8 = 2;
/// Entry kinds. A `cpuid` (`0F A2`) written over with `ud2` (`0F 0B`) in place: the runtime
/// answers it with the identity fields that differ between cores (the APIC, x2APIC, compute
/// unit and node ids, the hybrid core type) as core 0's, zero, so a value the program reads does
/// not depend on the core a run was given (ARCHITECTURE.md "Load-time rewriting").
pub const KIND_CPUID: u8 = 3;
/// The start of an instruction inside a group patch other than its first (an interior
/// boundary): its byte is one that faults (`int3`, `hlt`, `cli`, `sti`, port I/O), so a jump
/// there that the rewriter could not see traps; the runtime resumes at the copy of that
/// instruction, the entry's trampoline offset.
pub const KIND_INTERIOR: u8 = 4;
/// arm64 only: a conditional branch (`b.cond`, `cbz`, `cbnz`, `tbz`, `tbnz`) became `b T`; the
/// trampoline starts with the same condition aimed 8 bytes on and a `b` back to the next
/// instruction (not taken), then counts and branches to the original target (taken).
pub const KIND_COND: u8 = 5;
/// arm64 only: a `bl` or `b` whose target a `b` from the trampoline does not reach (±128 MiB)
/// became `bl T` or `b T`; after the count the row is `adrp x16, target; add x16, x16, #lo12;
/// br x16`. Only where `x16` is free by the procedure call standard: a call, or a jump to a
/// function's start.
pub const KIND_FAR: u8 = 6;
/// Offset of a `KIND_JUMP` trampoline's `jmp rel32` to the original target: after the count
/// (`dec qword [abs32]`, 8 bytes) and its `jz` (2 bytes).
pub const JUMP_ROW: u64 = 10;

/// The count's cell with `--preempt points`: one word below 2 GiB, so a trampoline in any image
/// reaches it with a 32-bit absolute operand (`dec qword [0x7fff0000]`).
pub const CELL: u64 = 0x7fff_0000;

/// arm64: a trampoline's trap, `udf #0x7074` (`SIGILL`): a compute point at its site.
pub const A64_TRAP: u32 = 0x7074;
/// arm64: bytes of a trampoline's count (`stp x16, x17, [sp, #-32]!`, the cell's address, load,
/// subtract, store, `cbz` to the trap's restore, `ldp x16, x17, [sp], #32`). It starts the
/// trampoline, or 8 bytes in for `KIND_COND`; `copy` of an arm64 site is the offset right after
/// it, the row: `b <target>` (`KIND_JUMP`, `KIND_COND`) or the copied instruction and `b` back
/// (`KIND_BEFORE`). After the row: `ldp x16, x17, [sp], #32`, the trap, `b` to the row.
pub const A64_COUNT: u64 = 28;

/// arm64's `shown`: where a stop at `off` bytes into a site's trampoline lands in the program.
/// `KIND_COND` before its count: at its first word the condition is still to be tested (`addr`),
/// at its second it was not taken (`addr + 4`). `KIND_BEFORE`: at the `b` back the next
/// instruction, else the instruction itself (a handler that returns there enters the patch
/// again: one more count, the same in every run). `KIND_FAR`: the branch or call itself (a
/// handler that returns there makes it again, through one more count). Otherwise the branch was
/// taken: `target`.
/// The count leaves `x16`, `x17` and `sp` as they were wherever a stop can show the program
/// a frame (the trap restores them first); only a fault inside the count itself (its stack slot,
/// the cell) sees them changed, and that ends the program or the run.
pub fn shown_a64(addr: u64, kind: u8, copy: u64, target: u64, off: u64) -> u64 {
    match kind {
        KIND_COND if off < 8 => addr + off.min(4),
        KIND_BEFORE if off == copy + 4 => addr + 4,
        KIND_BEFORE | KIND_FAR => addr,
        _ => target,
    }
}

/// Where a stop at `off` bytes into the trampoline of a site lands in the original program: the
/// address a signal frame, a record or a message shows. `addr`, `len`, `kind` and `copy` are
/// the site's; `target` the original target of a `KIND_JUMP` site. Before the copies (the
/// count) or at the trap, the program is about to run the patched instructions: `addr` (a
/// handler that returns there enters the patch again: one more count, the same in every run).
/// In the copies, a stop is at the start of one (a fault, a step): the original instruction at
/// the same offset of the patch (a handler that returns to one inside a group traps there and
/// resumes at its copy). At the jump back after them (5 bytes before the trap): the next
/// instruction. A `KIND_JUMP` site has already taken its branch or made its call: `target`
/// (the return address of a call is already pushed, as it would be there).
pub fn shown(addr: u64, len: u64, kind: u8, copy: u64, trap: u64, target: u64, off: u64) -> u64 {
    if kind == KIND_JUMP {
        target
    } else if off + 5 >= trap && off < trap {
        addr + len
    } else if off >= copy && off < trap {
        addr + (off - copy).min(len - 1)
    } else {
        addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stop_in_a_trampoline_shows_the_original_place() {
        // KIND_BEFORE: count (0..10), copy of a 7-byte instruction (10..17), jmp next (17..22),
        // trap (22..24), jmp row (24..26).
        let s = |off| shown(0x1000, 7, KIND_BEFORE, 10, 22, 0, off);
        assert_eq!(s(0), 0x1000);
        assert_eq!(s(10), 0x1000);
        assert_eq!(s(17), 0x1007);
        assert_eq!(s(22), 0x1000);
        assert_eq!(s(24), 0x1000);
        // A group of 2 + 2 + 2 bytes whose last, `js rel8`, is `js rel32` in the copy: copies
        // at 10, 12 and 14 (to 20), jmp next (20..25), trap (25..27).
        let g = |off| shown(0x1000, 6, KIND_BEFORE, 10, 25, 0, off);
        assert_eq!(g(10), 0x1000);
        assert_eq!(g(12), 0x1002);
        assert_eq!(g(14), 0x1004);
        assert_eq!(g(20), 0x1006);
        assert_eq!(g(25), 0x1000);
        assert_eq!(shown(0x1000, 5, KIND_JUMP, 0, 15, 0x900, 17), 0x900);
    }

    #[test]
    fn a_stop_in_an_arm64_trampoline_shows_the_original_place() {
        // KIND_COND: cond (0), b back (4), count (8..36), b target (36), ldp, udf, b row.
        let c = |off| shown_a64(0x1000, KIND_COND, 36, 0x900, off);
        assert_eq!(
            (c(0), c(4), c(8), c(36), c(44)),
            (0x1000, 0x1004, 0x900, 0x900, 0x900)
        );
        // KIND_BEFORE: count (0..28), copy (28), b back (32), ldp, udf (40), b row.
        let b = |off| shown_a64(0x1000, KIND_BEFORE, 28, 0, off);
        assert_eq!(
            (b(0), b(28), b(32), b(40)),
            (0x1000, 0x1000, 0x1004, 0x1000)
        );
        assert_eq!(shown_a64(0x1000, KIND_JUMP, 28, 0x900, 32), 0x900);
        assert_eq!(shown_a64(0x1000, KIND_FAR, 28, 0, 48), 0x1000);
    }
}
