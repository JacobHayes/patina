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
pub const REQUEST: [u8; 8] = *b"patplan1";

pub const REPLY_WORDS: usize = 10;
/// `OK`, one of the `NONE_*` reasons (no plan for this file: its mappings stay unpatched), or
/// a negated errno (the broker failed: the run cannot go on as asked).
pub const R_STATUS: usize = 0;
/// The link-time address of the requested file offset (`u64::MAX`: no load segment holds it).
pub const R_VADDR: usize = 1;
/// Bytes at the plan file's start that hold the page directory and the site rows (a multiple
/// of the page size; the runtime maps them where the program cannot see them).
pub const R_HDR: usize = 2;
/// Offset and count of the page directory: rows of `RUN_BYTES` (link address, length, offset
/// of the patched pages in the plan file), in address order.
pub const R_RUNS: usize = 3;
pub const R_NRUNS: usize = 4;
/// Offset and count of the site rows (`SITE_BYTES` each), in address order.
pub const R_SITES: usize = 5;
pub const R_NSITES: usize = 6;
/// The trampolines: link address (the image end rounded up to a page), offset in the plan
/// file (page-aligned), length.
pub const R_TRAMP_VADDR: usize = 7;
pub const R_TRAMP_OFF: usize = 8;
pub const R_TRAMP_LEN: usize = 9;

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

/// A page directory row: link address, length, offset in the plan file (`u64` each).
pub const RUN_BYTES: usize = 24;
/// A site row: address `u64`, trampoline offset `u32`, trampoline length, trap offset and
/// copy offset `u16` each, instruction length and kind `u8` each.
pub const SITE_BYTES: usize = 20;
pub const SITE_ADDR: usize = 0;
pub const SITE_TRAMP: usize = 8;
pub const SITE_TRAMP_LEN: usize = 12;
pub const SITE_TRAP: usize = 14;
pub const SITE_COPY: usize = 16;
pub const SITE_LEN: usize = 18;
pub const SITE_KIND: usize = 19;

/// Site kinds. `KIND_JUMP`: the patched branch or call goes to the trampoline, which counts and
/// jumps to the original target (`JUMP_ROW` holds that `jmp rel32`). `KIND_BEFORE`: the
/// patched instruction became a jump to the trampoline, which counts, runs a copy of it at
/// the copy offset and jumps to the instruction after it.
pub const KIND_JUMP: u8 = 1;
pub const KIND_BEFORE: u8 = 2;
/// A `cpuid` (`0F A2`) written over with `ud2` (`0F 0B`) in place, no trampoline (its
/// trampoline offset is the next site's, its length 0): the runtime answers it with the
/// identity fields that differ between cores (the APIC, x2APIC, compute unit and node ids, the
/// hybrid core type) as core 0's, zero, so a value the program reads does not depend on the core
/// a run was given (ARCHITECTURE.md "Load-time rewriting").
pub const KIND_CPUID: u8 = 3;
/// Offset of a `KIND_JUMP` trampoline's `jmp rel32` to the original target: after the count
/// (`dec qword [abs32]`, 8 bytes) and its `jz` (2 bytes).
pub const JUMP_ROW: u64 = 10;

/// The count's cell with `--preempt points`: one word below 2 GiB, so a trampoline in any image
/// reaches it with a 32-bit absolute operand (`dec qword [0x7fff0000]`).
pub const CELL: u64 = 0x7fff_0000;

/// Where a stop at `off` bytes into the trampoline of a site lands in the original program: the
/// address a signal frame, a record or a message shows. `addr`, `len`, `kind` and `copy` are
/// the site's; `target` the original target of a `KIND_JUMP` site. Before the copy (the count)
/// or at the trap, the program is about to run the patched instruction: `addr` (a handler that
/// returns there enters the patch again: one more count, the same in every run). In the copy:
/// `addr` (a fault of the relocated instruction is the original's). After the copy (its jump
/// back): the next instruction. A `KIND_JUMP` site has already taken its branch or made its
/// call: `target` (the return address of a call is already pushed, as it would be there).
pub fn shown(addr: u64, len: u64, kind: u8, copy: u64, trap: u64, target: u64, off: u64) -> u64 {
    if kind == KIND_JUMP {
        target
    } else if off >= copy + len && off < trap {
        addr + len
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
        assert_eq!(shown(0x1000, 5, KIND_JUMP, 0, 15, 0x900, 17), 0x900);
    }
}
