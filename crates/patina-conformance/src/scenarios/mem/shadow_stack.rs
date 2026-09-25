//! mem/shadow_stack — `map_shadow_stack` (Documentation/arch/x86/shstk.rst;
//! arch/x86/kernel/shstk.c): a size of 0, a restore token at a size that is
//! not a multiple of 8, a misaligned address and an unknown flag are
//! `EINVAL`; a mapping is page-aligned, lands on a free fixed address, and
//! reads zero apart from the restore token `SHADOW_STACK_SET_TOKEN` asks
//! for — on x86_64 the 8 bytes at its top hold the address just past them
//! with bit 0 set (the 64-bit mode bit).
//!
//! Shadow stacks are hardware: the scenario needs one to map.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::probe::{At, Probe, neg, page_size};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

/// `SHADOW_STACK_SET_TOKEN` (uapi/asm-generic/mman-common.h).
const SET_TOKEN: u32 = 1 << 0;
/// A flag no architecture defines (`SHADOW_STACK_SET_TOKEN` 1 and arm64's
/// `SHADOW_STACK_SET_MARKER` 2 are all there are).
const UNKNOWN_FLAG: u32 = 1 << 5;

pub fn run(p: &Probe) {
    let page = page_size();
    let null = At::null();
    p.check(
        "size 0 is EINVAL",
        p.map_shadow_stack("-", &null, 0, 0).0 == neg(EINVAL),
    );
    p.check(
        "a token at a size that is not a multiple of 8 is EINVAL",
        p.map_shadow_stack("-", &null, page - 4, SET_TOKEN).0 == neg(EINVAL),
    );
    p.check(
        "an unknown flag is EINVAL",
        p.map_shadow_stack("-", &null, page, UNKNOWN_FLAG).0 == neg(EINVAL),
    );
    let (r, plain) = p.map_shadow_stack("s", &null, page, 0);
    p.require("map a shadow stack", r >= 0);
    let plain = plain.unwrap();
    p.check("it reads zero", plain.zeroed(0, page));
    p.check(
        "a misaligned address is EINVAL",
        p.map_shadow_stack("-", &plain.at(8), page, 0).0 == neg(EINVAL),
    );
    p.require("unmap it", p.munmap(&plain.at(0), page) == 0);
    let (r, fixed) = p.map_shadow_stack("f", &plain.at(0), page, 0);
    p.check(
        "a free address takes it exactly",
        r >= 0 && fixed.is_some_and(|fixed| fixed.base == plain.base),
    );
    if let Some(fixed) = fixed {
        p.munmap(&fixed.at(0), page);
    }
    let (r, tokened) = p.map_shadow_stack("t", &null, page, SET_TOKEN);
    p.require("map one with a restore token", r >= 0);
    let tokened = tokened.unwrap();
    p.check("below the token it reads zero", tokened.zeroed(0, page - 8));
    #[cfg(target_arch = "x86_64")]
    p.check(
        "the token is the address past it, with the 64-bit bit",
        u64::from_ne_bytes(tokened.bytes(page - 8, 8).try_into().unwrap())
            == (tokened.base + page) as u64 | 1,
    );
    p.check("unmap it", p.munmap(&tokened.at(0), page) == 0);
}

pub const SCENARIO: Scenario = Scenario {
    name: "mem/shadow_stack",
    run,
    covers: &[Syscall::N_map_shadow_stack],
    vehicles: Vehicle::KERNEL,
    needs: &[Need::ShadowStack],
    gaps: &[unmodeled_trap!("map_shadow_stack", Vehicle::KERNEL, 0)],
    ..DEFAULTS
};
