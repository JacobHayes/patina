//! sys/bpf — the BPF row (kernel/bpf/syscall.c `__sys_bpf`), on a host that
//! refuses BPF objects to an unprivileged caller (`Need::RestrictedBpf`:
//! `kernel.unprivileged_bpf_disabled` set, the default of distribution
//! kernels and the configuration the virtual kernel declares):
//!
//! * an attribute size past a page is `E2BIG`, an unreadable attribute
//!   `EFAULT`, an unknown command `EINVAL`;
//! * `BPF_MAP_CREATE` checks the map type first (unknown: `EINVAL`), then is
//!   `EPERM` (`map_create`: the sysctl, and `CAP_BPF`);
//! * `BPF_PROG_LOAD` checks its flags first (unknown: `EINVAL`), then is
//!   `EPERM` even for a socket filter (`bpf_prog_load`);
//! * walking the loaded programs' ids needs `CAP_SYS_ADMIN` whatever the
//!   sysctl says (`bpf_obj_get_next_id`: `EPERM`).
//!
//! What root would be granted is a one-entry array map and a two-instruction
//! socket filter (`return 0`), both closed at exit and attached nowhere.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

const BPF_MAP_CREATE: i64 = 0;
const BPF_PROG_LOAD: i64 = 5;
const BPF_PROG_GET_NEXT_ID: i64 = 11;
/// No `BPF_*` command.
const UNKNOWN_COMMAND: i64 = 9999;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
/// No `BPF_F_*` program flag.
const UNKNOWN_PROG_FLAG: u32 = 1 << 30;

/// Room for every command's `union bpf_attr` prefix used here, zeroed past
/// what each sets.
#[repr(C, align(8))]
struct Attr([u8; 128]);

impl Attr {
    fn new() -> Attr {
        Attr([0; 128])
    }
    fn u32_at(mut self, offset: usize, value: u32) -> Attr {
        self.0[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        self
    }
    fn u64_at(mut self, offset: usize, value: u64) -> Attr {
        self.0[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
        self
    }
}

/// `BPF_ALU64 | BPF_MOV | BPF_K` r0 = 0, then `BPF_JMP | BPF_EXIT`.
const RETURN_ZERO: [u64; 2] = [0xb7, 0x95];
const LICENSE: &std::ffi::CStr = c"GPL";

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let bpf = |command: i64, attr: *const Attr, size: usize| {
        p.call_observed(Syscall::N_bpf, [command, attr as i64, size as i64, 0, 0, 0])
    };
    let size = std::mem::size_of::<Attr>();
    let map = |kind: u32| {
        Attr::new()
            .u32_at(0, kind)
            .u32_at(4, 4)
            .u32_at(8, 4)
            .u32_at(12, 1)
    };
    let array = map(BPF_MAP_TYPE_ARRAY);
    p.check(
        "an attribute size past a page is E2BIG",
        bpf(BPF_MAP_CREATE, &array, 8192) == neg(E2BIG),
    );
    p.check(
        "an unreadable attribute is EFAULT",
        bpf(BPF_MAP_CREATE, std::ptr::null(), size) == neg(EFAULT),
    );
    p.check(
        "an unknown command is EINVAL",
        bpf(UNKNOWN_COMMAND, &array, size) == neg(EINVAL),
    );
    p.check(
        "a map of no type is EINVAL before the privilege check",
        bpf(BPF_MAP_CREATE, &map(0), size) == neg(EINVAL),
    );
    p.check(
        "an array map is EPERM",
        bpf(BPF_MAP_CREATE, &array, size) == neg(EPERM),
    );
    let program = |flags: u32| {
        Attr::new()
            .u32_at(0, BPF_PROG_TYPE_SOCKET_FILTER)
            .u32_at(4, RETURN_ZERO.len() as u32)
            .u64_at(8, RETURN_ZERO.as_ptr() as u64)
            .u64_at(16, LICENSE.as_ptr() as u64)
            .u32_at(44, flags)
    };
    p.check(
        "a program with an unknown flag is EINVAL before the privilege check",
        bpf(BPF_PROG_LOAD, &program(UNKNOWN_PROG_FLAG), size) == neg(EINVAL),
    );
    p.check(
        "a socket filter is EPERM",
        bpf(BPF_PROG_LOAD, &program(0), size) == neg(EPERM),
    );
    p.check(
        "walking program ids is EPERM (no CAP_SYS_ADMIN)",
        bpf(BPF_PROG_GET_NEXT_ID, &Attr::new(), size) == neg(EPERM),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/bpf",
    run,
    // glibc has no wrapper for the row: the libc spelling would be
    // `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_bpf],
    needs: &[Need::Unprivileged, Need::RestrictedBpf],
    gaps: &[Gap {
        status: Status::Pending(Arc::Privileged),
        vehicles: Vehicle::KERNEL,
        what: "bpf is a fatal privileged trap (patina-syscalls linux.rs Trap(TRAP_PRIVILEGED)) where a kernel with unprivileged BPF disabled answers each command's argument checks and then EPERM",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(SIGABRT),
            diagnostic: TRAP,
        },
    }],
    ..DEFAULTS
};

#[cfg(target_arch = "x86_64")]
const TRAP: &str = "patina: SUD trapped unsupported syscall bpf (nr 321, class privileged";
#[cfg(target_arch = "aarch64")]
const TRAP: &str = "patina: SUD trapped unsupported syscall bpf (nr 280, class privileged";
