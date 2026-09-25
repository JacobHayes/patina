//! sys/admin — system administration refusals: the rows that check their
//! capability before any argument they take, so an unprivileged caller is
//! refused whatever it passes. Each is asked once, with every argument it
//! would check afterwards invalid:
//!
//! * `acct` (kernel/acct.c) needs `CAP_SYS_PACCT`: `EPERM` before its path
//!   is looked up;
//! * `vhangup` (fs/open.c) needs `CAP_SYS_TTY_CONFIG`: `EPERM`;
//! * `swapon` (mm/swapfile.c) refuses a flag outside `SWAP_FLAGS_VALID`
//!   (`EINVAL`) first, then needs `CAP_SYS_ADMIN` (`EPERM`) before its path
//!   is read; `swapoff` needs it first;
//! * `reboot` (kernel/reboot.c) needs `CAP_SYS_BOOT` before its magic
//!   numbers and command; `kexec_load` (`kexec_load_check`) and
//!   `kexec_file_load` need it in the initial user namespace before their
//!   flags, segments and descriptors;
//! * `init_module`, `finit_module` (`may_init_module`) and `delete_module`
//!   (kernel/module/main.c) need `CAP_SYS_MODULE` before their image, flags,
//!   descriptor or name;
//! * `pivot_root` (fs/namespace.c) needs `CAP_SYS_ADMIN` in the mount
//!   namespace's user namespace (`may_mount`) before its paths are read
//!   (7.0's `path_pivot_root` looks them up first, so NULL is `EFAULT`).
//!
//! Every call is one root would be refused too, so nothing is switched,
//! swapped, rebooted, loaded or unloaded: a missing accounting file
//! (`ENOENT`), an unknown swap flag or a NULL swap path (`EINVAL`,
//! `EFAULT`), an unknown reboot command (the libc vehicle's `reboot(howto)`
//! passes the magic numbers itself; the kernel vehicles pass none:
//! `EINVAL`), unknown `kexec` flags (`EINVAL`; `kexec_load` with no segments
//! and valid flags would unload the loaded image), an empty module image
//! (`ENOEXEC`), an unknown module flag (`EINVAL`), a NULL module name and
//! NULL root paths (`EFAULT`). `vhangup` takes no argument: the harness runs
//! the scenario only without a controlling terminal
//! (`Need::NoControllingTerminal`), which leaves it nothing to hang up.
//!
//! The libc vehicle goes through glibc's wrappers (`acct`, `vhangup`,
//! `swapon`, `swapoff`, `reboot`, `init_module`, `delete_module`,
//! `pivot_root`), which the shim does not define (registry `Absent`): it
//! reaches them through `dlsym`. `finit_module` and the `kexec` rows have
//! no wrapper; glibc's spelling is `syscall(2)`.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::ffi::CString;

/// Outside `SWAP_FLAGS_VALID`.
const UNKNOWN_SWAP_FLAG: i64 = 1 << 30;
/// No `LINUX_REBOOT_CMD_*` command.
const UNKNOWN_REBOOT_CMD: i64 = 0x7a7a_7a7a;
/// No `KEXEC_*` flag (and no architecture in the high half).
const UNKNOWN_KEXEC_FLAG: i64 = 0x80;
/// Past `KEXEC_SEGMENT_MAX`.
const TOO_MANY_SEGMENTS: i64 = 17;
/// No `KEXEC_FILE_*` flag.
const UNKNOWN_KEXEC_FILE_FLAG: i64 = 1 << 20;
/// No `MODULE_INIT_*` flag.
const UNKNOWN_MODULE_FLAG: i64 = 1 << 20;

pub fn run(p: &Probe) {
    p.require_unprivileged();
    let missing = CString::new(format!("{}/missing", p.dir())).unwrap();
    let params = c"".as_ptr() as i64;
    for (row, args, errno, label) in [
        (
            Syscall::N_acct,
            [missing.as_ptr() as i64, 0, 0, 0, 0, 0],
            EPERM,
            "acct is EPERM (no CAP_SYS_PACCT) before its path is looked up",
        ),
        (
            Syscall::N_vhangup,
            [0; 6],
            EPERM,
            "vhangup is EPERM (no CAP_SYS_TTY_CONFIG)",
        ),
        (
            Syscall::N_swapon,
            [0, UNKNOWN_SWAP_FLAG, 0, 0, 0, 0],
            EINVAL,
            "swapon refuses an unknown flag first, before its path is read",
        ),
        (
            Syscall::N_swapon,
            [0; 6],
            EPERM,
            "then swapon is EPERM (no CAP_SYS_ADMIN) before its path is read",
        ),
        (
            Syscall::N_swapoff,
            [0; 6],
            EPERM,
            "swapoff is EPERM before its path is read",
        ),
        (
            Syscall::N_reboot,
            [0, 0, UNKNOWN_REBOOT_CMD, 0, 0, 0],
            EPERM,
            "reboot is EPERM (no CAP_SYS_BOOT) before its magic numbers and command",
        ),
        (
            Syscall::N_kexec_load,
            [0, TOO_MANY_SEGMENTS, 0, UNKNOWN_KEXEC_FLAG, 0, 0],
            EPERM,
            "kexec_load is EPERM before its flags and segment count",
        ),
        (
            Syscall::N_kexec_file_load,
            [-1, -1, 0, 0, UNKNOWN_KEXEC_FILE_FLAG, 0],
            EPERM,
            "kexec_file_load is EPERM before its flags and descriptors",
        ),
        (
            Syscall::N_init_module,
            [0, 0, params, 0, 0, 0],
            EPERM,
            "init_module is EPERM (no CAP_SYS_MODULE) before its image is read",
        ),
        (
            Syscall::N_finit_module,
            [-1, params, UNKNOWN_MODULE_FLAG, 0, 0, 0],
            EPERM,
            "finit_module is EPERM before its flags and descriptor",
        ),
        (
            Syscall::N_delete_module,
            [0; 6],
            EPERM,
            "delete_module is EPERM before its name is read",
        ),
    ] {
        p.check(label, p.call_observed(row, args) == neg(errno));
    }
    p.check(
        "pivot_root of NULL paths is EPERM (no CAP_SYS_ADMIN) before they are read",
        p.call_observed(Syscall::N_pivot_root, [0; 6]) == neg(EPERM),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/admin",
    run,
    covers: &[
        Syscall::N_acct,
        Syscall::N_vhangup,
        Syscall::N_swapon,
        Syscall::N_swapoff,
        Syscall::N_reboot,
        Syscall::N_kexec_load,
        Syscall::N_kexec_file_load,
        Syscall::N_init_module,
        Syscall::N_finit_module,
        Syscall::N_delete_module,
        Syscall::N_pivot_root,
    ],
    symbols: &[
        "acct",
        "vhangup",
        "swapon",
        "swapoff",
        "reboot",
        "init_module",
        "delete_module",
        "pivot_root",
        "syscall",
    ],
    resolves: &[
        "acct",
        "vhangup",
        "swapon",
        "swapoff",
        "reboot",
        "init_module",
        "delete_module",
        "pivot_root",
    ],
    needs: &[Need::Unprivileged, Need::NoControllingTerminal],
    gaps: &[
        Gap {
            status: Status::Pending(Arc::Privileged),
            vehicles: Vehicle::KERNEL,
            what: "acct is a fatal privileged trap (patina-syscalls linux.rs Trap(TRAP_PRIVILEGED)), as are vhangup, swapon, swapoff, reboot, kexec_load, kexec_file_load, init_module, finit_module, delete_module and pivot_root, where the unprivileged caller is refused by the capability check before any argument (swapon's flags aside)",
            failure: Failure::Stops {
                events: 0,
                ending: Ending::Signal(SIGABRT),
                diagnostic: TRAP,
            },
        },
        Gap {
            status: Status::Pending(Arc::Privileged),
            vehicles: &[Vehicle::Libc],
            what: "the shim defines none of glibc's administration wrappers (registry `Absent`): a guest importing one is refused by the pre-run audit, and `dlsym` finds none (the shim's `__wrap_dlsym` answers only the names in its fixed routing table, c/posix/dlsym.c `patina_dlsym_route`), so the libc leg stops at its first call",
            failure: Failure::Stops {
                events: 0,
                ending: Ending::Exit(101),
                diagnostic: "sys/admin: cannot continue: glibc's acct resolves",
            },
        },
    ],
    ..DEFAULTS
};

#[cfg(target_arch = "x86_64")]
const TRAP: &str = "patina: SUD trapped unsupported syscall acct (nr 163, class privileged";
#[cfg(target_arch = "aarch64")]
const TRAP: &str = "patina: SUD trapped unsupported syscall acct (nr 89, class privileged";
