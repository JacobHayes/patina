//! Linux `readlink` lengths are kernel `int` values, even though libc exposes
//! `size_t` and the syscall register is word-sized.

use crate::catalog::{DEFAULTS, Scenario};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::Vehicle;
use libc::{EINVAL, O_CREAT, O_EXCL, O_WRONLY};
use patina_dst_syscalls::Syscall;

const CASES: [(usize, i64, &str); 3] = [
    (1 << 32, neg(EINVAL), ""),
    (0x8000_0000, neg(EINVAL), ""),
    (0x1_0000_0004, 4, "long"),
];

pub fn run(p: &Probe) {
    let root = p.dir();
    let target_path = format!("{root}/target");
    let link_path = format!("{root}/link");
    let fd = p.openat(AT_FDCWD, &target_path, O_WRONLY | O_CREAT | O_EXCL, 0o600);
    p.require("create the readlink target", fd >= 0);
    p.close(fd);
    p.require(
        "create link",
        p.symlinkat("long-target", AT_FDCWD, &link_path) == 0,
    );

    for (size, expected, target) in CASES {
        let (result, copied) = p.readlinkat_with_buffer(AT_FDCWD, &link_path, size, 16);
        p.check(
            &format!("readlinkat kernel int length {size:#x}"),
            result == expected && copied == target,
        );
    }

    #[cfg(target_arch = "x86_64")]
    for (size, expected, target) in CASES {
        let (result, copied) = p.readlink_with_buffer(&link_path, size, 16);
        p.check(
            &format!("readlink kernel int length {size:#x}"),
            result == expected && copied == target,
        );
    }
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/readlink_width",
    run,
    vehicles: Vehicle::ALL,
    covers: &[
        Syscall::N_readlinkat,
        #[cfg(target_arch = "x86_64")]
        Syscall::N_readlink,
    ],
    symbols: &["readlink", "readlinkat"],
    ..DEFAULTS
};
