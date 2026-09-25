//! fs/handles — name_to_handle_at (open_by_handle_at(2); fs/fhandle.c), the
//! unprivileged half of the file-handle pair. A handle buffer too small is
//! EOVERFLOW with the required size written back, and that size then
//! succeeds; a declared size past MAX_HANDLE_SZ, or an unknown flag, is
//! EINVAL. A handle names an inode: the same file twice and its hard link
//! give the same handle, another file a different one; a symlink is its own
//! inode unless AT_SYMLINK_FOLLOW; AT_EMPTY_PATH names the descriptor; a
//! directory has a handle; every name on one mount reports one mount id;
//! AT_HANDLE_FID (Linux 6.5) asks for an identifier-only handle. ENOENT,
//! ENOTDIR and EBADF as for any `*at` path. Handle bytes and mount ids are
//! the filesystem's business and are compared only by relation. Needs file
//! handles on the run directory's filesystem.

use crate::catalog::{DEFAULTS, KernelFloor, Need, Scenario};
use crate::vehicle::Vehicle;

use patina_dst_syscalls::Syscall;

use crate::probe::{AT_FDCWD, Probe, neg};
use libc::*;

/// A flag bit name_to_handle_at does not define in any release (the low bits
/// became AT_HANDLE_MNT_ID_UNIQUE and AT_HANDLE_CONNECTABLE in 6.12/6.13).
const UNKNOWN_HANDLE_FLAG: i32 = 0x8000;

pub fn run(p: &Probe) {
    let root = p.dir();
    let file = format!("{root}/f");
    let other = format!("{root}/g");
    let hard = format!("{root}/h");
    let link = format!("{root}/l");
    let dir = format!("{root}/d");
    let fd = p.openat(AT_FDCWD, &file, O_RDWR | O_CREAT | O_EXCL, 0o644);
    let fd_other = p.openat(AT_FDCWD, &other, O_RDWR | O_CREAT | O_EXCL, 0o644);
    p.require("create f and g", fd >= 0 && fd_other >= 0);
    p.check(
        "linkat f -> h",
        p.linkat(AT_FDCWD, &file, AT_FDCWD, &hard, 0) == 0,
    );
    p.check("symlinkat l -> f", p.symlinkat("f", AT_FDCWD, &link) == 0);
    p.check("mkdirat d", p.mkdirat(AT_FDCWD, &dir, 0o755) == 0);

    let (r, needed, _, _) = p.name_to_handle_at(AT_FDCWD, &file, 0, 0);
    p.check(
        "a zero-size handle is EOVERFLOW with the required size written back",
        r == neg(EOVERFLOW) && needed > 0 && needed <= MAX_HANDLE_SZ as u32,
    );
    let (r, bytes, handle, mount) = p.name_to_handle_at(AT_FDCWD, &file, needed, 0);
    p.check(
        "the required size succeeds and is what the handle uses",
        r == 0 && bytes == needed,
    );
    let (r, _, again, mount_again) = p.name_to_handle_at(AT_FDCWD, &file, MAX_HANDLE_SZ as u32, 0);
    p.check(
        "the same file gives the same handle and mount id",
        r == 0 && again == handle && mount_again == mount,
    );
    let (r, _, via_hard, _) = p.name_to_handle_at(AT_FDCWD, &hard, MAX_HANDLE_SZ as u32, 0);
    p.check(
        "a hard link gives the same handle",
        r == 0 && via_hard == handle,
    );
    let (r, _, of_other, mount_other) =
        p.name_to_handle_at(AT_FDCWD, &other, MAX_HANDLE_SZ as u32, 0);
    p.check(
        "another file gives another handle on the same mount",
        r == 0 && of_other != handle && mount_other == mount,
    );
    let (r, _, of_link, _) = p.name_to_handle_at(AT_FDCWD, &link, MAX_HANDLE_SZ as u32, 0);
    p.check(
        "without AT_SYMLINK_FOLLOW a symlink is its own inode",
        r == 0 && of_link != handle,
    );
    let (r, _, followed, _) =
        p.name_to_handle_at(AT_FDCWD, &link, MAX_HANDLE_SZ as u32, AT_SYMLINK_FOLLOW);
    p.check(
        "AT_SYMLINK_FOLLOW names the target",
        r == 0 && followed == handle,
    );
    let (r, _, by_fd, _) = p.name_to_handle_at(fd, "", MAX_HANDLE_SZ as u32, AT_EMPTY_PATH);
    p.check(
        "AT_EMPTY_PATH names the descriptor",
        r == 0 && by_fd == handle,
    );
    let (r, _, of_dir, mount_dir) = p.name_to_handle_at(AT_FDCWD, &dir, MAX_HANDLE_SZ as u32, 0);
    p.check(
        "a directory has a handle on the same mount",
        r == 0 && of_dir != handle && mount_dir == mount,
    );
    let (r, fid_bytes, _, fid_mount) =
        p.name_to_handle_at(AT_FDCWD, &file, MAX_HANDLE_SZ as u32, AT_HANDLE_FID);
    p.check(
        "AT_HANDLE_FID gives an identifier on the same mount",
        r == 0 && fid_bytes > 0 && fid_mount == mount,
    );
    p.check(
        "a declared size past MAX_HANDLE_SZ is EINVAL",
        p.name_to_handle_at(AT_FDCWD, &file, MAX_HANDLE_SZ as u32 + 1, 0)
            .0
            == neg(EINVAL),
    );
    p.check(
        "an unknown flag is EINVAL",
        p.name_to_handle_at(AT_FDCWD, &file, MAX_HANDLE_SZ as u32, UNKNOWN_HANDLE_FLAG)
            .0
            == neg(EINVAL),
    );
    p.check(
        "a missing name is ENOENT",
        p.name_to_handle_at(
            AT_FDCWD,
            &format!("{root}/missing"),
            MAX_HANDLE_SZ as u32,
            0,
        )
        .0 == neg(ENOENT),
    );
    p.check(
        "a path through a file is ENOTDIR",
        p.name_to_handle_at(AT_FDCWD, &format!("{file}/x"), MAX_HANDLE_SZ as u32, 0)
            .0
            == neg(ENOTDIR),
    );
    p.check(
        "a relative path from a closed descriptor is EBADF",
        p.name_to_handle_at(4000, "f", MAX_HANDLE_SZ as u32, 0).0 == neg(EBADF),
    );
    p.close(fd);
    p.close(fd_other);
}

pub const SCENARIO: Scenario = Scenario {
    name: "fs/handles",
    run,
    // The shim does not define name_to_handle_at, so its libc spelling would
    // be `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_name_to_handle_at,
        Syscall::N_openat,
        Syscall::N_linkat,
        Syscall::N_symlinkat,
        Syscall::N_mkdirat,
        Syscall::N_close,
    ],
    needs: &[Need::FileHandles],
    kernel_floor: Some(KernelFloor {
        release: "6.5",
        why: "AT_HANDLE_FID",
    }),
    ..DEFAULTS
};
