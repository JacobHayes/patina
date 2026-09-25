//! The IPC names a run owns, derived from its run directory, and their sweep.
//!
//! System V objects and POSIX message queues outlive the process that made
//! them. A scenario removes its own on every path it unwinds through
//! (`scenarios/ipc/owned.rs`), but a native run killed outright (the harness
//! deadline, SIGKILL) unwinds nothing, and the next vehicle's run recreates
//! the same directory — very likely on the same inode, so the same `ftok(3)`
//! keys — and would find the leak as `EEXIST`. The harness therefore calls
//! [`sweep`] after every native run, whatever its exit: every keyed object and
//! queue name a run can own is derived here, in one place, from the run
//! directory. (`IPC_PRIVATE` objects have no name to derive; a killed run
//! leaks those until a ledger records them.)

use patina_dst_syscalls::Syscall;
use std::ffi::CString;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The `ftok(3)` project byte of each keyed object kind a scenario creates.
pub const SHM_PROJECT: u8 = b'S';
pub const SEM_PROJECT: u8 = b'E';
pub const MSG_PROJECT: u8 = b'M';

/// glibc's `ftok(3)` of `dir` with `proj`: the inode's low 16 bits, the
/// device's low 8, `proj` on top. Computed from `stat` rather than imported
/// (the probe binary cannot import a wrapper the shim does not define).
pub fn key(dir: &Path, proj: u8) -> std::io::Result<i32> {
    let meta = std::fs::metadata(dir)?;
    let raw =
        (meta.ino() & 0xffff) as u32 | ((meta.dev() & 0xff) as u32) << 16 | u32::from(proj) << 24;
    Ok(raw as i32)
}

/// The POSIX message queue name (the kernel row's, without a leading slash)
/// a run in `dir` owns: its owned parent directory's name, which the harness
/// makes unique per scenario.
pub fn mq_name(dir: &Path) -> String {
    let owner = dir
        .parent()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("{owner}-mq")
}

/// `row` with three arguments through `syscall(2)`, unrecorded: the result,
/// or -1.
pub fn sys(row: Syscall, args: [i64; 3]) -> i64 {
    // SAFETY: integer arguments, or a NUL-terminated name the caller owns.
    let result = unsafe { libc::syscall(row.number() as libc::c_long, args[0], args[1], args[2]) };
    if result < 0 { -1 } else { result }
}

/// The arguments of `ctl` (`shmctl`, `semctl`, `msgctl`) removing object
/// `id` with `IPC_RMID` (`semctl` takes a semaphore number first).
pub fn rmid_args(ctl: Syscall, id: i64) -> [i64; 3] {
    match ctl {
        Syscall::N_semctl => [id, 0, libc::IPC_RMID as i64],
        _ => [id, libc::IPC_RMID as i64, 0],
    }
}

/// Remove every IPC object a run in `dir` may have left behind; answer what
/// was removed (`shm key=…`, `mq name`). A directory that no longer exists
/// owns no key.
pub fn sweep(dir: &Path) -> Vec<String> {
    let mut removed = Vec::new();
    if let Ok(name) = CString::new(mq_name(dir)) {
        if sys(Syscall::N_mq_unlink, [name.as_ptr() as i64, 0, 0]) == 0 {
            removed.push(format!("mq {}", mq_name(dir)));
        }
    }
    let kinds = [
        ("shm", SHM_PROJECT, Syscall::N_shmget, Syscall::N_shmctl),
        ("sem", SEM_PROJECT, Syscall::N_semget, Syscall::N_semctl),
        ("msg", MSG_PROJECT, Syscall::N_msgget, Syscall::N_msgctl),
    ];
    for (kind, proj, get, ctl) in kinds {
        let Ok(key) = key(dir, proj) else { continue };
        // `xxxget(key, 0, 0)` names an existing object without creating one.
        let id = sys(get, [key as i64, 0, 0]);
        if id < 0 {
            continue;
        }
        if sys(ctl, rmid_args(ctl, id)) == 0 {
            removed.push(format!("{kind} key={key:#x}"));
        }
    }
    removed
}
