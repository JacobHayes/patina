//! sys/padding — Linux clears ABI padding in these syscall outputs. The
//! native leg is the live host reference; every output starts as `0xAA`, and
//! only the padding bytes are compared so virtual fields may differ.

use crate::catalog::{DEFAULTS, Need, Scenario};
use crate::owned::{MSG_PROJECT, SEM_PROJECT, SHM_PROJECT};
use crate::probe::{MsgArg, Probe, SemArg, ShmArg, page_size};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use std::mem::{offset_of, size_of};
use std::ops::Range;

#[repr(C, align(8))]
struct Prefilled<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Prefilled<N> {
    fn aa() -> Self {
        Self { bytes: [0xaa; N] }
    }

    fn address(&mut self) -> i64 {
        self.bytes.as_mut_ptr() as usize as i64
    }

    fn is_zero(&self, range: Range<usize>) -> bool {
        self.bytes[range].iter().all(|byte| *byte == 0)
    }
}

pub fn run(p: &Probe) {
    // x86_64 stack_t has four padding bytes between ss_flags and ss_size.
    let mut old_stack = Prefilled::<{ size_of::<stack_t>() }>::aa();
    let rc = p.call_observed(Syscall::N_sigaltstack, [0, old_stack.address(), 0, 0, 0, 0]);
    let stack_pad =
        offset_of!(stack_t, ss_flags) + size_of::<c_int>()..offset_of!(stack_t, ss_size);
    p.check(
        "sigaltstack clears old-value padding",
        rc == 0 && old_stack.is_zero(stack_pad),
    );

    let mut info = Prefilled::<{ size_of::<sysinfo>() }>::aa();
    let rc = p.call_observed(Syscall::N_sysinfo, [info.address(), 0, 0, 0, 0, 0]);
    // `sysinfo` has a four-byte alignment gap before totalhigh and four tail
    // bytes after mem_unit on the 64-bit kernel ABI.
    let info_pad = offset_of!(sysinfo, totalhigh) - 4..offset_of!(sysinfo, totalhigh);
    let info_tail = offset_of!(sysinfo, mem_unit) + size_of::<c_uint>()..size_of::<sysinfo>();
    p.check(
        "sysinfo clears structure padding",
        rc == 0 && info.is_zero(info_pad) && info.is_zero(info_tail),
    );

    let root = p.dir();
    let dirfd = p.openat(AT_FDCWD, &root, O_RDONLY | O_DIRECTORY, 0);
    p.require("open the run directory", dirfd >= 0);
    let (stat_rc, stat) = p.fstat(dirfd);
    p.require("fstat the run directory", stat_rc == 0 && stat.is_some());
    let dev = stat.expect("fstat succeeded").dev;

    let mut ustat = Prefilled::<32>::aa();
    let rc = p.call_observed(Syscall::N_ustat, [dev as i64, ustat.address(), 0, 0, 0, 0]);
    p.check(
        "ustat clears structure padding",
        rc == 0 && ustat.is_zero(4..8) && ustat.is_zero(28..32),
    );
    p.close(dirfd);

    let msgid = p.msgget(
        p.owned_key(MSG_PROJECT, "padding-msg"),
        IPC_CREAT | IPC_EXCL | 0o600,
    );
    p.require("create the message queue", msgid >= 0);
    let mut msg_stat = Prefilled::<{ size_of::<msqid_ds>() }>::aa();
    let rc = p.call_observed(
        Syscall::N_msgctl,
        [msgid as i64, IPC_STAT as i64, msg_stat.address(), 0, 0, 0],
    );
    p.check(
        "msgctl IPC_STAT clears ipc_perm padding",
        rc == 0 && msg_stat.is_zero(28..32),
    );
    p.check(
        "remove the message queue",
        p.msgctl(msgid, IPC_RMID, MsgArg::None).0 == 0,
    );

    let semid = p.semget(
        p.owned_key(SEM_PROJECT, "padding-sem"),
        1,
        IPC_CREAT | IPC_EXCL | 0o600,
    );
    p.require("create the semaphore set", semid >= 0);
    let mut sem_stat = Prefilled::<{ size_of::<semid_ds>() }>::aa();
    let rc = p.call_observed(
        Syscall::N_semctl,
        [semid as i64, 0, IPC_STAT as i64, sem_stat.address(), 0, 0],
    );
    p.check(
        "semctl IPC_STAT clears ipc_perm padding",
        rc == 0 && sem_stat.is_zero(28..32),
    );
    p.check(
        "remove the semaphore set",
        p.semctl(semid, 0, IPC_RMID, &SemArg::None).0 == 0,
    );

    let shmid = p.shmget(
        p.owned_key(SHM_PROJECT, "padding-shm"),
        page_size(),
        IPC_CREAT | IPC_EXCL | 0o600,
    );
    p.require("create the shared-memory segment", shmid >= 0);
    let mut shm_stat = Prefilled::<{ size_of::<shmid_ds>() }>::aa();
    let rc = p.call_observed(
        Syscall::N_shmctl,
        [shmid as i64, IPC_STAT as i64, shm_stat.address(), 0, 0, 0],
    );
    p.check(
        "shmctl IPC_STAT clears ipc_perm padding",
        rc == 0 && shm_stat.is_zero(28..32),
    );
    p.check(
        "remove the shared-memory segment",
        p.shmctl(shmid, IPC_RMID, ShmArg::None).0 == 0,
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/padding",
    run,
    covers: &[
        Syscall::N_sigaltstack,
        Syscall::N_sysinfo,
        Syscall::N_ustat,
        Syscall::N_msgget,
        Syscall::N_msgctl,
        Syscall::N_semget,
        Syscall::N_semctl,
        Syscall::N_shmget,
        Syscall::N_shmctl,
        Syscall::N_openat,
        Syscall::N_fstat,
        Syscall::N_close,
    ],
    vehicles: Vehicle::KERNEL,
    symbols: &["syscall"],
    needs: &[Need::SysvMsg, Need::SysvSem, Need::SysvShm],
    ..DEFAULTS
};
