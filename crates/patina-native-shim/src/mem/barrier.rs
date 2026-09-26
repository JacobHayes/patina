//! `membarrier(2)` (kernel/sched/membarrier.c) for the one virtual process:
//! every barrier is trivially satisfied in one process under a cooperative
//! scheduler, so the commands are validated and the registrations kept, and
//! nothing is ever passed to the host.

use crate::EINVAL;
use std::ffi::c_int;
use std::sync::atomic::Ordering;

/// `enum membarrier_cmd` (uapi/linux/membarrier.h).
const MEMBARRIER_CMD_QUERY: c_int = 0;
const MEMBARRIER_CMD_GLOBAL: c_int = 1 << 0;
const MEMBARRIER_CMD_GLOBAL_EXPEDITED: c_int = 1 << 1;
const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: c_int = 1 << 2;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED: c_int = 1 << 3;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: c_int = 1 << 4;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: c_int = 1 << 5;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: c_int = 1 << 6;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ: c_int = 1 << 7;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ: c_int = 1 << 8;
const MEMBARRIER_CMD_GET_REGISTRATIONS: c_int = 1 << 9;
const MEMBARRIER_CMD_FLAG_CPU: u32 = 1 << 0;
/// What `MEMBARRIER_CMD_QUERY` answers: every command (restartable
/// sequences are modeled, `crate::thread::registrations`).
const MEMBARRIER_COMMANDS: c_int = MEMBARRIER_CMD_GLOBAL
    | MEMBARRIER_CMD_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ
    | MEMBARRIER_CMD_GET_REGISTRATIONS;

/// The process's membarrier registrations, as the registration commands name
/// them (`MEMBARRIER_CMD_GET_REGISTRATIONS` answers exactly this). Registering
/// for sync-core also registers the plain private expedited state, which is
/// what the kernel's `membarrier_state` reports, but not its readiness; so
/// does registering for rseq.
static MEMBARRIER_REGISTERED: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
/// The registrations a barrier checks (`*_READY`).
static MEMBARRIER_READY: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// `membarrier(2)` (kernel/sched/membarrier.c) for the one virtual process.
pub(crate) fn membarrier(cmd: c_int, flags: u32, _cpu_id: c_int) -> i64 {
    let flags_allowed = if cmd == MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ {
        MEMBARRIER_CMD_FLAG_CPU
    } else {
        0
    };
    if flags & !flags_allowed != 0 {
        return -i64::from(EINVAL);
    }
    let barrier = |ready: c_int| {
        if MEMBARRIER_READY.load(Ordering::Acquire) & ready == 0 {
            -i64::from(crate::EPERM)
        } else {
            0
        }
    };
    let register = |registration: c_int| {
        MEMBARRIER_REGISTERED.fetch_or(registration, Ordering::AcqRel);
        0
    };
    match cmd {
        MEMBARRIER_CMD_QUERY => i64::from(MEMBARRIER_COMMANDS),
        MEMBARRIER_CMD_GLOBAL | MEMBARRIER_CMD_GLOBAL_EXPEDITED => 0,
        MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED => {
            MEMBARRIER_READY.fetch_or(cmd, Ordering::AcqRel);
            register(cmd)
        }
        MEMBARRIER_CMD_PRIVATE_EXPEDITED => barrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED),
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED => {
            MEMBARRIER_READY.fetch_or(cmd, Ordering::AcqRel);
            register(cmd)
        }
        MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE => {
            barrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE)
        }
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
            MEMBARRIER_READY.fetch_or(cmd, Ordering::AcqRel);
            register(cmd | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED)
        }
        // No sequence is ever running on another CPU: every task runs on the
        // one virtual CPU, and a sequence is never preempted.
        MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ => {
            barrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ)
        }
        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ => {
            MEMBARRIER_READY.fetch_or(cmd, Ordering::AcqRel);
            register(cmd | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED)
        }
        MEMBARRIER_CMD_GET_REGISTRATIONS => {
            i64::from(MEMBARRIER_REGISTERED.load(Ordering::Acquire))
        }
        _ => -i64::from(EINVAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membarrier_validates_then_answers_from_the_registrations() {
        // Process-global state: this is the only test that touches it.
        assert_eq!(
            membarrier(MEMBARRIER_CMD_QUERY, 0, 0),
            i64::from(MEMBARRIER_COMMANDS)
        );
        assert_eq!(membarrier(MEMBARRIER_CMD_QUERY, 1, 0), -i64::from(EINVAL));
        assert_eq!(membarrier(1 << 20, 0, 0), -i64::from(EINVAL));
        // The rseq barrier takes the CPU flag (and no other), and waits for
        // its own registration.
        assert_eq!(
            membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ, 2, 0),
            -i64::from(EINVAL)
        );
        assert_eq!(
            membarrier(
                MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ,
                MEMBARRIER_CMD_FLAG_CPU,
                0
            ),
            -i64::from(crate::EPERM)
        );
        assert_eq!(
            membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0),
            -i64::from(crate::EPERM)
        );
        assert_eq!(
            membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0),
            0
        );
        // Sync-core registration makes only the sync-core barrier ready.
        assert_eq!(
            membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0),
            -i64::from(crate::EPERM)
        );
        assert_eq!(
            membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0),
            0
        );
        assert_eq!(
            membarrier(MEMBARRIER_CMD_GET_REGISTRATIONS, 0, 0),
            i64::from(
                MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
                    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
            )
        );
        assert_eq!(
            membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0),
            0
        );
        assert_eq!(membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0), 0);
        assert_eq!(
            membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 1, 0),
            -i64::from(EINVAL)
        );
        assert_eq!(membarrier(MEMBARRIER_CMD_GLOBAL_EXPEDITED, 0, 0), 0);
        assert_eq!(
            membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ, 0, 0),
            0
        );
        assert_eq!(
            membarrier(
                MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ,
                MEMBARRIER_CMD_FLAG_CPU,
                0
            ),
            0
        );
        assert_eq!(
            membarrier(MEMBARRIER_CMD_GET_REGISTRATIONS, 0, 0),
            i64::from(
                MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
                    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
                    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ
            )
        );
    }
}
