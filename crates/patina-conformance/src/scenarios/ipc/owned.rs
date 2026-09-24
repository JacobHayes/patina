//! IPC objects outlive the process that made them, so every object a
//! scenario creates is removed even when the scenario stops early: an
//! [`Owned`] issues its removal (unrecorded, through `syscall(2)`) when it is
//! dropped still armed — a failed `require` unwinding past it — and the
//! scenario disarms it once its own recorded removal succeeds. A run killed
//! outright unwinds nothing; the harness then sweeps the keyed objects and
//! the queue name ([`crate::owned::sweep`]).

use patina_dst_syscalls::Syscall;
use std::cell::Cell;
use std::ffi::CString;

pub struct Owned {
    row: Syscall,
    args: [i64; 3],
    /// A name the removal passes by pointer (`mq_unlink`).
    name: Option<CString>,
    armed: Cell<bool>,
}

impl Owned {
    /// A System V object: `shmctl`/`semctl`/`msgctl` with `IPC_RMID`.
    pub fn sysv(row: Syscall, id: i32) -> Owned {
        let args = match row {
            Syscall::N_semctl => [id as i64, 0, libc::IPC_RMID as i64],
            _ => [id as i64, libc::IPC_RMID as i64, 0],
        };
        Owned {
            row,
            args,
            name: None,
            armed: Cell::new(id >= 0),
        }
    }

    /// A POSIX message queue: `mq_unlink(name)`.
    pub fn mqueue(name: &str) -> Owned {
        Owned {
            row: Syscall::N_mq_unlink,
            args: [0; 3],
            name: Some(CString::new(name).expect("no interior NUL")),
            armed: Cell::new(true),
        }
    }

    /// The scenario removed it (its recorded removal answered `result`).
    /// `IPC_RMID` of a still-attached segment only marks it `SHM_DEST`; the
    /// process's exit-time detach destroys it, so a guard never detaches
    /// first — a detach would unmap memory the unwinding scenario may still
    /// reference.
    pub fn removed(&self, result: i64) {
        if result == 0 {
            self.armed.set(false);
        }
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.armed.get() {
            return;
        }
        let first = match &self.name {
            Some(name) => name.as_ptr() as i64,
            None => self.args[0],
        };
        // SAFETY: the removal of an object this run created; the name, when
        // there is one, lives until the call returns.
        unsafe {
            libc::syscall(
                self.row.number() as libc::c_long,
                first,
                self.args[1],
                self.args[2],
            );
        }
    }
}
