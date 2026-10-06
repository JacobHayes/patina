//! Human-reviewed Linux runtime dispositions. Source identity and numbers are
//! generated; adding an upstream identity makes this exhaustive match fail until
//! its actual runtime disposition is reviewed. Never infer ENOSYS from novelty.

use super::{Capability, TRAP_PRIVILEGED, TRAP_PROCESS, TRAP_UNMODELED};
use super::{Disposition, Family, IDENTITY_PID, INIT_PID, Syscall, SyscallRow};

use super::linux_row::r;

const ENOSYS: i32 = 38;

// Rows are split for readability, then concatenated into a single exhaustive
// match. No fallback arm can let a new generated syscall skip policy review.
macro_rules! define_policy {
    ($id:ident, $($rows:tt)*) => {
        pub const fn disposition($id: Syscall) -> SyscallRow {
            if !$id.is_implemented() { return super::linux_row::removed($id); }
            match $id { $($rows)* }
        }
    };
}
mod early;
mod late;
use early::early_rows;
use late::late_rows;
early_rows! { id, late_rows }

const fn rows() -> [SyscallRow; Syscall::ALL.len()] {
    let mut rows = [disposition(Syscall::ALL[0]); Syscall::ALL.len()];
    let mut i = 0;
    while i < rows.len() {
        rows[i] = disposition(Syscall::ALL[i]);
        i += 1;
    }
    rows
}

pub const SYSCALLS: &[SyscallRow] = &rows();
