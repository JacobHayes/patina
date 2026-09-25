//! proc/vm_rw — copying memory between address spaces aimed at the caller
//! itself (mm/process_vm_access.c `process_vm_rw`), as 6.8 answers it:
//!
//! * a read copies the remote ranges into the local ones and answers the
//!   bytes copied, gathered and scattered across either side's vectors, and
//!   a write copies the other way;
//! * a flag is `EINVAL`, as is a vector longer than `IOV_MAX` on either
//!   side; a pid no process has is `ESRCH`; no vectors copy nothing (0);
//! * a fault on either side before anything is copied is `EFAULT`, and one
//!   after a first range is a short count: the copy stops at the fault.
//!
//! The ptrace-mode check these calls make passes for the caller's own
//! process. Only the caller's own memory is ever named: another process's
//! would be a cross-process effect the single-process model has no
//! counterpart for. glibc 2.39 wraps both rows, but the registry has no
//! symbol row for them (the shim defines neither), so the probe binary
//! cannot import them — the pre-run audit would refuse it — and the
//! scenario runs through the kernel vehicles.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::observe::{Id, Norm};
use crate::probe::{NO_SUCH_PID, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

/// An address below `vm.mmap_min_addr`: never mapped.
const UNMAPPED: usize = 0x1000;
/// One more vector than `IOV_MAX` (`UIO_MAXIOV`).
const TOO_MANY: usize = 1025;

/// One side's vector, as the event records it: each range's length and
/// whether it is mapped (never its address).
fn shape(ranges: &[iovec]) -> Value {
    ranges
        .iter()
        .map(|range| {
            serde_json::json!({
                "len": range.iov_len,
                "mapped": range.iov_base as usize != UNMAPPED,
            })
        })
        .collect::<Vec<_>>()
        .into()
}

fn range(bytes: &mut [u8]) -> iovec {
    iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    }
}

fn unmapped(len: usize) -> iovec {
    iovec {
        iov_base: UNMAPPED as *mut c_void,
        iov_len: len,
    }
}

/// `process_vm_readv` (`write` false) or `process_vm_writev` of `pid`, with
/// `counts` overriding the vectors' lengths.
fn copy(
    p: &Probe,
    write: bool,
    pid: i32,
    local: &[iovec],
    remote: &[iovec],
    counts: Option<(usize, usize)>,
    flags: i64,
) -> i64 {
    let row = if write {
        Syscall::N_process_vm_writev
    } else {
        Syscall::N_process_vm_readv
    };
    let (liovcnt, riovcnt) = counts.unwrap_or((local.len(), remote.len()));
    let result = p.call_unrecorded(
        row,
        [
            pid as i64,
            local.as_ptr() as i64,
            liovcnt as i64,
            remote.as_ptr() as i64,
            riovcnt as i64,
            flags,
        ],
    );
    p.rec
        .event(row.name(), result)
        .arg("pid", pid)
        .norm("args.pid", Norm::Identity(Id::Process))
        .arg("local", shape(local))
        .arg("liovcnt", liovcnt)
        .arg("remote", shape(remote))
        .arg("riovcnt", riovcnt)
        .arg("flags", flags)
        .emit();
    result
}

pub fn run(p: &Probe) {
    let pid = p.getpid() as i32;
    let mut source = *b"abcdefg";
    let mut target = [0u8; 7];
    p.check(
        "process_vm_readv of itself copies the remote range",
        copy(
            p,
            false,
            pid,
            &[range(&mut target)],
            &[range(&mut source)],
            None,
            0,
        ) == 7
            && target == source,
    );
    let mut head = [0u8; 3];
    let mut tail = [0u8; 4];
    p.check(
        "a read scatters one remote range across two local ones",
        copy(
            p,
            false,
            pid,
            &[range(&mut head), range(&mut tail)],
            &[range(&mut source)],
            None,
            0,
        ) == 7
            && head == *b"abc"
            && tail == *b"defg",
    );
    let mut patch = *b"XYZ";
    p.check(
        "process_vm_writev of itself copies into the remote range",
        copy(
            p,
            true,
            pid,
            &[range(&mut patch)],
            &[range(&mut source[..3])],
            None,
            0,
        ) == 3
            && source == *b"XYZdefg",
    );
    p.check(
        "a flag is EINVAL",
        copy(
            p,
            false,
            pid,
            &[range(&mut target)],
            &[range(&mut source)],
            None,
            1,
        ) == neg(EINVAL),
    );
    p.check(
        "a pid no process has is ESRCH",
        copy(
            p,
            false,
            NO_SUCH_PID,
            &[range(&mut target)],
            &[range(&mut source)],
            None,
            0,
        ) == neg(ESRCH),
    );
    p.check(
        "no vectors copy nothing",
        copy(p, false, pid, &[], &[], None, 0) == 0,
    );
    for (counts, label) in [
        (
            (TOO_MANY, 1),
            "a local vector longer than IOV_MAX is EINVAL",
        ),
        (
            (1, TOO_MANY),
            "a remote vector longer than IOV_MAX is EINVAL",
        ),
    ] {
        p.check(
            label,
            copy(
                p,
                false,
                pid,
                &[range(&mut target)],
                &[range(&mut source)],
                Some(counts),
                0,
            ) == neg(EINVAL),
        );
    }
    p.check(
        "an unmapped remote range is EFAULT",
        copy(
            p,
            false,
            pid,
            &[range(&mut target)],
            &[unmapped(7)],
            None,
            0,
        ) == neg(EFAULT),
    );
    p.check(
        "an unmapped local range is EFAULT",
        copy(
            p,
            false,
            pid,
            &[unmapped(7)],
            &[range(&mut source)],
            None,
            0,
        ) == neg(EFAULT),
    );
    p.check(
        "a write to an unmapped remote range is EFAULT",
        copy(p, true, pid, &[range(&mut patch)], &[unmapped(3)], None, 0) == neg(EFAULT),
    );
    target = [0; 7];
    p.check(
        "a remote fault after a first range stops the copy short",
        copy(
            p,
            false,
            pid,
            &[range(&mut target)],
            &[range(&mut source[..3]), unmapped(4)],
            None,
            0,
        ) == 3
            && target[..3] == *b"XYZ",
    );
    let mut first = [0u8; 3];
    p.check(
        "a local fault after a first range stops the copy short",
        copy(
            p,
            false,
            pid,
            &[range(&mut first), unmapped(4)],
            &[range(&mut source)],
            None,
            0,
        ) == 3
            && first == *b"XYZ",
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "proc/vm_rw",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[Syscall::N_process_vm_readv, Syscall::N_process_vm_writev],
    gaps: &[Gap {
        status: Status::Pending(Arc::SignalsThreadsProcess),
        vehicles: Vehicle::KERNEL,
        what: "process_vm_readv and process_vm_writev are Trap(unmodeled) in the registry (the signals arc answers them for the process itself through the shim's uaccess, and ESRCH for any other pid), so the SUD dispatcher aborts at the first process_vm_readv",
        failure: Failure::Stops {
            events: 1,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall process_vm_readv (nr",
        },
    }],
    ..DEFAULTS
};
