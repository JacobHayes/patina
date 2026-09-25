//! asyncio/io_uring — the io_uring rows (io_uring/io_uring.c,
//! io_uring/register.c) as 6.8 answers an unprivileged caller
//! (`kernel.io_uring_disabled` 0, the default, or the caller in
//! `kernel.io_uring_group`):
//!
//! * `io_uring_setup` refuses no entries, a set reserved field and an
//!   unknown flag (`EINVAL`) and NULL parameters (`EFAULT`); one entry
//!   creates a close-on-exec ring of one submission and two completion
//!   entries, reporting 6.8's feature set (`IORING_FEAT_*`, 14 bits);
//! * `io_uring_enter` with nothing to submit or wait for answers 0, refuses
//!   an unknown flag (`EINVAL`), a descriptor that is no ring (`EOPNOTSUPP`)
//!   and a closed one (`EBADF`); a no-op written to the mapped submission
//!   queue is submitted by one enter that waits for it, and completes with
//!   the caller's cookie and result 0;
//! * `io_uring_register` refuses an unknown opcode (`EINVAL`) and a
//!   descriptor that is no ring (`EOPNOTSUPP`); its probe reports 6.8's
//!   opcode table (55 opcodes, `IORING_OP_LAST` 55) and the list of those
//!   the kernel supports (a model that supports a subset differs by
//!   exactly the opcodes it lacks).
//!
//! glibc wraps none of the rows (liburing is a separate library), so the
//! scenario runs through the kernel vehicles. The host must offer io_uring
//! to the caller (`Need::IoUring`). The no-op round trip writes through the
//! ring geometry setup reports, so the probe stops, rather than writing
//! out of bounds, unless that geometry is exactly one submission and two
//! completion entries with every offset inside its mapping.

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{AT_FDCWD, Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;
use std::sync::atomic::{AtomicU32, Ordering};

/// A setup or enter flag io_uring does not define.
const UNKNOWN_FLAG: i64 = 1 << 31;
/// `IORING_ENTER_GETEVENTS`.
const ENTER_GETEVENTS: i64 = 1;
/// `IORING_REGISTER_PROBE`.
const REGISTER_PROBE: i64 = 8;
/// A register opcode io_uring does not define.
const REGISTER_UNKNOWN: i64 = 999;
/// `IORING_OFF_SQ_RING`, `IORING_OFF_CQ_RING`, `IORING_OFF_SQES`.
const OFF_SQ_RING: i64 = 0;
const OFF_CQ_RING: i64 = 0x0800_0000;
const OFF_SQES: i64 = 0x1000_0000;
/// `IORING_OP_NOP`.
const OP_NOP: u8 = 0;
/// `IO_URING_OP_SUPPORTED`.
const OP_SUPPORTED: u16 = 1;
/// The probe's capacity: every opcode an 8-bit field can name.
const PROBE_OPS: usize = 256;
/// The caller's cookie, returned in the completion's `user_data`.
const COOKIE: u64 = 0x42;

/// `struct io_sqring_offsets`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SqOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

/// `struct io_cqring_offsets`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CqOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

/// `struct io_uring_params`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Params {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: SqOffsets,
    cq_off: CqOffsets,
}

/// `struct io_uring_sqe`, as far as a no-op fills it.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Sqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    tail: [u64; 3],
}

/// `struct io_uring_cqe`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Cqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

/// `struct io_uring_probe` with room for every opcode.
#[repr(C)]
struct ProbeTable {
    last_op: u8,
    ops_len: u8,
    resv: u16,
    resv2: [u32; 3],
    ops: [ProbeOp; PROBE_OPS],
}

/// `struct io_uring_probe_op`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ProbeOp {
    op: u8,
    resv: u8,
    flags: u16,
    resv2: u32,
}

fn setup(p: &Probe, entries: i64, params: Option<&mut Params>, what: &str) -> i64 {
    let ptr = params.map_or(0, |params| params as *mut Params as i64);
    p.observed(
        Syscall::N_io_uring_setup,
        [entries, ptr, 0, 0, 0, 0],
        &[("entries", entries.into()), ("params", what.into())],
    )
}

fn enter(p: &Probe, fd: i32, submit: i64, min_complete: i64, flags: i64, what: &str) -> i64 {
    p.observed(
        Syscall::N_io_uring_enter,
        [fd as i64, submit, min_complete, flags, 0, 0],
        &[
            ("fd", what.into()),
            ("to_submit", submit.into()),
            ("min_complete", min_complete.into()),
            ("flags", flags.into()),
        ],
    )
}

/// Map `len` bytes of the ring at `offset` (setup, unrecorded).
fn map(p: &Probe, fd: i32, len: usize, offset: i64) -> *mut u8 {
    // SAFETY: a fresh shared mapping of the ring descriptor, which the
    // kernel sizes; nothing else is mapped over.
    let at = unsafe {
        mmap(
            std::ptr::null_mut(),
            len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            fd,
            offset,
        )
    };
    p.require("map the ring", at != MAP_FAILED);
    at.cast()
}

/// Submit one no-op through the mapped rings and reap its completion:
/// `(enter's result, the completion)`.
fn nop_round_trip(p: &Probe, fd: i32, params: &Params) -> (i64, Option<Cqe>) {
    let sq = params.sq_off;
    let cq = params.cq_off;
    let sq_len = sq.array as usize + params.sq_entries as usize * 4;
    let cq_len = cq.cqes as usize + params.cq_entries as usize * std::mem::size_of::<Cqe>();
    let sqes_len = params.sq_entries as usize * std::mem::size_of::<Sqe>();
    // The writes below go through the reported geometry: a wrong answer
    // stops the probe here rather than writing outside the mapped rings.
    let fits = |offset: u32, len: usize| offset as usize + 4 <= len;
    p.require(
        "the ring has one submission and two completion entries",
        params.sq_entries == 1 && params.cq_entries == 2,
    );
    p.require(
        "the submission ring's words lie within it",
        [sq.head, sq.tail, sq.ring_mask, sq.ring_entries]
            .into_iter()
            .all(|offset| fits(offset, sq_len)),
    );
    p.require(
        "the completion ring's words lie within it",
        [cq.head, cq.tail, cq.ring_mask, cq.ring_entries]
            .into_iter()
            .all(|offset| fits(offset, cq_len)),
    );
    let (sq_ring, cq_ring, sqes) = p.rec.quiet(|| {
        (
            map(p, fd, sq_len, OFF_SQ_RING),
            map(p, fd, cq_len, OFF_CQ_RING),
            map(p, fd, sqes_len, OFF_SQES),
        )
    });
    // SAFETY: every offset is the kernel's, within the lengths it sized;
    // the head and tail words are shared with the kernel, so they are
    // accessed atomically.
    unsafe {
        let word = |base: *mut u8, offset: u32| &*(base.add(offset as usize) as *const AtomicU32);
        let sq_tail = word(sq_ring, sq.tail);
        let mask = *(sq_ring.add(sq.ring_mask as usize) as *const u32);
        let cq_mask = *(cq_ring.add(cq.ring_mask as usize) as *const u32);
        p.require(
            "the ring masks index within the entries",
            mask < params.sq_entries && cq_mask < params.cq_entries,
        );
        let slot = sq_tail.load(Ordering::Relaxed) & mask;
        *(sqes as *mut Sqe).add(slot as usize) = Sqe {
            opcode: OP_NOP,
            user_data: COOKIE,
            ..Sqe::default()
        };
        *(sq_ring.add(sq.array as usize) as *mut u32).add(slot as usize) = slot;
        sq_tail.fetch_add(1, Ordering::Release);
        let result = enter(p, fd, 1, 1, ENTER_GETEVENTS, "ring");
        let cq_head = word(cq_ring, cq.head);
        let cq_tail = word(cq_ring, cq.tail);
        let head = cq_head.load(Ordering::Relaxed);
        let completion = (cq_tail.load(Ordering::Acquire) != head).then(|| {
            let cqe = *(cq_ring.add(cq.cqes as usize) as *const Cqe).add((head & cq_mask) as usize);
            cq_head.store(head + 1, Ordering::Release);
            cqe
        });
        p.rec.quiet(|| {
            munmap(sq_ring.cast(), sq_len);
            munmap(cq_ring.cast(), cq_len);
            munmap(sqes.cast(), sqes_len);
        });
        (result, completion)
    }
}

pub fn run(p: &Probe) {
    let mut params = Params::default();
    p.check(
        "io_uring_setup of no entries is EINVAL",
        setup(p, 0, Some(&mut params), "zeroed") == neg(EINVAL),
    );
    p.check(
        "io_uring_setup with NULL parameters is EFAULT",
        setup(p, 1, None, "null") == neg(EFAULT),
    );
    let mut reserved = Params {
        resv: [1, 0, 0],
        ..Params::default()
    };
    p.check(
        "a reserved field set is EINVAL",
        setup(p, 1, Some(&mut reserved), "reserved") == neg(EINVAL),
    );
    let mut flagged = Params {
        flags: UNKNOWN_FLAG as u32,
        ..Params::default()
    };
    p.check(
        "an unknown setup flag is EINVAL",
        setup(p, 1, Some(&mut flagged), "unknown-flag") == neg(EINVAL),
    );

    let result = p.call_unrecorded(
        Syscall::N_io_uring_setup,
        [1, &mut params as *mut Params as i64, 0, 0, 0, 0],
    );
    p.rec
        .event(Syscall::N_io_uring_setup.name(), result)
        .arg("entries", 1)
        .arg("params", "zeroed")
        .norm("ret", crate::observe::Norm::Relative("fd"))
        .field("sq_entries", params.sq_entries)
        .field("cq_entries", params.cq_entries)
        .field("flags", params.flags)
        .field("features", params.features)
        .emit();
    let ring = result as i32;
    p.require("create a ring", ring >= 0);
    p.check(
        "one entry is one submission and two completion entries",
        params.sq_entries == 1 && params.cq_entries == 2,
    );
    p.check(
        "the ring is close-on-exec",
        p.fcntl(ring, F_GETFD, 0) == i64::from(FD_CLOEXEC),
    );

    let path = format!("{}/plain", p.dir());
    let plain = p.openat(
        AT_FDCWD,
        &path,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
        0o644,
    );
    p.require("create a plain file", plain >= 0);
    p.check(
        "io_uring_enter with nothing to do answers 0",
        enter(p, ring, 0, 0, 0, "ring") == 0,
    );
    p.check(
        "an unknown enter flag is EINVAL",
        enter(p, ring, 0, 0, UNKNOWN_FLAG, "ring") == neg(EINVAL),
    );
    p.check(
        "a descriptor that is no ring is EOPNOTSUPP",
        enter(p, plain, 0, 0, 0, "plain") == neg(EOPNOTSUPP),
    );
    p.check(
        "a closed descriptor is EBADF",
        enter(p, 4000, 0, 0, 0, "closed") == neg(EBADF),
    );
    let (entered, completion) = nop_round_trip(p, ring, &params);
    p.mark(
        "nop_completion",
        &[
            ("present", completion.is_some().into()),
            (
                "user_data",
                completion.map_or(Value::Null, |c| c.user_data.into()),
            ),
            ("res", completion.map_or(Value::Null, |c| c.res.into())),
        ],
    );
    p.check("one enter submits the no-op and waits for it", entered == 1);
    p.check(
        "the no-op completes with the caller's cookie and result 0",
        completion.is_some_and(|c| c.user_data == COOKIE && c.res == 0),
    );

    p.check(
        "an unknown register opcode is EINVAL",
        p.observed(
            Syscall::N_io_uring_register,
            [ring as i64, REGISTER_UNKNOWN, 0, 0, 0, 0],
            &[("fd", "ring".into()), ("opcode", REGISTER_UNKNOWN.into())],
        ) == neg(EINVAL),
    );
    p.check(
        "registering on a descriptor that is no ring is EOPNOTSUPP",
        p.observed(
            Syscall::N_io_uring_register,
            [plain as i64, REGISTER_PROBE, 0, 0, 0, 0],
            &[("fd", "plain".into()), ("opcode", REGISTER_PROBE.into())],
        ) == neg(EOPNOTSUPP),
    );
    // SAFETY: an all-zero probe table is its valid empty state.
    let mut table: ProbeTable = unsafe { std::mem::zeroed() };
    let result = p.call_unrecorded(
        Syscall::N_io_uring_register,
        [
            ring as i64,
            REGISTER_PROBE,
            &mut table as *mut ProbeTable as i64,
            PROBE_OPS as i64,
            0,
            0,
        ],
    );
    let supported: Vec<u8> = table.ops[..usize::from(table.ops_len)]
        .iter()
        .filter(|op| op.flags & OP_SUPPORTED != 0)
        .map(|op| op.op)
        .collect();
    p.rec
        .event(Syscall::N_io_uring_register.name(), result)
        .arg("fd", "ring")
        .arg("opcode", REGISTER_PROBE)
        .arg("nr_args", PROBE_OPS)
        .field("last_op", table.last_op)
        .field("ops_len", table.ops_len)
        .field("supported", supported)
        .emit();
    p.check(
        "the probe reports the opcode table",
        result == 0 && table.ops_len > 0 && table.last_op == table.ops_len - 1,
    );
    p.close(plain);
    p.close(ring);
}

pub const SCENARIO: Scenario = Scenario {
    name: "asyncio/io_uring",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_io_uring_setup,
        Syscall::N_io_uring_enter,
        Syscall::N_io_uring_register,
    ],
    needs: &[Need::IoUring],
    gaps: &[Gap {
        status: Status::Pending(Arc::IoUring),
        vehicles: Vehicle::KERNEL,
        what: "the io_uring rows are Trap(unmodeled), where the registry's plan until the io_uring arc models rings over the readiness reactor is a soft-deny: io_uring_setup ENOSYS, which tokio/mio/monoio probe for and fall back from. Today the SUD dispatcher aborts at the first io_uring_setup; once the soft-deny lands this gap becomes an io_uring_setup ENOSYS difference at event 0",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall io_uring_setup (nr",
        },
    }],
    ..DEFAULTS
};
