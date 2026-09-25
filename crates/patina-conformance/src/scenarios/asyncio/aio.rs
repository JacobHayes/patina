//! asyncio/aio — Linux native AIO (fs/aio.c) on a file in the run
//! directory, as 6.8 answers it:
//!
//! * `io_setup` refuses no events and a context word that is not zeroed
//!   (`EINVAL`) and a NULL one (`EFAULT`); a context it did not create is
//!   `EINVAL` to `io_submit`, `io_getevents` and `io_destroy`;
//! * a context of four events is created (its id is non-zero); a buffered
//!   write submitted to it completes at submission, so `io_cancel` finds
//!   nothing in flight (`EINVAL`) and `io_getevents` reaps exactly one event
//!   carrying the caller's cookie, its iocb and the byte count; nothing more
//!   is pending (`io_getevents` and `io_pgetevents` with a zero timeout
//!   answer 0), and a minimum above the maximum is `EINVAL`;
//! * a read submitted back is reaped through `io_pgetevents` (with a signal
//!   mask) and returns what the write wrote;
//! * a poll of an empty pipe stays in flight: `io_submit` stores the
//!   kernel's key (0) in its iocb, `io_cancel` refuses the iocb once its key
//!   is changed (`EINVAL`) and otherwise answers `EINPROGRESS`, and the
//!   poll's completion is then reaped with result 0 (a second cancel is
//!   `EINVAL`); a poll of a readable pipe completes at submission with
//!   `POLLIN`;
//! * `io_submit` refuses an unknown opcode and a reserved field (`EINVAL`)
//!   and a closed descriptor (`EBADF`), and submits nothing for no iocbs;
//! * `io_destroy` ends the context; a second one is `EINVAL`.
//!
//! glibc wraps none of the rows (libaio is a separate library), so the
//! scenario runs through the kernel vehicles. Every reap that expects an
//! event blocks until it arrives, so no answer depends on timing. The host
//! must offer AIO (`Need::Aio`).

use crate::catalog::{Arc, DEFAULTS, Gap, Need, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{AT_FDCWD, Probe, SIGSET_BYTES, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

/// `IOCB_CMD_PREAD`, `IOCB_CMD_PWRITE`, `IOCB_CMD_POLL`
/// (include/uapi/linux/aio_abi.h).
const CMD_PREAD: u16 = 0;
const CMD_PWRITE: u16 = 1;
const CMD_POLL: u16 = 5;
/// An opcode AIO does not define.
const CMD_UNKNOWN: u16 = 99;
/// The caller's cookie, returned in the event's `data`.
const COOKIE: u64 = 0x1234;
const PAYLOAD: &[u8] = b"hello aio";

/// `struct iocb` (x86_64 and arm64 are little-endian: `aio_key` before
/// `aio_rw_flags`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Iocb {
    data: u64,
    key: u32,
    rw_flags: i32,
    lio_opcode: u16,
    reqprio: i16,
    fildes: u32,
    buf: u64,
    nbytes: u64,
    offset: i64,
    reserved2: u64,
    flags: u32,
    resfd: u32,
}

/// `struct io_event`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoEvent {
    data: u64,
    obj: u64,
    res: i64,
    res2: i64,
}

/// `struct __aio_sigset`.
#[repr(C)]
struct AioSigset {
    sigmask: *const sigset_t,
    sigsetsize: usize,
}

const ZERO: timespec = timespec {
    tv_sec: 0,
    tv_nsec: 0,
};

fn setup(p: &Probe, nr: i64, ctx: Option<&mut u64>, what: &str) -> i64 {
    let ptr = ctx.map_or(0, |ctx| ctx as *mut u64 as i64);
    p.observed(
        Syscall::N_io_setup,
        [nr, ptr, 0, 0, 0, 0],
        &[("nr_events", nr.into()), ("ctx", what.into())],
    )
}

fn submit(p: &Probe, ctx: u64, iocbs: &[&Iocb], what: &str) -> i64 {
    let pointers: Vec<*const Iocb> = iocbs.iter().map(|iocb| *iocb as *const Iocb).collect();
    p.observed(
        Syscall::N_io_submit,
        [
            ctx as i64,
            pointers.len() as i64,
            pointers.as_ptr() as i64,
            0,
            0,
            0,
        ],
        &[("nr", pointers.len().into()), ("iocbs", what.into())],
    )
}

/// `io_getevents`, or `io_pgetevents` with an empty signal mask; records
/// what each reaped event carries.
fn reap(
    p: &Probe,
    ctx: u64,
    min: i64,
    max: usize,
    timeout: Option<&timespec>,
    with_mask: bool,
    iocb: &Iocb,
) -> (i64, Vec<IoEvent>) {
    let mut events = vec![IoEvent::default(); max];
    let timeout_ptr = timeout.map_or(0, |ts| ts as *const timespec as i64);
    let empty: sigset_t = unsafe { std::mem::zeroed() };
    let sigset = AioSigset {
        sigmask: &empty,
        sigsetsize: SIGSET_BYTES as usize,
    };
    let (row, sixth) = if with_mask {
        (Syscall::N_io_pgetevents, &sigset as *const AioSigset as i64)
    } else {
        (Syscall::N_io_getevents, 0)
    };
    let result = p.call_unrecorded(
        row,
        [
            ctx as i64,
            min,
            max as i64,
            events.as_mut_ptr() as i64,
            timeout_ptr,
            sixth,
        ],
    );
    let reaped = if result > 0 {
        &events[..result as usize]
    } else {
        &[][..]
    };
    let described: Vec<Value> = reaped
        .iter()
        .map(|event| {
            serde_json::json!({
                "data": event.data,
                "obj_is_iocb": event.obj == iocb as *const Iocb as u64,
                "res": event.res,
                "res2": event.res2,
            })
        })
        .collect();
    p.rec
        .event(row.name(), result)
        .arg("min_nr", min)
        .arg("nr", max)
        .arg("zero_timeout", timeout.is_some())
        .field("events", described)
        .emit();
    (result, reaped.to_vec())
}

fn destroy(p: &Probe, ctx: u64, what: &str) -> i64 {
    p.observed(
        Syscall::N_io_destroy,
        [ctx as i64, 0, 0, 0, 0, 0],
        &[("ctx", what.into())],
    )
}

fn cancel(p: &Probe, ctx: u64, iocb: &Iocb, what: &str) -> i64 {
    // 6.8 writes nothing to the result event (`io_cancel` reports the
    // cancelled operation through the completion queue).
    let mut unused = IoEvent::default();
    p.observed(
        Syscall::N_io_cancel,
        [
            ctx as i64,
            iocb as *const Iocb as i64,
            &mut unused as *mut IoEvent as i64,
            0,
            0,
            0,
        ],
        &[("iocb", what.into())],
    )
}

/// `IOCB_CMD_POLL` on a pipe's read end: in flight while the pipe is empty,
/// so cancellable (`EINPROGRESS`, then its completion reaped with result 0,
/// and a second cancel `EINVAL`); completed at submission once a byte is
/// queued (result `POLLIN`).
fn poll(p: &Probe, ctx: u64) {
    let (r, [rd, wr]) = p.pipe2(O_CLOEXEC);
    p.require("create a pipe", r == 0);
    // Submitted with a key the kernel overwrites: it stores its own (0)
    // into the caller's iocb and checks it on cancel.
    let mut waiting = Iocb {
        data: COOKIE + 2,
        key: 7,
        lio_opcode: CMD_POLL,
        fildes: rd as u32,
        buf: POLLIN as u64,
        ..Iocb::default()
    };
    let at: *mut Iocb = &mut waiting;
    p.check(
        "a poll of an empty pipe is submitted",
        // SAFETY: `waiting` is this frame's; the kernel writes its key.
        submit(p, ctx, &[unsafe { &*at }], "poll-empty") == 1,
    );
    // SAFETY: the key the kernel wrote into `waiting`.
    let key = unsafe { std::ptr::read_volatile(&raw const (*at).key) };
    p.mark("poll_key_after_submit", &[("key", key.into())]);
    p.check(
        "io_submit stores the kernel's key, 0, in the iocb",
        key == 0,
    );
    // SAFETY: as above.
    unsafe { std::ptr::write_volatile(&raw mut (*at).key, 1) };
    p.check(
        "io_cancel of an iocb whose key is not the kernel's is EINVAL",
        // SAFETY: as above.
        cancel(p, ctx, unsafe { &*at }, "poll-empty-rekeyed") == neg(EINVAL),
    );
    // SAFETY: as above.
    unsafe { std::ptr::write_volatile(&raw mut (*at).key, 0) };
    p.check(
        "io_cancel of the poll in flight is EINPROGRESS",
        // SAFETY: as above.
        cancel(p, ctx, unsafe { &*at }, "poll-empty") == neg(EINPROGRESS),
    );
    let (r, events) = reap(p, ctx, 1, 1, None, false, &waiting);
    p.check(
        "the cancelled poll completes with result 0",
        r == 1 && events[0].data == COOKIE + 2 && events[0].res == 0 && events[0].res2 == 0,
    );
    p.check(
        "a second io_cancel of it is EINVAL",
        cancel(p, ctx, &waiting, "poll-empty") == neg(EINVAL),
    );
    p.require("queue a byte", p.write(wr, b"x") == 1);
    let ready = Iocb {
        data: COOKIE + 3,
        key: 0,
        ..waiting
    };
    p.check(
        "a poll of a readable pipe is submitted",
        submit(p, ctx, &[&ready], "poll-ready") == 1,
    );
    let (r, events) = reap(p, ctx, 1, 1, None, false, &ready);
    p.check(
        "it completed at submission with POLLIN",
        r == 1 && events[0].data == COOKIE + 3 && events[0].res == i64::from(POLLIN),
    );
    p.close(rd);
    p.close(wr);
}

pub fn run(p: &Probe) {
    let mut ctx = 0u64;
    p.check(
        "io_setup of no events is EINVAL",
        setup(p, 0, Some(&mut ctx), "zeroed") == neg(EINVAL),
    );
    let mut dirty = 1u64;
    p.check(
        "io_setup into a context word that is not zeroed is EINVAL",
        setup(p, 1, Some(&mut dirty), "nonzero") == neg(EINVAL),
    );
    p.check(
        "io_setup into NULL is EFAULT",
        setup(p, 1, None, "null") == neg(EFAULT),
    );
    p.check(
        "io_destroy of a context never created is EINVAL",
        destroy(p, 0, "none") == neg(EINVAL),
    );
    p.check(
        "io_submit to a context never created is EINVAL",
        submit(p, 0, &[], "none") == neg(EINVAL),
    );
    let placeholder = Iocb::default();
    p.check(
        "io_getevents from a context never created is EINVAL",
        reap(p, 0, 0, 1, Some(&ZERO), false, &placeholder).0 == neg(EINVAL),
    );

    p.check(
        "io_setup of four events creates a context",
        setup(p, 4, Some(&mut ctx), "zeroed") == 0,
    );
    p.check("the context id is non-zero", ctx != 0);
    let path = format!("{}/aio", p.dir());
    let fd = p.openat(
        AT_FDCWD,
        &path,
        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC,
        0o644,
    );
    p.require("create the file", fd >= 0);

    let write = Iocb {
        data: COOKIE,
        lio_opcode: CMD_PWRITE,
        fildes: fd as u32,
        buf: PAYLOAD.as_ptr() as u64,
        nbytes: PAYLOAD.len() as u64,
        ..Iocb::default()
    };
    p.check(
        "a buffered write is submitted",
        submit(p, ctx, &[&write], "pwrite") == 1,
    );
    p.check(
        "io_cancel of a write that completed at submission is EINVAL",
        cancel(p, ctx, &write, "pwrite") == neg(EINVAL),
    );
    let (r, events) = reap(p, ctx, 1, 2, None, false, &write);
    p.check(
        "io_getevents reaps the write's one event",
        r == 1
            && events[0].data == COOKIE
            && events[0].obj == &write as *const Iocb as u64
            && events[0].res == PAYLOAD.len() as i64
            && events[0].res2 == 0,
    );
    p.check(
        "nothing more is pending: io_getevents answers 0",
        reap(p, ctx, 0, 2, Some(&ZERO), false, &write).0 == 0,
    );
    p.check(
        "io_pgetevents with nothing pending answers 0",
        reap(p, ctx, 0, 2, Some(&ZERO), true, &write).0 == 0,
    );
    p.check(
        "a minimum above the maximum is EINVAL",
        reap(p, ctx, 2, 1, Some(&ZERO), false, &write).0 == neg(EINVAL),
    );

    let mut back = [0u8; PAYLOAD.len()];
    let read = Iocb {
        data: COOKIE + 1,
        lio_opcode: CMD_PREAD,
        fildes: fd as u32,
        buf: back.as_mut_ptr() as u64,
        nbytes: back.len() as u64,
        ..Iocb::default()
    };
    p.check(
        "a read is submitted",
        submit(p, ctx, &[&read], "pread") == 1,
    );
    let (r, events) = reap(p, ctx, 1, 1, None, true, &read);
    p.check(
        "io_pgetevents reaps the read, which returns what the write wrote",
        r == 1
            && events[0].data == COOKIE + 1
            && events[0].res == PAYLOAD.len() as i64
            && back == PAYLOAD,
    );

    poll(p, ctx);

    let unknown = Iocb {
        lio_opcode: CMD_UNKNOWN,
        ..read
    };
    let reserved = Iocb {
        reserved2: 1,
        ..read
    };
    let closed = Iocb {
        fildes: 4000,
        ..read
    };
    p.check(
        "an unknown opcode is EINVAL",
        submit(p, ctx, &[&unknown], "unknown-opcode") == neg(EINVAL),
    );
    p.check(
        "a reserved field set is EINVAL",
        submit(p, ctx, &[&reserved], "reserved") == neg(EINVAL),
    );
    p.check(
        "a closed descriptor is EBADF",
        submit(p, ctx, &[&closed], "closed-fd") == neg(EBADF),
    );
    p.check("no iocbs submit nothing", submit(p, ctx, &[], "none") == 0);
    p.check(
        "io_destroy ends the context",
        destroy(p, ctx, "created") == 0,
    );
    p.check(
        "a destroyed context is EINVAL",
        destroy(p, ctx, "destroyed") == neg(EINVAL),
    );
    p.close(fd);
}

pub const SCENARIO: Scenario = Scenario {
    name: "asyncio/aio",
    run,
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_io_setup,
        Syscall::N_io_destroy,
        Syscall::N_io_submit,
        Syscall::N_io_cancel,
        Syscall::N_io_getevents,
        Syscall::N_io_pgetevents,
    ],
    needs: &[Need::Aio],
    gaps: &[Gap {
        status: Status::Pending(Arc::IoUring),
        vehicles: Vehicle::KERNEL,
        what: "the Linux AIO rows are Trap(unmodeled), where the registry's plan is a soft-deny: ENOSYS, a kernel built without AIO (CONFIG_AIO=n), which libaio users fall back from. Today the SUD dispatcher aborts at the first io_setup; once the soft-deny lands this gap becomes an io_setup ENOSYS difference at event 0",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(libc::SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall io_setup (nr",
        },
    }],
    ..DEFAULTS
};
