//! Syscall handlers, one module per table file. Every handler has the
//! signature `fn handle(call: &mut dyn Call) -> Action` and reaches the saved
//! machine context only through `call.frame()`.

pub mod fd;
pub mod fs;
pub mod inet;
pub mod io;
pub mod lock;
pub mod mem;
pub mod misc;
pub mod net;
pub mod poll;
pub mod proc;
pub mod procfs;
pub mod sched;
pub mod sdk;
pub mod sig;
pub mod signalfd;
pub mod thread;
pub mod time;
pub mod timerfd;
pub mod udp;
pub mod unixsock;

use crate::raw::*;
use crate::state::ctl;
use crate::trap::{args, Action, Call};
use core::sync::atomic::Ordering::*;
use proto::layout::FD_HIDDEN_MIN;
use proto::table::{Class, Group, Row};

pub fn dispatch(call: &mut dyn Call, row: &'static Row) -> Action {
    // Descriptors the call reads (an anonymous `mmap` ignores its descriptor argument).
    let fds = row.fds & proto::table::nargs::live(call.nr(), &call.guest_args());
    for i in 0..6 {
        if fds & (1 << i) != 0 && call.arg(i) as i32 >= FD_HIDDEN_MIN {
            return Action::Return(-e::EBADF);
        }
    }
    match row.class {
        Class::Deny(errno) => {
            let c = ctl();
            c.note_denied(call.nr());
            c.stats
                .refusals
                .store(c.stats.refusals.load(Relaxed) + 1, Relaxed);
            Action::Return(-(errno as i64))
        }
        Class::Stop => stop(call, row),
        _ => {
            // Memory the kernel would touch for the program (`Row::ins`, `outs`, `refs`),
            // checked before anything reads it: the runtime's region reads as a hole.
            let guest = call.guest_args();
            if crate::guest::names_runtime(row, &guest) {
                return Action::Return(-e::EFAULT);
            }
            let ts = call.thread();
            ts.call_row = row as *const Row as u64;
            ts.call_args = guest;
            // A path swap is made before the paths are resolved, so the walk sees it.
            let cfg = &ctl().faults.cfg;
            let swap = if cfg.any != 0 && cfg.path_swap() {
                crate::swap::before(call)
            } else {
                None
            };
            let act = passed(call, row);
            if let Some(s) = swap {
                crate::swap::after(s);
            }
            call.thread().call_row = 0;
            act
        }
    }
}

/// A call the table lets through: its paths, its faults, its handler.
fn passed(call: &mut dyn Call, row: &'static Row) -> Action {
    // Path arguments resolved first: handlers see the path the kernel walks.
    if let Err(r) = crate::resolve::prepare(call) {
        if r == -e::ENOENT {
            crate::resolve::note_missing(call);
        }
        return Action::Return(r);
    }
    // Faults are decided before the call.
    let mut post = None;
    if ctl().faults.cfg.any != 0 {
        if let Some(c) = proto::faults::class_of(call.nr()) {
            let g = crate::inject::before(call, c);
            if let Some(r) = g.ret {
                return Action::Return(r);
            }
            post = g.post;
        }
    }
    let act = handle_group(call, row);
    if matches!(act, Action::Return(r) if r == -e::ENOENT) {
        crate::resolve::note_missing(call);
    }
    if matches!(act, Action::Return(r) if r == -e::EFBIG) && host_fsize_limited() {
        // The launcher's RLIMIT_FSIZE is inherited and enforced by the kernel; the
        // guest's own limit is virtual. Reaching the host's is not a sandbox answer.
        crate::sup::host_error(-e::EFBIG, call.nr(), proto::ctl::HE_HOST_LIMIT);
    }
    match (post, act) {
        (Some(errno), Action::Return(0)) => Action::Return(errno),
        (_, a) => a,
    }
}

fn handle_group(call: &mut dyn Call, row: &'static Row) -> Action {
    match row.group {
        Group::Time => time::handle(call),
        Group::Mem => mem::handle(call),
        Group::Fs => fs::handle(call),
        Group::Fd => fd::handle(call),
        Group::Sched => sched::handle(call),
        Group::Sig => sig::handle(call),
        Group::Proc => proc::handle(call),
        Group::Net => net::handle(call),
        Group::Misc => misc::handle(call),
        Group::Sdk => sdk::handle(call),
    }
}

/// End the run naming this call: the record is written first so the log shows where.
pub fn stop(call: &mut dyn Call, row: &'static Row) -> ! {
    call.thread().eff_class = Class::Stop.code();
    crate::log::trap(row, call, -e::ENOSYS);
    crate::sup::stop(call.nr(), call.guest_args()[0])
}

/// Stop for a variant of a written row that is not supported yet.
pub fn stop_here(call: &mut dyn Call) -> Action {
    let row = proto::row(call.nr() as u32);
    stop(call, row)
}

/// End the run naming this call (a variant that is not supported yet).
pub fn halt(call: &mut dyn Call) -> ! {
    let row = proto::row(call.nr() as u32);
    stop(call, row)
}

/// Refuse a request of an open-ended call (an ioctl request, fcntl command, prctl option,
/// socket option) that no row lists: the call answers `errno` (what a kernel without the
/// request answers), and `PREFIX:VALUE` is recorded in `outcome.refused`.
pub fn refuse_request(call: &mut dyn Call, prefix: &[u8], v: u64, hex: bool, errno: i64) -> i64 {
    let mut b = [0u8; 48];
    let mut n = prefix.len();
    b[..n].copy_from_slice(prefix);
    b[n] = b':';
    n += 1;
    if hex {
        b[n] = b'0';
        b[n + 1] = b'x';
        n += 2;
        let digits = (64 - v.leading_zeros()).div_ceil(4).max(1);
        for i in (0..digits).rev() {
            let d = ((v >> (i * 4)) & 0xf) as u8;
            b[n] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
            n += 1;
        }
    } else {
        n += crate::path::fmt_dec(&mut b[n..], v);
    }
    crate::path::refuse(&b[..n]);
    set_class(call, Class::Deny(-errno as i32));
    errno
}

/// Mark the class actually applied to this call.
pub fn set_class(call: &mut dyn Call, c: Class) {
    call.thread().eff_class = c.code();
}

/// The raw call with the guest's arguments.
pub fn raw(call: &dyn Call) -> i64 {
    let a = args(call);
    unsafe { sc6(call.nr(), a[0], a[1], a[2], a[3], a[4], a[5]) }
}

/// Pass the call to the kernel unchanged. A host error the tool did not inject ends the run as `infra`.
pub fn pass(call: &mut dyn Call) -> Action {
    let r = raw(call);
    host_check(call, r);
    Action::Return(r)
}

/// Whether the real `RLIMIT_FSIZE` (the launcher's, inherited) is finite.
pub fn host_fsize_limited() -> bool {
    let mut rl = [0u64; 2];
    let r = unsafe { sc4(nr::PRLIMIT64, 0, 1, 0, rl.as_mut_ptr() as u64) };
    r == 0 && rl[0] != u64::MAX
}

pub fn host_check(call: &dyn Call, r: i64) {
    if r == -e::ENOMEM || r == -e::EIO {
        crate::sup::host_error(r, call.nr(), proto::ctl::HE_SYSCALL);
    }
    // RLIMIT_NPROC counts the user's processes on the whole host: a refused clone is the
    // host's limit, not a sandbox answer.
    if r == -e::EAGAIN && matches!(call.nr(), nr::CLONE | nr::FORK | nr::VFORK | nr::CLONE3) {
        crate::sup::host_error(r, call.nr(), proto::ctl::HE_HOST_LIMIT);
    }
}

pub use crate::guest::{get, put};
