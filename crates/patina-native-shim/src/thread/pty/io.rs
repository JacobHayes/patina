//! PTY blocking I/O, readiness, queue counts, and name queries.

use super::*;

/// `TTY_THRESHOLD_UNTHROTTLE`: a pty's read wakes the other side's writers
/// once at most this many bytes are left (`n_tty_check_unthrottle`).
const UNTHROTTLE: usize = 128;

/// What one pass of a read decided.
enum Pass {
    /// Answer with what was taken (possibly nothing).
    Done,
    /// Answer this error, unless something was taken already.
    Error(c_int),
    /// Look again at once: more is wanted, and there may be more.
    Again,
    /// Wait for more.
    Wait,
}

/// How long `n_tty_read` may wait for input now (`timeout`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Timeout {
    /// As long as it takes.
    Unbounded,
    /// Not at all.
    Zero,
    /// `VTIME` tenths of a second, which the model does not keep.
    Timer,
}

/// When a read of a side ends, as `n_tty_read` fixes it when the read
/// starts (a mode switch while it waits changes how it copies, not this): a
/// canonical read ends with the line it copies; a raw one once it has
/// `VMIN` bytes, `VTIME` timing the wait between them, or with `VMIN` 0 on
/// any byte, `VTIME` bounding the wait for it. The master's own settings
/// are the pts driver's for a master: raw, `VMIN` 1, `VTIME` 0.
#[derive(Clone, Copy)]
struct Wanted {
    /// `minimum`: the bytes that end the read.
    pub(super) minimum: usize,
    /// `time`: `VTIME` starts timing the wait once a pass copied bytes.
    between: bool,
    pub(super) timeout: Timeout,
}

impl Wanted {
    fn at_start(pair: &Pair, side: Side) -> Wanted {
        let (canonical, vmin, vtime) = match side {
            Side::Master => (false, 1, 0),
            Side::Slave => (
                pair.canonical(),
                pair.termios.cc[VMIN],
                pair.termios.cc[VTIME],
            ),
        };
        if canonical {
            Wanted {
                minimum: 0,
                between: false,
                timeout: Timeout::Unbounded,
            }
        } else if vmin != 0 {
            Wanted {
                minimum: usize::from(vmin),
                between: vtime != 0,
                timeout: Timeout::Unbounded,
            }
        } else {
            Wanted {
                minimum: 1,
                between: false,
                timeout: if vtime == 0 {
                    Timeout::Zero
                } else {
                    Timeout::Timer
                },
            }
        }
    }
}

/// `tty_read` on a pair's descriptor: a hung-up slave reads nothing
/// (`hung_up_tty_read`), one whose last open failed is `EIO`; then
/// `n_tty_read`. Each pass copies what the side's current mode offers, a
/// canonical slave's line (or as much of it as fits) or whatever is queued,
/// until the read has what it wants ([`Wanted`]) or its room is full. With
/// nothing to copy, the side's other end having closed is `EIO` (the
/// master's slave, or the slave's master while the read waited), a zero
/// timeout answers what was taken, a non-blocking read `EAGAIN`, and a wait
/// on `VTIME`'s timer stops by name. A pass that copied wakes the other
/// side's writers once at most [`UNTHROTTLE`] bytes are left.
///
/// # Safety
/// `destination` must be writable for `length` bytes when nonzero.
pub(crate) unsafe fn read(
    resolved: crate::fdtable::Resolved,
    destination: *mut c_void,
    length: usize,
    nonblocking: bool,
) -> isize {
    let side = Side::of(resolved.kind).expect("a pty kind");
    let index = resolved.handle as u32;
    if let Err(errno) = sched_point() {
        return fail(errno) as isize;
    }
    let mut wanted = {
        let state = lock_state();
        let Some(pair) = state.ptys.pairs.get(&index) else {
            return fail(crate::EBADF) as isize;
        };
        if side == Side::Slave && hung_up(pair) {
            set_errno(0);
            return 0;
        }
        if side == Side::Slave && pair.io_error {
            return fail(EIO) as isize;
        }
        if length == 0 {
            set_errno(0);
            return 0;
        }
        Wanted::at_start(pair, side)
    };
    let me = current_task();
    let mut taken: Vec<u8> = Vec::new();
    loop {
        let mut state = lock_state();
        let Some(pair) = state.ptys.pairs.get_mut(&index) else {
            return fail(crate::EBADF) as isize;
        };
        let mut woken = Vec::new();
        let pass = if !pair.readable(side, false) {
            let other_closed = match side {
                Side::Master => pair.slave_closed,
                Side::Slave => hung_up(pair),
            };
            if other_closed {
                Pass::Error(EIO)
            } else if wanted.timeout == Timeout::Zero {
                Pass::Done
            } else if nonblocking {
                Pass::Error(crate::EWOULDBLOCK)
            } else if wanted.timeout == Timeout::Timer {
                drop(state);
                unmodeled("a raw read's wait on its timer (VTIME)");
            } else {
                Pass::Wait
            }
        } else {
            let room = length - taken.len();
            match side {
                Side::Master => {
                    let count = room.min(pair.to_master.len());
                    taken.extend(pair.to_master.drain(..count));
                }
                Side::Slave if pair.canonical() => taken.extend(pair.take_line(room)),
                Side::Slave => {
                    let count = room.min(pair.to_slave.len());
                    taken.extend(pair.to_slave.drain(..count).map(|cell| cell.byte));
                }
            }
            if pair.in_buffer(side) <= UNTHROTTLE {
                woken = pair.wake(side.other(), false, true);
            }
            if taken.len() == length || taken.len() >= wanted.minimum {
                Pass::Done
            } else {
                if wanted.between {
                    wanted.timeout = Timeout::Timer;
                }
                Pass::Again
            }
        };
        match pass {
            Pass::Error(errno) if taken.is_empty() => {
                drop(state);
                wake_all(woken);
                return fail(errno) as isize;
            }
            Pass::Done | Pass::Error(_) => {
                if !taken.is_empty() {
                    touch_side(&mut state.ptys, side, index, false);
                }
                drop(state);
                wake_all(woken);
                if !taken.is_empty() {
                    // SAFETY: writable for `length` bytes, and `taken` is no
                    // longer.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            taken.as_ptr(),
                            destination.cast::<u8>(),
                            taken.len(),
                        );
                    }
                }
                set_errno(0);
                return taken.len() as isize;
            }
            Pass::Again => {
                drop(state);
                wake_all(woken);
                continue;
            }
            Pass::Wait => {}
        }
        pair.waiters[side.slot()].push_back(me);
        let step = state.block(
            me,
            "pty-read",
            Wait::new(BlockClass::Io, vec![WaiterLoc::Pty(index, side)]),
        );
        match step {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => return fail(error.into_posix()) as isize,
        }
        let mut state = lock_state();
        state.timed_out.remove(&me);
        unwatch(&mut state, index, side, me);
        drop(state);
        if signals::resume() == signals::Resumed::Eintr {
            if !taken.is_empty() {
                // SAFETY: as above.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        taken.as_ptr(),
                        destination.cast::<u8>(),
                        taken.len(),
                    );
                }
                return taken.len() as isize;
            }
            return fail(crate::EINTR) as isize;
        }
    }
}

/// `tty_write` on a pair's descriptor (`n_tty_write`): a hung-up slave, or
/// one whose last open failed, is `EIO`. The slave's bytes go through its
/// output processing to the master; the master's are received under the
/// slave's settings, which may echo them back. A direction that would hold
/// more than [`ROOM`] unread bytes, and a write to a master whose slave has
/// closed (6.8 leaves its bytes unprocessed until the slave reopens), stop
/// by name. Every write, an empty one too, wakes its own side's writers
/// (`tty_write_unlock`); a receiving side's readers wake as its line
/// discipline delivers (`__receive_buf`: a canonical slave's on a line end
/// only, a raw side's whenever it holds input).
///
/// # Safety
/// `source` must be readable for `length` bytes when nonzero.
pub(crate) unsafe fn write(
    resolved: crate::fdtable::Resolved,
    source: *const c_void,
    length: usize,
    nonblocking: bool,
) -> isize {
    let _ = nonblocking;
    let side = Side::of(resolved.kind).expect("a pty kind");
    let index = resolved.handle as u32;
    if let Err(errno) = sched_point() {
        return fail(errno) as isize;
    }
    let bytes = if length == 0 {
        &[][..]
    } else {
        // SAFETY: readable for `length` bytes per this function's contract.
        unsafe { std::slice::from_raw_parts(source.cast::<u8>(), length) }
    };
    let mut state = lock_state();
    let Some(pair) = state.ptys.pairs.get_mut(&index) else {
        return fail(crate::EBADF) as isize;
    };
    if side == Side::Slave && (hung_up(pair) || pair.io_error) {
        return fail(EIO) as isize;
    }
    let mut woken = pair.wake(side, false, true);
    if bytes.is_empty() {
        drop(state);
        wake_all(woken);
        set_errno(0);
        return 0;
    }
    let (lines_had, master_had) = (pair.canon, pair.to_master.len());
    match side {
        Side::Master => {
            if pair.slave_closed {
                drop(state);
                unmodeled("a write to a master whose slave has closed");
            }
            for &byte in bytes {
                pair.receive(byte);
            }
        }
        Side::Slave => {
            for &byte in bytes {
                pair.output(byte);
            }
        }
    }
    if pair.to_slave.len() > ROOM || pair.to_master.len() > ROOM {
        drop(state);
        unmodeled("a direction holding more than 4095 unread bytes (the kernel's flow control)");
    }
    if side == Side::Master {
        let delivered = if pair.canonical() {
            pair.canon != lines_had
        } else {
            !pair.to_slave.is_empty()
        };
        if delivered {
            woken.extend(pair.wake(Side::Slave, true, false));
        }
    }
    if pair.to_master.len() != master_had {
        woken.extend(pair.wake(Side::Master, true, false));
    }
    touch_side(&mut state.ptys, side, index, true);
    drop(state);
    wake_all(woken);
    set_errno(0);
    length as isize
}

/// `n_tty_poll`, or `hung_up_tty_poll` for a hung-up slave: every event.
/// A side is readable when a read would take something (a canonical slave's
/// complete line; a raw slave's `VMIN` bytes when `VTIME` is 0); a master
/// polls hung up once its last slave description closed; either side takes
/// a write while the pair is live.
pub(in crate::thread) fn poll(state: &ThreadRuntime, side: Side, index: u32) -> (u32, (u64, u64)) {
    use super::net::abi::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
    let Some(pair) = state.ptys.pairs.get(&index) else {
        return (POLLERR | POLLHUP, (0, 0));
    };
    if side == Side::Slave && hung_up(pair) {
        return (
            POLLIN | POLLOUT | POLLERR | POLLHUP | POLLRDNORM | POLLWRNORM,
            pair.edges[side.slot()],
        );
    }
    let mut mask = POLLOUT | POLLWRNORM;
    if pair.readable(side, true) {
        mask |= POLLIN | POLLRDNORM;
    }
    if side == Side::Master && pair.slave_closed {
        mask |= POLLHUP;
    }
    (mask, pair.edges[side.slot()])
}

/// Register a readiness reactor's task on a side's queue: it wakes on every
/// wakeup of the side (a pair's descriptor is writable whenever it is live,
/// so only an edge-triggered interest in output waits for one).
pub(in crate::thread) fn watch(
    state: &mut ThreadRuntime,
    side: Side,
    index: u32,
    me: TaskId,
) -> Option<WaiterLoc> {
    let pair = state.ptys.pairs.get_mut(&index)?;
    let waiters = &mut pair.waiters[side.slot()];
    if !waiters.contains(&me) {
        waiters.push_back(me);
    }
    Some(WaiterLoc::Pty(index, side))
}

/// Unlink `me` from a side's queue.
pub(in crate::thread) fn unwatch(state: &mut ThreadRuntime, index: u32, side: Side, me: TaskId) {
    if let Some(pair) = state.ptys.pairs.get_mut(&index) {
        pair.waiters[side.slot()].retain(|task| *task != me);
    }
}

/// `TIOCINQ` (`FIONREAD`): the bytes a read would take now (a canonical
/// slave counts its complete lines less their ends of file); `EIO` on a
/// hung-up slave.
pub(crate) fn inq(side: Side, index: u32) -> Result<i32, c_int> {
    let state = lock_state();
    let pair = state.ptys.pairs.get(&index).ok_or(crate::EBADF)?;
    if side == Side::Slave && hung_up(pair) {
        return Err(EIO);
    }
    Ok(pair.queued(side) as i32)
}

/// The name `/proc/self/fd` reads for a pseudoterminal descriptor
/// (`ttyname`'s answer): its length, written with its terminator when `len`
/// has room; `ENOTTY` for any other descriptor, `EBADF` for none.
///
/// # Safety
/// `buf` must be writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_pty_name(fd: c_int, buf: *mut c_char, len: usize) -> isize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let resolved = match crate::resolve_fd(fd) {
        Ok(resolved) => resolved,
        Err(errno) => return fail(errno) as isize,
    };
    let Some(side) = Side::of(resolved.kind) else {
        return fail(ENOTTY) as isize;
    };
    let name = name(side, resolved.handle as u32);
    if name.len() < len {
        // SAFETY: writable for `len` bytes per this function's contract.
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), buf.cast::<u8>(), name.len());
            buf.add(name.len()).write(0);
        }
    }
    set_errno(0);
    name.len() as isize
}
