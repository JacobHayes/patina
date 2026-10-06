//! Terminal ioctl requests and termios updates.

use super::*;

// ---- requests ----------------------------------------------------------

const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
const TCSBRK: u64 = 0x5409;
const TCFLSH: u64 = 0x540B;
const TCIFLUSH: usize = 0;
const TCOFLUSH: usize = 1;
const TCIOFLUSH: usize = 2;
const TIOCSCTTY: u64 = 0x540E;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;
const TIOCOUTQ: u64 = 0x5411;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const TIOCNOTTY: u64 = 0x5422;
const TIOCGETD: u64 = 0x5424;
const TCSBRKP: u64 = 0x5425;
const TIOCGSID: u64 = 0x5429;
const TIOCGPTN: u64 = 0x8004_5430;
const TIOCSPTLCK: u64 = 0x4004_5431;
const TIOCGPTLCK: u64 = 0x8004_5439;
const TIOCGPTPEER: u64 = 0x5441;

/// Stop the run: the tty request is not modeled.
pub(super) fn stop(request: u64) -> ! {
    crate::trap_fatal(&format!(
        "ioctl: tty request {request:#x} on a pseudoterminal is not modeled; failing closed"
    ))
}

pub(super) fn put<T: Copy>(arg: usize, value: T) -> c_int {
    match uaccess::write(arg, &value) {
        Ok(()) => {
            set_errno(0);
            0
        }
        Err(errno) => fail(errno),
    }
}

pub(super) fn done() -> c_int {
    set_errno(0);
    0
}

/// `tty_ioctl` for a pair's descriptor, past the requests every descriptor
/// takes (`do_vfs_ioctl`). A hung-up slave answers every request `EIO`
/// (`hung_up_tty_ioctl`), `TIOCSPGRP` `ENOTTY`.
pub(crate) fn ioctl(side: Side, index: u32, request: u64, arg: usize) -> c_int {
    // Requests of another type go on to the line discipline, which knows
    // none of them.
    let tty_request = (request >> 8) & 0xff == u64::from(b'T');
    let mut state = lock_state();
    let Some(pair) = state.ptys.pairs.get_mut(&index) else {
        return fail(crate::EBADF);
    };
    if side == Side::Slave && hung_up(pair) {
        return fail(if request == TIOCSPGRP { ENOTTY } else { EIO });
    }
    if !tty_request {
        return fail(ENOTTY);
    }
    match request {
        TCGETS => {
            let termios = pair.termios;
            drop(state);
            put(arg, termios)
        }
        TCSETS | TCSETSW | TCSETSF => {
            let Ok(new) = uaccess::read::<Termios>(arg) else {
                return fail(EFAULT);
            };
            // `EXTPROC` changes how every read, poll and count judges the
            // input, which the model does not.
            if new.lflag & EXTPROC != 0 {
                drop(state);
                unmodeled("EXTPROC (input processing left to the other side)");
            }
            // `TCSETSF` flushes the slave's input first (`n_tty_flush_buffer`).
            if request == TCSETSF {
                pair.flush(Side::Slave);
            }
            set_termios(pair, new);
            // `n_tty_set_termios` wakes the slave's queues, and only the
            // slave's, whichever side asked.
            let woken = pair.wake(Side::Slave, true, true);
            drop(state);
            wake_all(woken);
            done()
        }
        // `__tty_perform_flush` on the descriptor's own side: its input,
        // and the other side's unprocessed bytes, of which there are none.
        // `tty_unthrottle` after an input flush: a pty side is always
        // marked throttled once open, so `pty_unthrottle` wakes the other
        // side's writers.
        TCFLSH => match arg {
            TCIFLUSH | TCIOFLUSH => {
                pair.flush(side);
                let woken = pair.wake(side.other(), false, true);
                drop(state);
                wake_all(woken);
                done()
            }
            TCOFLUSH => done(),
            _ => fail(crate::EINVAL),
        },
        TIOCGWINSZ => {
            let winsize = pair.winsize;
            drop(state);
            put(arg, winsize)
        }
        // `tty_do_resize` (a Unix98 slave has no `.resize`): the foreground
        // group a change signals is the controlling terminal's, which this
        // pair never is.
        TIOCSWINSZ => match uaccess::read::<Winsize>(arg) {
            Ok(winsize) => {
                pair.winsize = winsize;
                done()
            }
            Err(errno) => fail(errno),
        },
        TIOCGPTN if side == Side::Master => {
            drop(state);
            put(arg, index)
        }
        TIOCSPTLCK if side == Side::Master => match uaccess::read::<i32>(arg) {
            Ok(value) => {
                pair.locked = value != 0;
                done()
            }
            Err(errno) => fail(errno),
        },
        TIOCGPTLCK if side == Side::Master => {
            let locked = i32::from(pair.locked);
            drop(state);
            put(arg, locked)
        }
        TIOCGPTPEER if side == Side::Master => {
            drop(state);
            open_peer(index, arg as i32)
        }
        // `ptm_open_peer` of a slave; the other master requests fall to
        // the line discipline.
        TIOCGPTPEER => fail(EIO),
        TIOCGPTN | TIOCSPTLCK | TIOCGPTLCK => fail(ENOTTY),
        // `tty_wait_until_sent` finds nothing queued in a pty, and a pty
        // has no break to send.
        TCSBRK | TCSBRKP => done(),
        // `n_tty_ioctl`: the driver holds nothing unsent.
        TIOCOUTQ => {
            drop(state);
            put(arg, 0i32)
        }
        TIOCGETD => {
            drop(state);
            put(arg, 0i32)
        }
        // The job-control requests, for a terminal that is not the
        // caller's controlling one (`tty_jobctrl_ioctl`).
        TIOCGPGRP if side == Side::Master => {
            drop(state);
            put(arg, 0i32)
        }
        TIOCGPGRP | TIOCGSID | TIOCNOTTY => fail(ENOTTY),
        TIOCSPGRP => {
            drop(state);
            match uaccess::read::<i32>(arg) {
                Err(errno) => fail(errno),
                Ok(pgrp) if pgrp < 0 => fail(crate::EINVAL),
                Ok(_) => fail(ENOTTY),
            }
        }
        TIOCSCTTY if !crate::identity::session_leader() => fail(crate::EPERM),
        _ => {
            drop(state);
            stop(request)
        }
    }
}

/// `set_termios` → `tty_set_termios` → `pty_set_termios` on the pair's
/// slave: `ADDRB` stays, and the character size and receiver are forced
/// to 8 bits, no parity; then the line discipline's (`n_tty_set_termios`).
fn set_termios(pair: &mut Pair, mut new: Termios) {
    let was_canonical = pair.canonical();
    new.cflag ^= (new.cflag ^ pair.termios.cflag) & ADDRB;
    new.cflag &= !(CSIZE | PARENB);
    new.cflag |= CS8 | CREAD;
    pair.termios = new;
    pair.recanonicalize(was_canonical);
}
