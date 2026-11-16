//! File locks: `flock` and `fcntl(F_SETLKW / F_OFD_SETLKW)` are try-locks plus a park
//! until the I/O generation moves (an unlock, a close, a lock change moves it).

use super::io::{self, Waiter};
use super::*;
use proto::ctl::PARK_LOCK;

const LOCK_NB: u64 = 4;
const LOCK_UN: u64 = 8;
pub const F_SETLK: u64 = 6;
pub const F_SETLKW: u64 = 7;
pub const F_OFD_SETLK: u64 = 37;
pub const F_OFD_SETLKW: u64 = 38;

pub fn flock(call: &mut dyn Call) -> i64 {
    let (fd, op) = (call.arg(0), call.arg(1));
    if op & (LOCK_NB | LOCK_UN) != 0 {
        let r = raw(call);
        if r == 0 {
            io::bump();
        }
        return r;
    }
    let mut w = Waiter::new(fd as i32 as i64, PARK_LOCK, 73);
    w.nonblock = Some(false);
    let g = w.run(|| io::eagain(unsafe { sc2(73, fd, op | LOCK_NB) }));
    let r = io::result(g, -e::EAGAIN);
    if r == 0 {
        io::bump();
    }
    w.finish(r)
}

/// F_SETLK / F_OFD_SETLK (any change of lock state moves the generation) and the waiting
/// forms as try-locks plus park.
pub fn fcntl_lock(fd: u64, cmd: u64, arg: u64) -> i64 {
    let r = match cmd {
        F_SETLKW | F_OFD_SETLKW => {
            let try_cmd = if cmd == F_SETLKW {
                F_SETLK
            } else {
                F_OFD_SETLK
            };
            let mut w = Waiter::new(fd as i32 as i64, PARK_LOCK, 72);
            w.nonblock = Some(false);
            let g = w.run(|| {
                let r = unsafe { sc3(nr::FCNTL, fd, try_cmd, arg) };
                if r == -e::EAGAIN || r == -e::EACCES {
                    None
                } else {
                    Some(r)
                }
            });
            w.finish(io::result(g, -e::EAGAIN))
        }
        _ => unsafe { sc3(nr::FCNTL, fd, cmd, arg) },
    };
    if r == 0 {
        io::bump();
    }
    r
}
