//! poll, ppoll, select, pselect6, epoll_wait, epoll_pwait, epoll_pwait2: the same
//! call with a zero timeout is the attempt; if nothing is ready the thread parks until the
//! I/O generation moves or the virtual deadline passes (then 0). A zero timeout from the
//! guest never parks (each such call is still charged: the poll churn rule). Signal masks
//! given to ppoll/pselect6/epoll_pwait are not given to the kernel (the mask is virtual).

use super::io::{self, Deadline, Got, Waiter};
use super::*;
use proto::layout::FD_HIDDEN_MIN;

const NS: u64 = 1_000_000_000;
const POLLNVAL: u32 = 0x20;
const PPOLL: u64 = 271;
const MAX_HIDDEN: usize = 32;

/// Read a guest timespec (None: NULL pointer = wait forever).
fn timespec(p: u64) -> Result<Option<u64>, i64> {
    if p == 0 {
        return Ok(None);
    }
    super::time::read_timespec(p).map(Some)
}

fn timeval(p: u64) -> Result<Option<u64>, i64> {
    if p == 0 {
        return Ok(None);
    }
    let [s, us] = get::<[i64; 2]>(p)?;
    if s < 0 || !(0..1_000_000).contains(&us) {
        return Err(-e::EINVAL);
    }
    Ok(Some(
        (s as u64)
            .saturating_mul(NS)
            .saturating_add(us as u64 * 1000),
    ))
}

/// Remaining time to a deadline (the kernel writes it back for ppoll, select, pselect6).
fn remaining(dl: Option<u64>) -> u64 {
    dl.map(|d| d.saturating_sub(super::time::now()))
        .unwrap_or(0)
}

/// Run `attempt` (returns > 0 when something is ready) under the waiting rules.
fn wait_ready(w: &mut Waiter, timeout_ns: Option<u64>, mut attempt: impl FnMut() -> i64) -> i64 {
    if timeout_ns == Some(0) {
        return attempt();
    }
    w.nonblock = Some(false);
    w.deadline = match timeout_ns {
        Some(ns) => Deadline::after(ns),
        None => Deadline::None,
    };
    let g = w.run(|| {
        let r = attempt();
        if r == 0 {
            None
        } else {
            Some(r)
        }
    });
    let r = match g {
        Got::Done(r) => r,
        Got::TimedOut => 0,
        g => io::result(g, 0),
    };
    w.finish(r)
}

/// One zero-timeout ppoll over the guest's array; descriptors at hidden numbers answer
/// POLLNVAL (they are set to -1 for the kernel call and restored).
fn ppoll0(fds: u64, n: u64) -> i64 {
    let mut hidden = [(0u64, 0i32); MAX_HIDDEN];
    let mut nh = 0;
    if fds != 0 {
        let restore = |hidden: &[(u64, i32)]| {
            for &(j, f) in hidden {
                let _ = put(fds + j * 8, f);
            }
        };
        for i in 0..n.min(4096) {
            let fd = match get::<i32>(fds + i * 8) {
                Ok(fd) => fd,
                Err(r) => {
                    restore(&hidden[..nh]);
                    return r;
                }
            };
            if fd >= FD_HIDDEN_MIN {
                if nh == MAX_HIDDEN {
                    restore(&hidden[..nh]);
                    return -e::EINVAL;
                }
                hidden[nh] = (i, fd);
                nh += 1;
                if let Err(r) = put(fds + i * 8, -1i32) {
                    restore(&hidden[..nh - 1]);
                    return r;
                }
            }
        }
    }
    let ts = [0u64; 2];
    let r = unsafe { sc6(PPOLL, fds, n, ts.as_ptr() as u64, 0, 8, 0) };
    for &(i, fd) in &hidden[..nh] {
        // Both words were read and written above: these copies succeed.
        let ev = get::<u32>(fds + i * 8 + 4).unwrap_or(0);
        let _ = put(fds + i * 8, [fd as u32, (ev & 0xffff) | (POLLNVAL << 16)]);
    }
    if r < 0 {
        r
    } else {
        r + nh as i64
    }
}

fn first_fd(fds: u64, n: u64) -> i64 {
    if fds == 0 || n == 0 {
        -1
    } else {
        get::<i32>(fds).map_or(-1, |fd| fd as i64)
    }
}

/// poll(fds, n, timeout_ms) and ppoll(fds, n, tsp, sigmask, size).
pub fn poll(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let (fds, n) = (a[0], a[1]);
    let (timeout, tsp) = if call.nr() == 7 {
        let t = a[2] as i32;
        (
            if t < 0 {
                None
            } else {
                Some(t as u64 * 1_000_000)
            },
            0,
        )
    } else {
        match timespec(a[2]) {
            Ok(t) => (t, a[2]),
            Err(e) => return e,
        }
    };
    let mut w = Waiter::new(first_fd(fds, n), proto::ctl::PARK_IN, call.nr());
    w.nfds = n;
    let dl = timeout.map(|t| super::time::now().saturating_add(t));
    let r = wait_ready(&mut w, timeout, || ppoll0(fds, n));
    if tsp != 0 && r >= 0 {
        let left = remaining(dl);
        let _ = put(tsp, [left / NS, left % NS]);
    }
    r
}

const SET_WORDS: usize = (FD_HIDDEN_MIN as usize).div_ceil(64);

/// select(n, r, w, x, timeval) and pselect6(n, r, w, x, timespec, sigmask).
pub fn select(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let mut n = a[0] as i32 as i64;
    if n < 0 {
        return -e::EINVAL;
    }
    let sets = [a[1], a[2], a[3]];
    if n > FD_HIDDEN_MIN as i64 {
        // A hidden descriptor named in a set is a bad descriptor.
        for &s in &sets {
            if s == 0 {
                continue;
            }
            for fd in FD_HIDDEN_MIN as i64..n {
                let word = match get::<u64>(s + (fd as u64 / 64) * 8) {
                    Ok(w) => w,
                    Err(r) => return r,
                };
                if word & (1 << (fd % 64)) != 0 {
                    return -e::EBADF;
                }
            }
        }
        n = FD_HIDDEN_MIN as i64;
    }
    let words = (n as usize).div_ceil(64);
    let mut saved = [[0u64; SET_WORDS]; 3];
    for (k, &s) in sets.iter().enumerate() {
        if s != 0 {
            for (i, w) in saved[k][..words].iter_mut().enumerate() {
                *w = match get::<u64>(s + i as u64 * 8) {
                    Ok(v) => v,
                    Err(r) => return r,
                };
            }
        }
    }
    let pselect = call.nr() == 270;
    let timeout = if pselect {
        timespec(a[4])
    } else {
        timeval(a[4])
    };
    let timeout = match timeout {
        Ok(t) => t,
        Err(e) => return e,
    };
    let first = (0..n).find(|&fd| {
        (0..3).any(|k| sets[k] != 0 && saved[k][fd as usize / 64] & (1 << (fd % 64)) != 0)
    });
    let mut w = Waiter::new(first.unwrap_or(-1), proto::ctl::PARK_IN, call.nr());
    w.nfds = n as u64;
    let dl = timeout.map(|t| super::time::now().saturating_add(t));
    let r = wait_ready(&mut w, timeout, || {
        for (k, &s) in sets.iter().enumerate() {
            if s != 0 {
                for (i, &w) in saved[k][..words].iter().enumerate() {
                    // Read above; a set the kernel cannot write is its EFAULT below.
                    let _ = put(s + i as u64 * 8, w);
                }
            }
        }
        let ts = [0u64; 2];
        // pselect6 with a zero timespec and no mask: the attempt for both.
        unsafe {
            sc6(
                270,
                n as u64,
                sets[0],
                sets[1],
                sets[2],
                ts.as_ptr() as u64,
                0,
            )
        }
    });
    if a[4] != 0 && r >= 0 {
        let left = remaining(dl);
        let _ = if pselect {
            put(a[4], [left / NS, left % NS])
        } else {
            put(a[4], [left / NS, (left % NS) / 1000])
        };
    }
    r
}

/// epoll_wait(ep, ev, max, ms), epoll_pwait(ep, ev, max, ms, mask, size),
/// epoll_pwait2(ep, ev, max, timespec, mask, size).
pub fn epoll_wait(call: &mut dyn Call) -> i64 {
    let a = args(call);
    let timeout = if call.nr() == 441 {
        match timespec(a[3]) {
            Ok(t) => t,
            Err(e) => return e,
        }
    } else {
        let t = a[3] as i32;
        if t < 0 {
            None
        } else {
            Some(t as u64 * 1_000_000)
        }
    };
    let mut w = Waiter::new(a[0] as i32 as i64, proto::ctl::PARK_IN, call.nr());
    wait_ready(&mut w, timeout, || unsafe {
        sc6(281, a[0], a[1], a[2], 0, 0, 8)
    })
}

/// epoll_ctl passes; the interest list changed, so a waiter on this epoll may now be ready.
pub fn epoll_ctl(call: &mut dyn Call) -> i64 {
    let r = raw(call);
    host_check(call, r);
    if r == 0 {
        io::bump();
    }
    r
}
