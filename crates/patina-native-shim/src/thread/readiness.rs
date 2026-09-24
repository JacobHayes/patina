//! poll/select are adapters over the same readiness predicates and per-source
//! wait queues as epoll. All use no-restart signal waits and atomic mask swaps.
use super::signals::{Resumed, resume, with_temporary_mask};
use super::*;
use crate::EINTR;
const EFAULT: i32 = 14;

pub(super) const POLLIN: i16 = 0x001;
const POLLPRI: i16 = 0x002;
const POLLOUT: i16 = 0x004;
const POLLERR: i16 = 0x008;
const POLLHUP: i16 = 0x010;
const POLLNVAL: i16 = 0x020;
const POLLRDNORM: i16 = 0x040;
const POLLWRNORM: i16 = 0x100;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

fn poll(fds: &mut [PollFd], timeout: Option<u64>, mut remaining: Option<&mut u64>) -> i64 {
    // Rust std checks the standard descriptors before a deferred harness has
    // installed Context. An immediately resolved query needs neither clock nor
    // scheduler; activate only when this call genuinely needs to park.
    let mut deadline = None;
    if let (Some(timeout), Some(out)) = (timeout, remaining.as_deref_mut()) {
        *out = timeout;
    }
    let update_remaining = |deadline: Option<u64>, remaining: &mut Option<&mut u64>| {
        if let (Some(deadline), Some(out)) = (deadline, remaining.as_deref_mut()) {
            let now = with_context_raw(|context| context.now(ClockKind::Monotonic))
                .unwrap_or_else(|_| fatal("readiness wait clock read failed"));
            *out = deadline.saturating_sub(now);
        }
    };
    loop {
        let mut state = lock_state();
        let mut count = 0;
        let mut watched = Vec::new();
        for fd in fds.iter_mut() {
            fd.revents = 0;
            if fd.fd < 0 {
                continue;
            }
            if crate::fd_table().lock().resolve(fd.fd).is_none() {
                fd.revents = POLLNVAL;
            } else {
                let mut ready = fd_readiness(&state, fd.fd, None);
                // A simplex pipe's EOF is POLLHUP, not POLLIN. select turns
                // HUP back into read readiness below; the byte-channel backend
                // also serves socketpair, whose EOF remains readable.
                let entry = crate::fd_table().lock().resolve(fd.fd).unwrap();
                if entry.kind == FdKind::Pipe {
                    if let Some(end) = state.net.pipe_ends.get(&(entry.handle as i32)) {
                        if let Some(channel) = end
                            .read_channel
                            .and_then(|id| state.net.pipe_channels.get(&id))
                        {
                            if end.write_channel.is_none() {
                                ready.readable = !channel.buffer.is_empty();
                                ready.read_eof = channel.write_closed();
                            }
                        }
                    }
                }
                if ready.readable {
                    fd.revents |= fd.events & (POLLIN | POLLRDNORM);
                }
                if ready.writable {
                    fd.revents |= fd.events & (POLLOUT | POLLWRNORM);
                }
                if ready.read_eof {
                    fd.revents |= POLLHUP;
                }
                if ready.write_eof {
                    fd.revents |= POLLERR;
                }
                if fd.events & (POLLIN | POLLRDNORM) != 0 {
                    watched.push((ReadyDir::Read, fd.fd));
                }
                if fd.events & (POLLOUT | POLLWRNORM) != 0 {
                    watched.push((ReadyDir::Write, fd.fd));
                }
            }
            if fd.revents != 0 {
                count += 1;
            }
        }
        update_remaining(deadline, &mut remaining);
        if count != 0 || timeout == Some(0) {
            return count;
        }
        if let Err(error) = state.ensure_active() {
            return -i64::from(error.into_posix());
        }
        let me = current_task();
        if deadline.is_none() {
            if let Some(timeout) = timeout {
                let now = with_context_raw(|context| context.now(ClockKind::Monotonic))
                    .unwrap_or_else(|_| fatal("readiness wait clock read failed"));
                deadline = Some(now.saturating_add(timeout));
            }
        }
        if deadline.is_some_and(|deadline| {
            with_context_raw(|context| context.now(ClockKind::Monotonic))
                .unwrap_or_else(|_| fatal("readiness wait clock read failed"))
                >= deadline
        }) {
            return 0;
        }
        let locs = register_readiness_waiters(&mut state, me, &watched);
        let step = match deadline {
            Some(deadline) => state.block_timed(
                me,
                "poll",
                Wait::new(BlockClass::Readiness, locs.clone()),
                ClockKind::Monotonic,
                deadline,
            ),
            None => state.block(me, "poll", Wait::new(BlockClass::Readiness, locs.clone())),
        };
        match step {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => {
                unregister_waiters(&mut state, me, &locs);
                return -i64::from(error.into_posix());
            }
        }
        {
            let mut state = lock_state();
            unregister_waiters(&mut state, me, &locs);
            state.timed_out.remove(&me);
        }
        update_remaining(deadline, &mut remaining);
        if resume() == Resumed::Eintr {
            return -i64::from(EINTR);
        }
    }
}

/// Raw-errno ABI shared by poll/ppoll on both doors. Negative timeout means
/// indefinite; nonnegative timeout is relative nanoseconds.
/// # Safety
/// `fds` names `count` pollfd records; non-null mask names eight bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_poll(
    fds: *mut PollFd,
    count: usize,
    timeout: i64,
    mask: *const u64,
    remaining: *mut u64,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if count > crate::fd_limit() {
        return -i64::from(EINVAL);
    }
    if count != 0 && fds.is_null() {
        return -i64::from(EFAULT);
    }
    let fds = if count == 0 {
        &mut []
    } else {
        unsafe { std::slice::from_raw_parts_mut(fds, count) }
    };
    unsafe {
        with_temporary_mask(mask, || {
            poll(
                fds,
                (timeout >= 0).then_some(timeout as u64),
                remaining.as_mut(),
            )
        })
    }
}

/// # Safety
/// Same buffer contract as patina_epoll_wait; optional mask names eight bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_epoll_wait_masked(
    ep: i32,
    events: *mut c_void,
    capacity: i32,
    timeout: i32,
    mask: *const u64,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe {
        with_temporary_mask(mask, || {
            let rc = epoll::patina_epoll_wait(ep, events, capacity, timeout);
            if rc < 0 {
                -i64::from(crate::patina_errno())
            } else {
                i64::from(rc)
            }
        })
    }
}

/// select/pselect use native-word fd sets. Timeout is relative nanoseconds;
/// `remaining` lets each door write its timeval/timespec by its ABI rules.
/// # Safety
/// Each non-null set has ceil(nfds/64) words; optional remaining names a u64.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_select(
    nfds: i32,
    read: *mut u64,
    write: *mut u64,
    except: *mut u64,
    timeout: i64,
    mask: *const u64,
    remaining: *mut u64,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if nfds < 0 || nfds as usize > crate::fdtable::RLIMIT_NOFILE {
        return -i64::from(EINVAL);
    }
    let mut fds = Vec::new();
    for fd in 0..nfds {
        let bit = 1u64 << (fd % 64);
        let index = fd as usize / 64;
        let mut events = 0;
        for (set, event) in [(read, POLLIN), (write, POLLOUT), (except, POLLPRI)] {
            if !set.is_null() && unsafe { *set.add(index) } & bit != 0 {
                events |= event;
            }
        }
        if events != 0 {
            if crate::fd_table().lock().resolve(fd).is_none() {
                return -i64::from(crate::EBADF);
            }
            fds.push(PollFd {
                fd,
                events,
                revents: 0,
            });
        }
    }
    let rc = unsafe {
        with_temporary_mask(mask, || {
            poll(
                &mut fds,
                (timeout >= 0).then_some(timeout as u64),
                remaining.as_mut(),
            )
        })
    };
    if rc < 0 {
        return rc;
    }
    for set in [read, write, except] {
        if !set.is_null() {
            unsafe {
                std::ptr::write_bytes(set, 0, (nfds as usize).div_ceil(64));
            }
        }
    }
    let mut count = 0;
    for fd in fds {
        for (set, requested, ready) in [
            (read, POLLIN, POLLIN | POLLHUP | POLLERR),
            (write, POLLOUT, POLLOUT | POLLERR),
            (except, POLLPRI, POLLPRI),
        ] {
            if !set.is_null() && fd.events & requested != 0 && fd.revents & ready != 0 {
                unsafe {
                    *set.add(fd.fd as usize / 64) |= 1u64 << (fd.fd % 64);
                }
                count += 1;
            }
        }
    }
    count
}

#[cfg(test)]
mod tests;
