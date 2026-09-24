//! poll/select are adapters over the same readiness predicates and per-source
//! wait queues as epoll. All use no-restart signal waits and atomic mask swaps.
use super::signals::{Resumed, resume, with_temporary_mask};
use super::*;
use crate::EINTR;

pub(super) const POLLIN: i16 = 0x001;
const POLLPRI: i16 = 0x002;
const POLLOUT: i16 = 0x004;
const POLLERR: i16 = 0x008;
const POLLHUP: i16 = 0x010;
const POLLNVAL: i16 = 0x020;

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
            match fd_poll(&state, fd.fd, None) {
                None => fd.revents = POLLNVAL,
                Some((mask, _)) => {
                    // `do_pollfd`: the requested events and the ones always
                    // reported.
                    let filter = fd.events as u16 as u32 | (POLLERR | POLLHUP) as u32;
                    fd.revents = (mask & filter) as u16 as i16;
                    // The object's wait queue wakes on any change: watch both
                    // directions.
                    watched.push((ReadyDir::Read, fd.fd));
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
    // `do_sys_poll`: the count is judged against the limit before the array
    // is read, the array is copied in whole, and every `revents` is copied
    // back out once the wait ends, whatever it answered.
    if count > crate::fd_limit() {
        return -i64::from(EINVAL);
    }
    let mut local = match crate::uaccess::read_vec::<PollFd>(fds as usize, count) {
        Ok(local) => local,
        Err(errno) => return -i64::from(errno),
    };
    let rc = unsafe {
        with_temporary_mask(mask, || {
            poll(
                &mut local,
                (timeout >= 0).then_some(timeout as u64),
                remaining.as_mut(),
            )
        })
    };
    match crate::uaccess::write_slice(fds as usize, &local) {
        Ok(()) => rc,
        Err(errno) => -i64::from(errno),
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
/// The sets are copied in and out whole (`EFAULT` for one that cannot be),
/// as `core_sys_select` copies them.
/// # Safety
/// An optional mask names eight bytes; optional remaining names a u64.
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
    if nfds < 0 {
        return -i64::from(EINVAL);
    }
    // `core_sys_select`: a count past the table is the table's size.
    let nfds = nfds.min(crate::fd_limit() as i32);
    let words = (nfds as usize).div_ceil(64);
    let load = |set: *mut u64| -> Result<Vec<u64>, i32> {
        if set.is_null() {
            Ok(vec![0; words])
        } else {
            crate::uaccess::read_vec(set as usize, words)
        }
    };
    let (sets_in, write_in, except_in) = match (load(read), load(write), load(except)) {
        (Ok(read), Ok(write), Ok(except)) => (read, write, except),
        (Err(errno), _, _) | (_, Err(errno), _) | (_, _, Err(errno)) => {
            return -i64::from(errno);
        }
    };
    let mut fds = Vec::new();
    for fd in 0..nfds {
        let bit = 1u64 << (fd % 64);
        let index = fd as usize / 64;
        let mut events = 0;
        for (set, event) in [
            (&sets_in, POLLIN),
            (&write_in, POLLOUT),
            (&except_in, POLLPRI),
        ] {
            if set[index] & bit != 0 {
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
    let mut out = [vec![0u64; words], vec![0u64; words], vec![0u64; words]];
    let mut count = 0;
    for fd in fds {
        // `POLLIN_SET`, `POLLOUT_SET`, `POLLEX_SET`.
        for (slot, requested, ready) in [
            (0, POLLIN, POLLIN | POLLHUP | POLLERR),
            (1, POLLOUT, POLLOUT | POLLERR),
            (2, POLLPRI, POLLPRI),
        ] {
            if fd.events & requested != 0 && fd.revents & ready != 0 {
                out[slot][fd.fd as usize / 64] |= 1u64 << (fd.fd % 64);
                count += 1;
            }
        }
    }
    for (set, bits) in [read, write, except].into_iter().zip(&out) {
        if !set.is_null() {
            if let Err(errno) = crate::uaccess::write_slice(set as usize, bits) {
                return -i64::from(errno);
            }
        }
    }
    count
}

/// The `select` row (`kern_select`): its `struct timeval` copied in and
/// normalized — microseconds reaching a second carry into the seconds; only
/// a time that is still negative is `EINVAL` — and the unslept time written
/// back where it can be.
/// # Safety
/// As [`patina_select`]; a non-null `timeval` names the guest's timeval.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_select_timeval(
    nfds: i32,
    read: *mut u64,
    write: *mut u64,
    except: *mut u64,
    timeval: usize,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    const USEC: i64 = 1_000_000;
    let nanos = if timeval == 0 {
        -1
    } else {
        let [sec, usec]: [i64; 2] = match crate::uaccess::read(timeval) {
            Ok(tv) => tv,
            Err(errno) => return -i64::from(errno),
        };
        let sec = sec.saturating_add(usec / USEC);
        let nsec = (usec % USEC) * 1000;
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return -i64::from(EINVAL);
        }
        sec.saturating_mul(1_000_000_000).saturating_add(nsec)
    };
    let mut remaining = nanos.max(0) as u64;
    let rc = unsafe {
        patina_select(
            nfds,
            read,
            write,
            except,
            nanos,
            std::ptr::null(),
            &mut remaining,
        )
    };
    if timeval != 0 && (rc >= 0 || rc == -i64::from(EINTR)) {
        let left = [
            (remaining / 1_000_000_000) as i64,
            ((remaining % 1_000_000_000) / 1000) as i64,
        ];
        // `poll_select_finish`: a timeval that cannot be written back
        // leaves the result as it is.
        let _ = crate::uaccess::write(timeval, &left);
    }
    rc
}

#[cfg(test)]
mod tests;
