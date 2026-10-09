//! poll/select are adapters over the same readiness predicates and per-source
//! wait queues as epoll. All use no-restart signal waits and atomic mask swaps.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::signals::{Resumed, resume, temporary_mask, with_mask, with_temporary_mask};
use super::*;
use crate::EINTR;
use crate::abi::{Errno, SysResult};

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

#[allow(dead_code)]
mod plain_impls {
    #![deny(clippy::undocumented_unsafe_blocks)]

    crate::plain!(super::PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    });
}

fn poll_sources(
    fds: &mut [PollFd],
    timeout: Option<u64>,
    mut remaining: Option<&mut u64>,
) -> SysResult<i64> {
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
            return Ok(count);
        }
        if let Err(error) = state.ensure_active() {
            return Err(Errno::new(c_int::from(error.into_posix())));
        }
        let me = current_task();
        if deadline.is_none()
            && let Some(timeout) = timeout
        {
            let now = with_context_raw(|context| context.now(ClockKind::Monotonic))
                .unwrap_or_else(|_| fatal("readiness wait clock read failed"));
            deadline = Some(now.saturating_add(timeout));
        }
        if deadline.is_some_and(|deadline| {
            with_context_raw(|context| context.now(ClockKind::Monotonic))
                .unwrap_or_else(|_| fatal("readiness wait clock read failed"))
                >= deadline
        }) {
            return Ok(0);
        }
        let wait = register_readiness_waiters(&mut state, me, &watched);
        let locs = wait.locs.clone();
        let step = match deadline {
            Some(deadline) => state.block_timed(me, "poll", wait, ClockKind::Monotonic, deadline),
            None => state.block(me, "poll", wait),
        };
        match step {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => {
                unregister_waiters(&mut state, me, &locs);
                return Err(Errno::new(c_int::from(error.into_posix())));
            }
        }
        {
            let mut state = lock_state();
            unregister_waiters(&mut state, me, &locs);
            state.timed_out.remove(&me);
        }
        update_remaining(deadline, &mut remaining);
        if resume() == Resumed::Eintr {
            return Err(Errno::new(EINTR as c_int));
        }
    }
}

#[unsafe(no_mangle)]
/// Raw-errno ABI shared by poll/ppoll on both doors. Negative timeout means
/// indefinite; nonnegative timeout is relative nanoseconds.
/// # Safety
/// `fds` names `count` pollfd records; non-null mask names eight bytes.
pub unsafe extern "C" fn patina_poll(
    fds: *mut PollFd,
    count: usize,
    timeout: i64,
    mask: *const u64,
    remaining: *mut u64,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // SAFETY: this entry forwards its documented guest-buffer contract.
    crate::abi::raw(unsafe { poll_core(fds, count, timeout, mask, remaining) })
}

/// Poll the guest's array and optional signal mask, returning a typed result.
///
/// # Safety
/// `fds` names `count` guest pollfd records; non-null `mask` and `remaining`
/// name eight readable and writable guest bytes respectively.
pub(crate) unsafe fn poll_core(
    fds: *mut PollFd,
    count: usize,
    timeout: i64,
    mask: *const u64,
    remaining: *mut u64,
) -> SysResult<i64> {
    // `ppoll`: the signal mask is copied in before `do_sys_poll` judges the
    // count against the limit, then reads the array whole; every `revents`
    // is copied back out once the wait ends, whatever it answered.
    let mask = temporary_mask(mask)?;
    if count > crate::fd_limit() {
        return Err(Errno::new(EINVAL));
    }
    let mut local = crate::uaccess::read_vec::<PollFd>(fds as usize, count).map_err(Errno::new)?;
    let result = with_mask(mask, || {
        // SAFETY: the core contract makes `remaining` null or writable for one u64.
        let remaining = unsafe { remaining.as_mut() };
        poll_sources(
            &mut local,
            (timeout >= 0).then_some(timeout as u64),
            remaining,
        )
    });
    match crate::uaccess::write_slice(fds as usize, &local) {
        Ok(()) => result,
        Err(errno) => Err(Errno::new(errno)),
    }
}

/// Wait on epoll under an optional temporary signal mask.
///
/// # Safety
/// `events` names `capacity` writable guest records and non-null `mask` names
/// eight readable guest bytes.
pub(crate) unsafe fn epoll_wait_masked_core(
    ep: i32,
    events: *mut c_void,
    capacity: i32,
    timeout: i32,
    mask: *const u64,
) -> SysResult<i64> {
    // SAFETY: the contract above supplies both guest buffers to their uaccess readers.
    unsafe {
        with_temporary_mask(mask, || {
            // SAFETY: `events` and its capacity satisfy the epoll wait core contract.
            epoll::wait_core(ep, events, capacity, timeout).map(i64::from)
        })
    }
}

#[unsafe(no_mangle)]
/// select/pselect use native-word fd sets. Timeout is relative nanoseconds;
/// `remaining` lets each door write its timeval/timespec by its ABI rules.
/// The sets are copied in and out whole (`EFAULT` for one that cannot be),
/// as `core_sys_select` copies them.
/// # Safety
/// An optional mask names eight bytes; optional remaining names a u64.
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
    // SAFETY: this entry forwards its documented guest-buffer contract.
    crate::abi::raw(unsafe { select_core(nfds, read, write, except, timeout, mask, remaining) })
}

/// Run select/pselect over native-word guest fd sets.
///
/// # Safety
/// Optional `mask` names eight readable guest bytes; optional `remaining`
/// names one writable guest u64. Each non-null fd set follows the syscall ABI.
pub(crate) unsafe fn select_core(
    nfds: i32,
    read: *mut u64,
    write: *mut u64,
    except: *mut u64,
    timeout: i64,
    mask: *const u64,
    remaining: *mut u64,
) -> SysResult<i64> {
    // `do_pselect`: the signal mask is copied in before `core_sys_select`
    // judges the count and reads the sets.
    let mask = temporary_mask(mask)?;
    if nfds < 0 {
        return Err(Errno::new(EINVAL));
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
            return Err(Errno::new(errno));
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
                return Err(Errno::new(crate::EBADF));
            }
            fds.push(PollFd {
                fd,
                events,
                revents: 0,
            });
        }
    }
    with_mask(mask, || {
        // SAFETY: the core contract makes `remaining` null or writable for one u64.
        let remaining = unsafe { remaining.as_mut() };
        poll_sources(
            &mut fds,
            (timeout >= 0).then_some(timeout as u64),
            remaining,
        )
    })?;
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
        if !set.is_null()
            && let Err(errno) = crate::uaccess::write_slice(set as usize, bits)
        {
            return Err(Errno::new(errno));
        }
    }
    Ok(count)
}

/// Select using libc's timeval input and output behavior.
///
/// # Safety
/// As [`select_core`], with nonzero `timeval` naming the caller's timeval.
pub(crate) unsafe fn select_timeval_core(
    nfds: i32,
    read: *mut u64,
    write: *mut u64,
    except: *mut u64,
    timeval: usize,
) -> SysResult<i64> {
    const USEC: i64 = 1_000_000;
    let nanos = if timeval == 0 {
        -1
    } else {
        let [sec, usec]: [i64; 2] = crate::uaccess::read(timeval).map_err(Errno::new)?;
        let sec = sec.saturating_add(usec / USEC);
        let nsec = (usec % USEC) * 1000;
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return Err(Errno::new(EINVAL));
        }
        sec.saturating_mul(1_000_000_000).saturating_add(nsec)
    };
    let mut remaining = nanos.max(0) as u64;
    // SAFETY: all guest sets retain the caller contract; `remaining` is local.
    let result = unsafe {
        select_core(
            nfds,
            read,
            write,
            except,
            nanos,
            std::ptr::null(),
            &mut remaining,
        )
    };
    if timeval != 0 && (result.is_ok() || result == Err(Errno::new(EINTR as c_int))) {
        let left = [
            (remaining / 1_000_000_000) as i64,
            ((remaining % 1_000_000_000) / 1000) as i64,
        ];
        // `poll_select_finish`: a timeval that cannot be written back
        // leaves the result as it is.
        let _ = crate::uaccess::write(timeval, &left);
    }
    result
}

#[cfg(test)]
mod tests;
