//! Linux eventfd state and entry points.

use super::*;

// ------------------------------------------------------------------
// eventfd (Linux). A deterministic in-process model of the kernel's 64-bit
// event counter — mio's `Waker` vehicle on Linux, the EVFILT_USER analogue.
// The counter is keyed by class handle; the descriptor table maps the guest
// number onto it and the universal read/write/close route here by kind.
// Like the pipe channels, the counter is
// deterministic given the recorded schedule and carries NO trace events;
// only the scheduler parks/wakes are recorded.

/// A virtual eventfd: the counter, its creation-flag semantics, and the
/// tasks parked on readability (blocking reads of a zero counter, and
/// `epoll_wait` callers watching it through the shared fan-in core).
#[cfg(target_os = "linux")]
pub(crate) struct EventFd {
    pub(crate) value: u64,
    /// EFD_SEMAPHORE: reads return 1 and decrement, instead of
    /// return-and-reset.
    semaphore: bool,
    /// Arrival sequence, bumped once per value-adding write so the epoll
    /// EPOLLET latch re-fires per wake even when the counter never drains —
    /// mio's `Waker` writes without reading back, relying on the kernel's
    /// per-arrival edge semantics.
    pub(crate) write_events: u64,
    pub(crate) read_waiters: VecDeque<TaskId>,
}

#[unsafe(no_mangle)]
/// eventfd(2) / eventfd2. Syscall-shaped (`eventfd2(initval, flags)`) so a
/// future syscall-user-dispatch SIGSYS dispatcher can call it with raw
/// register arguments; the C interposer is thin marshaling over this.
/// EFD_CLOEXEC is accepted as a no-op (no exec under the runtime); unknown
/// flags are `EINVAL`. Activates the thread subsystem so a later blocking
/// read or epoll park can reach the baton.
#[cfg(target_os = "linux")]
pub extern "C" fn patina_eventfd(initval: u32, flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    const EFD_SEMAPHORE: c_int = 0o1;
    const EFD_CLOEXEC: c_int = 0o2000000;
    const EFD_NONBLOCK: c_int = 0o4000;
    if flags & !(EFD_SEMAPHORE | EFD_CLOEXEC | EFD_NONBLOCK) != 0 {
        return super::fail(EINVAL);
    }
    let mut state = lock_state();
    if let Err(error) = state.ensure_active() {
        return super::fail(c_int::from(error.into_posix()));
    }
    let handle = next_handle(&mut state);
    state.net.eventfds.insert(
        handle,
        EventFd {
            value: u64::from(initval),
            semaphore: flags & EFD_SEMAPHORE != 0,
            write_events: 0,
            read_waiters: VecDeque::new(),
        },
    );
    let nonblock = if flags & EFD_NONBLOCK != 0 {
        O_NONBLOCK
    } else {
        0
    };
    match super::install_fd(
        FdKind::EventFd,
        handle as u64,
        O_READ | O_WRITE | nonblock,
        flags & EFD_CLOEXEC != 0,
    ) {
        Ok(fd) => {
            super::set_errno(0);
            fd
        }
        Err(errno) => {
            state.net.eventfds.remove(&handle);
            super::fail(errno)
        }
    }
}

/// Read a virtual eventfd: 8 bytes, returns-and-resets the counter (or
/// returns 1 and decrements under EFD_SEMAPHORE). A zero counter is
/// `EWOULDBLOCK` under `O_NONBLOCK`, otherwise the caller parks until a
/// write arrives.
///
/// # Safety
/// `buf` must be writable for `len` bytes.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn eventfd_read(
    handle: u64,
    nonblocking: bool,
    buf: *mut c_void,
    len: usize,
) -> isize {
    let fd = handle as c_int;
    if let Err(errno) = sched_point() {
        return super::fail(errno) as isize;
    }
    if buf.is_null() || len < 8 {
        return super::fail(EINVAL) as isize;
    }
    let me = current_task();
    loop {
        let mut state = lock_state();
        let Some(efd) = state.net.eventfds.get_mut(&fd) else {
            return super::fail(super::EBADF) as isize;
        };
        if efd.value != 0 {
            let taken = if efd.semaphore {
                efd.value -= 1;
                1u64
            } else {
                std::mem::replace(&mut efd.value, 0)
            };
            // SAFETY: `buf` is writable for >= 8 bytes per this function's
            // contract (checked above).
            unsafe {
                buf.cast::<u8>()
                    .copy_from_nonoverlapping(taken.to_ne_bytes().as_ptr(), 8)
            };
            return 8;
        }
        if nonblocking {
            return super::fail(EWOULDBLOCK) as isize;
        }
        efd.read_waiters.push_back(me);
        let step = state.block(
            me,
            "eventfd-read",
            Wait::new(BlockClass::Io, vec![WaiterLoc::EventFdRecv(fd)]),
        );
        match step {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => return super::fail(c_int::from(error.into_posix())) as isize,
        }
        lock_state().timed_out.remove(&me);
        #[cfg(target_os = "linux")]
        if signals::resume() == signals::Resumed::Eintr {
            return super::fail(super::EINTR) as isize;
        }
    }
}

/// Write a virtual eventfd: 8 bytes adding to the counter, waking parked
/// readers and epoll watchers. The kernel parks a writer whose addition
/// would exceed `u64::MAX - 1`; no supported caller writes near the bound
/// (mio's `Waker` adds 1 per wake), so that fails closed loudly instead of
/// modeling a blocked-writer queue.
///
/// # Safety
/// `buf` must be readable for `len` bytes.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn eventfd_write(handle: u64, buf: *const c_void, len: usize) -> isize {
    let fd = handle as c_int;
    if let Err(errno) = sched_point() {
        return super::fail(errno) as isize;
    }
    if buf.is_null() || len < 8 {
        return super::fail(EINVAL) as isize;
    }
    let mut add = [0u8; 8];
    // SAFETY: `buf` is readable for >= 8 bytes per this function's contract.
    unsafe {
        add.as_mut_ptr()
            .copy_from_nonoverlapping(buf.cast::<u8>(), 8)
    };
    let add = u64::from_ne_bytes(add);
    if add == u64::MAX {
        return super::fail(EINVAL) as isize;
    }
    let mut state = lock_state();
    let Some(efd) = state.net.eventfds.get_mut(&fd) else {
        return super::fail(super::EBADF) as isize;
    };
    let Some(sum) = efd.value.checked_add(add).filter(|sum| *sum < u64::MAX) else {
        fatal(&format!(
            "eventfd write overflows the counter ({} + {add}): blocking eventfd \
             writers are not modeled; failing closed",
            efd.value
        ));
    };
    if add == 0 {
        // Adding zero changes no readiness; the kernel reports success
        // without waking anyone.
        return 8;
    }
    efd.value = sum;
    efd.write_events = efd.write_events.wrapping_add(1);
    let waiters: Vec<TaskId> = efd.read_waiters.drain(..).collect();
    drop(state);
    wake_all(waiters);
    8
}

/// Free an eventfd whose description's last reference went, waking any
/// parked readers (they observe EBADF — loud, deterministic — rather than
/// parking forever on a dead counter).
#[cfg(target_os = "linux")]
pub(crate) fn eventfd_close(handle: u64) {
    let mut state = lock_state();
    let Some(efd) = state.net.eventfds.remove(&(handle as c_int)) else {
        return;
    };
    let waiters: Vec<TaskId> = efd.read_waiters.into_iter().collect();
    drop(state);
    wake_all(waiters);
}
