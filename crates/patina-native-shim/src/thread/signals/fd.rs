//! signalfd descriptions share the universal descriptor table; no host fd exists.
use super::*;

pub(in crate::thread) struct SignalFd {
    pub mask: u64,
    pub waiters: VecDeque<TaskId>,
    pub arrivals: u64,
}

/// # Safety
/// `mask` names an eight-byte Linux signal set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signalfd(
    fd: i32,
    mask: *const u64,
    size: usize,
    flags: i32,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if size != SIGSET_BYTES || flags & !(SFD_NONBLOCK | SFD_CLOEXEC) != 0 {
        return -i64::from(EINVAL);
    }
    if mask.is_null() {
        return -i64::from(EFAULT);
    }
    activate();
    let mask = uncatchable(unsafe { *mask });
    let mut state = lock_state();
    if fd != -1 {
        let Some(entry) = crate::fd_table().lock().resolve(fd) else {
            return -i64::from(crate::EBADF);
        };
        if entry.kind != FdKind::SignalFd {
            return -i64::from(EINVAL);
        }
        state.signals.signalfds.get_mut(&entry.handle).unwrap().mask = mask;
        let readers: std::collections::BTreeSet<_> = state.signals.signalfds[&entry.handle]
            .waiters
            .iter()
            .copied()
            .collect();
        let mut ready = Vec::new();
        for task in readers {
            // A blocked read or reactor must consult the replacement mask even
            // when no subsequent signal is generated to make it runnable.
            let watched = state
                .signals
                .signalfds
                .values()
                .filter(|fd| fd.waiters.contains(&task))
                .fold(0, |set, fd| set | fd.mask);
            let wanted = watched & state.signals.mask(task);
            if let Some(blocked) = state.signals.blocked.get_mut(&task) {
                blocked.wanted = wanted;
            }
            if state.signals.pending(task) & wanted != 0 {
                ready.push(task);
            }
        }
        drop(state);
        wake_all(ready);
        return i64::from(fd);
    }
    let handle = state.signals.next_fd;
    state.signals.next_fd += 1;
    let status = O_READ
        | if flags & SFD_NONBLOCK != 0 {
            crate::O_NONBLOCK
        } else {
            0
        };
    match crate::install_fd(FdKind::SignalFd, handle, status, flags & SFD_CLOEXEC != 0) {
        Ok(fd) => {
            state.signals.signalfds.insert(
                handle,
                SignalFd {
                    mask,
                    waiters: VecDeque::new(),
                    arrivals: 0,
                },
            );
            i64::from(fd)
        }
        Err(errno) => -i64::from(errno),
    }
}

pub(crate) fn close(handle: u64) {
    let waiters = lock_state()
        .signals
        .signalfds
        .remove(&handle)
        .map(|fd| fd.waiters.into_iter().collect())
        .unwrap_or_default();
    wake_all(waiters);
}

pub(in crate::thread) fn readable(state: &ThreadRuntime, handle: u64, task: TaskId) -> bool {
    state
        .signals
        .signalfds
        .get(&handle)
        .is_some_and(|fd| state.signals.pending(task) & fd.mask != 0)
}

fn record(info: Info, sig: u8) -> [u8; 128] {
    let mut out = [0; 128];
    out[0..4].copy_from_slice(&u32::from(sig).to_ne_bytes());
    out[8..12].copy_from_slice(&info.code().to_ne_bytes());
    out[12..16].copy_from_slice(&(info.words[2] as u32).to_ne_bytes());
    out[16..20].copy_from_slice(&((info.words[2] >> 32) as u32).to_ne_bytes());
    out[44..48].copy_from_slice(&(info.value() as i32).to_ne_bytes());
    out[48..56].copy_from_slice(&info.words[3].to_ne_bytes());
    out
}

/// # Safety
/// `buf` must be writable for `len` bytes.
pub(crate) unsafe fn read(handle: u64, nonblocking: bool, buf: *mut c_void, len: usize) -> isize {
    if len < 128 {
        return crate::fail(EINVAL) as isize;
    }
    if buf.is_null() {
        return crate::fail(EFAULT) as isize;
    }
    if let Err(errno) = sched_point() {
        return crate::fail(errno) as isize;
    }
    let me = activate();
    loop {
        let mut state = lock_state();
        let Some(fd) = state.signals.signalfds.get(&handle) else {
            return crate::fail(crate::EBADF) as isize;
        };
        let mask = fd.mask & state.signals.mask(me);
        let mut count = 0;
        while count + 128 <= len {
            let Some(instance) = state.signals.dequeue(me, mask) else {
                break;
            };
            let bytes = record(instance.info, instance.sig);
            // SAFETY: the caller's buffer has room for this complete record.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>().add(count), 128);
            }
            count += 128;
        }
        if count != 0 {
            return count as isize;
        }
        if nonblocking {
            return crate::fail(EAGAIN) as isize;
        }
        state
            .signals
            .signalfds
            .get_mut(&handle)
            .unwrap()
            .waiters
            .push_back(me);
        let step = state.block(
            me,
            "signalfd-read",
            Wait::new(
                BlockClass::SignalfdRead,
                vec![WaiterLoc::SignalFdRecv(handle)],
            )
            .signals(mask),
        );
        match step {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => return crate::fail(error.into_posix()) as isize,
        }
        if resume() == Resumed::Eintr {
            return crate::fail(EINTR) as isize;
        }
    }
}
