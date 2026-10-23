//! Darwin kqueue readiness model.
#![deny(clippy::undocumented_unsafe_blocks)]

use std::collections::{BTreeMap, VecDeque};
use std::ffi::c_int;
#[cfg(patina_posix_exports)]
use std::ffi::c_void;

#[cfg(patina_posix_exports)]
use crate::abi::{SysResult, failed};
#[cfg(patina_posix_exports)]
use patina_dst_abi::ClockKind;

use super::{FdKind, TaskId, ThreadRuntime, WaitQueue, fatal, lock_state, wake_all};
// The gather path: only the guest archive's `kqueue`/`kevent` doors reach it.
#[cfg(patina_posix_exports)]
use super::{
    O_READ, O_WRITE, PatinaKevent, ReadyDir, Step, WaiterLoc, Watched, current_task, fd_poll,
    register_readiness_waiters, sched_point, switch_and_park, unregister_waiters,
};
#[cfg(patina_posix_exports)]
use crate::thread::net::abi::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP};
#[cfg(patina_posix_exports)]
use crate::thread::pipe::PIPE_BUF;

// macOS <sys/event.h> filter identifiers (the reactor is macOS-only).
pub(super) const EVFILT_READ: i16 = -1;
pub(super) const EVFILT_WRITE: i16 = -2;
pub(super) const EVFILT_TIMER: i16 = -7;
pub(super) const EVFILT_USER: i16 = -10;

// <sys/event.h> flags (the u16 `flags` field). EV_RECEIPT/EV_ERROR are
// handled entirely in the C marshalling layer.
const EV_ADD: u16 = 0x0001;
const EV_DELETE: u16 = 0x0002;
const EV_ENABLE: u16 = 0x0004;
const EV_DISABLE: u16 = 0x0008;
const EV_ONESHOT: u16 = 0x0010;
const EV_CLEAR: u16 = 0x0020;
#[cfg(patina_posix_exports)]
pub(super) const EV_EOF: u16 = 0x8000;

// EVFILT_USER / EVFILT_TIMER fflags.
const NOTE_TRIGGER: u32 = 0x0100_0000;
const NOTE_SECONDS: u32 = 0x0000_0001;
const NOTE_USECONDS: u32 = 0x0000_0002;
const NOTE_NSECONDS: u32 = 0x0000_0004;
const NOTE_ABSOLUTE: u32 = 0x0000_0008;

// Gather blocking modes handed down from the C `timeout` argument.
#[cfg(patina_posix_exports)]
const MODE_POLL: c_int = 0; // zero timespec: non-blocking poll
#[cfg(patina_posix_exports)]
const MODE_FOREVER: c_int = 1; // NULL timeout: block until ready
#[cfg(patina_posix_exports)]
const MODE_TIMEOUT: c_int = 2; // non-zero timespec: relative deadline

/// One registered `(ident, filter)` knote.
pub(super) struct KFilterState {
    udata: usize,
    enabled: bool,
    oneshot: bool,
    /// EVFILT_USER: pending NOTE_TRIGGER, cleared on delivery (edge).
    user_triggered: bool,
    /// EVFILT_TIMER: next fire time in absolute virtual nanoseconds.
    timer_deadline: u64,
    /// EVFILT_TIMER: repeat interval in nanoseconds; 0 = one-shot.
    timer_interval: u64,
    /// EVFILT_READ/WRITE: registered with EV_CLEAR.
    clear: bool,
    /// EVFILT_READ/WRITE delivery latch: the direction's arrival sequence
    /// when readiness was last delivered, `None` once a scan saw it not
    /// ready. Every knote fires again on readiness returning after a drop;
    /// an EV_CLEAR knote also fires on a new arrival (the kernel activates
    /// a knote on every append, whether or not the reader drained it in
    /// between). Other modes keep the latch (not the kernel's level or
    /// EV_DISPATCH semantics).
    delivered: Option<u64>,
}

/// A registered knote sorts by `(ident, filter)`, giving deterministic
/// gather order straight from the `BTreeMap`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FilterKey {
    ident: u64,
    filter: i16,
}

/// A virtual kqueue: its registered knotes plus the tasks parked in
/// `kevent` on it, woken by an EVFILT_USER NOTE_TRIGGER or a registration
/// from any thread.
#[derive(Default)]
struct Kqueue {
    filters: BTreeMap<FilterKey, KFilterState>,
    waiters: WaitQueue<VecDeque<TaskId>>,
}

/// A kqueue registry. The descriptor table refcounts the description
/// (one per `kqueue()`, shared by every `dup`/`F_DUPFD` of it) and frees
/// the registry through [`kqueue_close`] when the last number closes.
pub(super) struct KqueueSlot {
    kq: Kqueue,
}

/// Resolve a guest number to its kqueue registry id, or `None` if it is
/// not a live kqueue descriptor.
fn kq_id(_state: &ThreadRuntime, fd: c_int) -> Option<u64> {
    match super::super::fd_table().lock().resolve(fd) {
        Some(resolved) if resolved.kind == FdKind::Kqueue => Some(resolved.handle),
        _ => None,
    }
}

fn fatal_filter(filter: i16, fd: c_int, direction: &str) -> ! {
    fatal(&format!(
        "kevent EVFILT_{direction} registered on non-virtual descriptor {fd} \
         (filter {filter}): readiness for real host descriptors is not modeled; \
         failing closed"
    ));
}

#[cfg(patina_posix_exports)]
pub(crate) fn create() -> SysResult<c_int> {
    let fd = crate::at_free_numbers(|| {
        let mut state = lock_state();
        state
            .ensure_active()
            .map_err(|error| c_int::from(error.into_posix()))?;
        let id = state.net.next_kq;
        state.net.next_kq = state.net.next_kq.wrapping_add(1);
        state.net.kqueues.insert(
            id,
            KqueueSlot {
                kq: Kqueue::default(),
            },
        );
        // A kqueue descriptor is close-on-exec from birth (xnu sets
        // FD_CLOEXEC on it) and reports O_RDWR.
        super::super::install_fd(FdKind::Kqueue, id, O_READ | O_WRITE, true).inspect_err(|_| {
            state.net.kqueues.remove(&id);
        })
    })
    .map_err(failed)?;
    super::super::set_errno(0);
    Ok(fd)
}

/// Free a kqueue registry whose description's last reference went,
/// waking any task parked in `kevent` on it.
pub(crate) fn kqueue_close(handle: u64) {
    let mut state = lock_state();
    let Some(mut slot) = state.net.kqueues.remove(&handle) else {
        return;
    };
    let waiters: Vec<TaskId> = slot.kq.waiters.take().into_iter().collect();
    drop(state);
    wake_all(waiters);
}

/// BSD drops the knotes registered on a NUMBER when that number closes
/// (`knote_fdclose`), whatever other references the file keeps — so a
/// reused number can never observe a stale knote.
pub(crate) fn kqueue_forget_number(fd: c_int) {
    let ident = fd as u64;
    let mut state = lock_state();
    for slot in state.net.kqueues.values_mut() {
        slot.kq.filters.retain(|key, _| {
            !(key.ident == ident && matches!(key.filter, EVFILT_READ | EVFILT_WRITE))
        });
    }
}

#[unsafe(no_mangle)]
/// Apply one changelist entry to a kqueue. Returns 0 on success or a
/// positive errno the C layer places in an EV_ERROR receipt. Registry
/// mutation only — no scheduling point, no trace event — except that an
/// EVFILT_USER NOTE_TRIGGER, an `EV_ADD` and an `EV_ENABLE` wake the kq's
/// parked `kevent` callers (like a condvar signal), which rescan: a knote
/// attached ready activates at once (`knote_attach`), and a park watches
/// the knotes enabled when it began, so one enabled since, or a timer
/// added since, must bound it from then on.
///
/// # Safety
/// C ABI entry point; `ident` for EVFILT_READ/WRITE is a descriptor.
pub extern "C" fn patina_kqueue_apply(
    kq_fd: c_int,
    ident: u64,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: i64,
    udata: usize,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let me_wake: Vec<TaskId>;
    {
        let mut state = lock_state();
        let Some(id) = kq_id(&state, kq_fd) else {
            return super::super::EBADF;
        };
        // Fail closed LOUDLY on filters the reactor does not model: a
        // silent ENOSYS/EINVAL that tokio swallowed would be an invisible
        // escape (a real host kqueue would then service them off-model).
        if !matches!(
            filter,
            EVFILT_READ | EVFILT_WRITE | EVFILT_USER | EVFILT_TIMER
        ) {
            fatal(&format!(
                "kevent filter {filter} is not modeled (only EVFILT_READ/WRITE/USER/TIMER \
                 are supported); failing closed"
            ));
        }
        let key = FilterKey { ident, filter };

        if flags & EV_DELETE != 0 {
            // Removal validates nothing about the fd: the descriptor may
            // already be closed (mio deregisters around close).
            if state
                .net
                .kqueues
                .get_mut(&id)
                .expect("kqueue was checked")
                .kq
                .filters
                .remove(&key)
                .is_none()
            {
                return super::super::ENOENT;
            }
            return 0;
        }

        if flags & EV_ADD != 0 {
            // Registration-time fd validation: EVFILT_READ/WRITE readiness
            // is defined only over virtual pipe and socket
            // descriptors. A real file, stdio, or otherwise unknown
            // descriptor fails closed loudly here.
            if matches!(filter, EVFILT_READ | EVFILT_WRITE) {
                let fd = c_int::try_from(ident).unwrap_or(-1);
                let known = matches!(
                    super::super::fd_table().lock().kind(fd),
                    Some(FdKind::Pipe | FdKind::Socket)
                );
                if !known {
                    let direction = if filter == EVFILT_READ {
                        "READ"
                    } else {
                        "WRITE"
                    };
                    fatal_filter(filter, fd, direction);
                }
            }
            let now = match crate::with_bookkeeping(|c| c.monotonic_now_unrecorded()) {
                Ok(now) => now,
                Err(errno) => return errno,
            };
            let (timer_deadline, timer_interval) = if filter == EVFILT_TIMER {
                let period = timer_nanos(data, fflags);
                let deadline = if fflags & NOTE_ABSOLUTE != 0 {
                    data.max(0) as u64
                } else {
                    now.saturating_add(period)
                };
                let interval = if flags & EV_ONESHOT != 0 { 0 } else { period };
                (deadline, interval)
            } else {
                (0, 0)
            };
            let kq = &mut state
                .net
                .kqueues
                .get_mut(&id)
                .expect("kqueue was checked")
                .kq;
            let entry = kq.filters.entry(key).or_insert(KFilterState {
                udata,
                enabled: true,
                oneshot: false,
                user_triggered: false,
                timer_deadline,
                timer_interval,
                clear: flags & EV_CLEAR != 0,
                delivered: None,
            });
            entry.clear = flags & EV_CLEAR != 0;
            entry.udata = udata;
            entry.enabled = flags & EV_DISABLE == 0;
            entry.oneshot = flags & EV_ONESHOT != 0;
            if filter == EVFILT_TIMER {
                // Re-adding a timer restarts it from now.
                entry.timer_deadline = timer_deadline;
                entry.timer_interval = timer_interval;
                entry.delivered = None;
            }
        } else if flags & (EV_ENABLE | EV_DISABLE) != 0 {
            let Some(entry) = state
                .net
                .kqueues
                .get_mut(&id)
                .expect("kqueue was checked")
                .kq
                .filters
                .get_mut(&key)
            else {
                return super::super::ENOENT;
            };
            if flags & EV_ENABLE != 0 {
                entry.enabled = true;
            }
            if flags & EV_DISABLE != 0 {
                entry.enabled = false;
            }
        }

        // EVFILT_USER NOTE_TRIGGER: latch the trigger. mio's `Waker::wake`
        // sends exactly this (EV_ADD | NOTE_TRIGGER) from another thread.
        let triggered = filter == EVFILT_USER && fflags & NOTE_TRIGGER != 0;
        let kq = &mut state
            .net
            .kqueues
            .get_mut(&id)
            .expect("kqueue was checked")
            .kq;
        if triggered && let Some(entry) = kq.filters.get_mut(&key) {
            entry.user_triggered = true;
        }
        // Wake every task parked in `kevent` on this kq to rescan.
        me_wake = if triggered || flags & (EV_ADD | EV_ENABLE) != 0 {
            kq.waiters.drain().collect()
        } else {
            Vec::new()
        };
    }
    wake_all(me_wake);
    0
}

/// EVFILT_TIMER period in nanoseconds from `data` and the unit fflags.
/// The macOS default (no unit flag) is milliseconds.
fn timer_nanos(data: i64, fflags: u32) -> u64 {
    let magnitude = data.max(0) as u64;
    if fflags & NOTE_NSECONDS != 0 {
        magnitude
    } else if fflags & NOTE_USECONDS != 0 {
        magnitude.saturating_mul(1_000)
    } else if fflags & NOTE_SECONDS != 0 {
        magnitude.saturating_mul(1_000_000_000)
    } else {
        magnitude.saturating_mul(1_000_000)
    }
}

/// A knote ready to deliver, plus the registry edits its delivery entails.
#[cfg(patina_posix_exports)]
struct ReadyEvent {
    event: PatinaKevent,
    key: FilterKey,
    /// Latch EV_CLEAR edge state after delivering a READ/WRITE event: the
    /// arrival sequence it was delivered at.
    set_delivered: Option<u64>,
    /// Clear the EVFILT_USER trigger after delivery.
    clear_user: bool,
    /// One-shot: remove the knote after delivery.
    remove: bool,
    /// EVFILT_TIMER re-arm to this absolute deadline (0 = no re-arm).
    rearm_timer: u64,
}

/// Scan the kq's enabled knotes at virtual time `now`, collecting the
/// events ready to deliver (in `(ident, filter)` order) and the re-arm
/// edits for knotes observed not-ready. `earliest_timer` returns the
/// soonest enabled timer deadline so a blocking gather can bound its park.
#[cfg(patina_posix_exports)]
fn scan(
    state: &ThreadRuntime,
    id: u64,
    now: u64,
) -> (Vec<ReadyEvent>, Vec<FilterKey>, Option<u64>) {
    let kq = &state.net.kqueues.get(&id).expect("kqueue exists").kq;
    let mut ready = Vec::new();
    let mut rearm_not_ready = Vec::new();
    let mut earliest_timer = None;
    for (key, st) in &kq.filters {
        if !st.enabled {
            continue;
        }
        match key.filter {
            EVFILT_READ | EVFILT_WRITE => {
                let fd = c_int::try_from(key.ident).unwrap_or(-1);
                // The filters read the poll mask: a number that names
                // nothing any more is ready with EOF, so the reactor
                // wakes and the next operation surfaces the error.
                let (mask, (reads, writes)) =
                    fd_poll(state, fd, None).unwrap_or((POLLERR | POLLHUP, (0, 0)));
                let (ready_now, eof, arrivals) = if key.filter == EVFILT_READ {
                    (
                        mask & (POLLIN | POLLRDHUP | POLLHUP | POLLERR) != 0,
                        mask & (POLLRDHUP | POLLHUP) != 0,
                        reads,
                    )
                } else {
                    // `filt_pipewrite_common`: a pipe is writable once a
                    // whole `PIPE_BUF` fits, not at its first free byte.
                    let room = mask & (POLLHUP | POLLERR) != 0
                        || !st.clear
                        || pipe_room(state, fd).is_none_or(|room| room >= PIPE_BUF);
                    (
                        mask & (POLLOUT | POLLHUP | POLLERR) != 0 && room,
                        mask & (POLLHUP | POLLERR) != 0,
                        writes,
                    )
                };
                let fires = match st.delivered {
                    None => true,
                    Some(seen) => st.clear && seen != arrivals,
                };
                if ready_now && fires {
                    let mut flags = 0u16;
                    if eof {
                        flags |= EV_EOF;
                    }
                    ready.push(ReadyEvent {
                        event: PatinaKevent {
                            ident: key.ident,
                            filter: key.filter,
                            flags,
                            fflags: 0,
                            data: 0,
                            udata: st.udata,
                        },
                        key: *key,
                        set_delivered: Some(arrivals),
                        clear_user: false,
                        remove: st.oneshot,
                        rearm_timer: 0,
                    });
                } else if !ready_now && st.delivered.is_some() {
                    // Readiness dropped: re-arm the latch so the next
                    // rising edge fires again.
                    rearm_not_ready.push(*key);
                }
            }
            EVFILT_USER => {
                if st.user_triggered {
                    ready.push(ReadyEvent {
                        event: PatinaKevent {
                            ident: key.ident,
                            filter: key.filter,
                            flags: 0,
                            fflags: 0,
                            data: 0,
                            udata: st.udata,
                        },
                        key: *key,
                        set_delivered: None,
                        clear_user: true,
                        remove: st.oneshot,
                        rearm_timer: 0,
                    });
                }
            }
            EVFILT_TIMER => {
                if now >= st.timer_deadline {
                    let rearm = if st.oneshot || st.timer_interval == 0 {
                        0
                    } else {
                        // Advance past `now` so a long-overdue periodic
                        // timer fires once and re-arms to the future.
                        let mut next = st.timer_deadline.saturating_add(st.timer_interval);
                        while next <= now {
                            next = next.saturating_add(st.timer_interval);
                        }
                        next
                    };
                    ready.push(ReadyEvent {
                        event: PatinaKevent {
                            ident: key.ident,
                            filter: key.filter,
                            flags: 0,
                            fflags: 0,
                            data: 1,
                            udata: st.udata,
                        },
                        key: *key,
                        set_delivered: None,
                        clear_user: false,
                        remove: st.oneshot || st.timer_interval == 0,
                        rearm_timer: rearm,
                    });
                } else {
                    earliest_timer = Some(
                        earliest_timer.map_or(st.timer_deadline, |e: u64| e.min(st.timer_deadline)),
                    );
                }
            }
            _ => {}
        }
    }
    (ready, rearm_not_ready, earliest_timer)
}

/// The free space of the pipe `fd` names, `None` for a number that names
/// no pipe's write end.
#[cfg(patina_posix_exports)]
fn pipe_room(state: &ThreadRuntime, fd: c_int) -> Option<usize> {
    let resolved = super::super::fd_table().lock().resolve(fd)?;
    if resolved.kind != FdKind::Pipe {
        return None;
    }
    let end = state.net.pipe_ends.get(&(resolved.handle as c_int))?;
    let channel = state.net.pipe_channels.get(&end.write_channel?)?;
    Some(channel.capacity.saturating_sub(channel.buffer.len()))
}

/// The enabled EVFILT_READ/WRITE knotes as the reactor-neutral sources the
/// shared fan-in primitive parks on. A knote names its NUMBER: closing the
/// number drops it ([`kqueue_forget_number`]), so what the number names now
/// is what it watches.
#[cfg(patina_posix_exports)]
fn watched_sources(state: &ThreadRuntime, id: u64) -> Vec<Watched> {
    let kq = &state.net.kqueues.get(&id).expect("kqueue exists").kq;
    kq.filters
        .iter()
        .filter(|(_, st)| st.enabled)
        .filter_map(|(key, _)| {
            let dir = match key.filter {
                EVFILT_READ => ReadyDir::Read,
                EVFILT_WRITE => ReadyDir::Write,
                _ => return None,
            };
            Some(Watched {
                dir,
                fd: c_int::try_from(key.ident).unwrap_or(-1),
                desc: None,
            })
        })
        .collect()
}

/// Apply the registry edits for the events actually delivered this gather:
/// latch EV_CLEAR edges, clear EVFILT_USER triggers, remove one-shots, and
/// re-arm periodic timers.
#[cfg(patina_posix_exports)]
fn commit_delivered(state: &mut ThreadRuntime, id: u64, delivered: &[ReadyEvent]) {
    let kq = &mut state.net.kqueues.get_mut(&id).expect("kqueue exists").kq;
    for event in delivered {
        if event.remove {
            kq.filters.remove(&event.key);
            continue;
        }
        if let Some(st) = kq.filters.get_mut(&event.key) {
            if event.set_delivered.is_some() {
                st.delivered = event.set_delivered;
            }
            if event.clear_user {
                st.user_triggered = false;
            }
            if event.rearm_timer != 0 {
                st.timer_deadline = event.rearm_timer;
            }
        }
    }
}

/// Apply the readiness "not-ready" re-arms to the EV_CLEAR edge latches.
#[cfg(patina_posix_exports)]
fn commit_rearm(state: &mut ThreadRuntime, id: u64, keys: &[FilterKey]) {
    let kq = &mut state.net.kqueues.get_mut(&id).expect("kqueue exists").kq;
    for key in keys {
        if let Some(st) = kq.filters.get_mut(key) {
            st.delivered = None;
        }
    }
}

/// Gather up to `nevents` ready events and park using the virtual clock.
///
/// # Safety
/// `out` must be writable for `nevents` [`PatinaKevent`]s.
#[cfg(patina_posix_exports)]
pub(crate) unsafe fn gather_core(
    kq_fd: c_int,
    out: *mut c_void,
    nevents: c_int,
    mode: c_int,
    timeout_nanos: u64,
) -> SysResult<c_int> {
    if let Err(errno) = sched_point() {
        return Err(failed(errno));
    }
    let capacity = nevents.max(0) as usize;
    let me = current_task();
    // Absolute deadline for a MODE_TIMEOUT gather, fixed on the first park.
    let mut timeout_deadline: Option<u64> = None;
    loop {
        let mut state = lock_state();
        let Some(id) = kq_id(&state, kq_fd) else {
            return Err(failed(super::super::EBADF));
        };
        let now = match crate::with_bookkeeping(|c| c.monotonic_now_unrecorded()) {
            Ok(now) => now,
            Err(errno) => return Err(failed(errno)),
        };
        let (ready, rearm_not_ready, earliest_timer) = scan(&state, id, now);
        commit_rearm(&mut state, id, &rearm_not_ready);

        if !ready.is_empty() || capacity == 0 {
            let count = ready.len().min(capacity);
            let delivered = &ready[..count];
            if !out.is_null() {
                // SAFETY: the gather core contract supplies writable output storage for `count`.
                let slots =
                    unsafe { std::slice::from_raw_parts_mut(out.cast::<PatinaKevent>(), count) };
                for (slot, event) in slots.iter_mut().zip(delivered) {
                    *slot = event.event;
                }
            }
            commit_delivered(&mut state, id, delivered);
            return Ok(c_int::try_from(count).unwrap_or(c_int::MAX));
        }

        if mode == MODE_POLL {
            return Ok(0);
        }

        // A bounded gather whose deadline has passed with nothing ready
        // returns zero events — never re-parks on an elapsed deadline
        // (which would live-lock the deadlock rescue). The absolute
        // deadline is fixed on entry so it does not drift across scans.
        if mode == MODE_TIMEOUT {
            let deadline = *timeout_deadline.get_or_insert(now.saturating_add(timeout_nanos));
            if now >= deadline {
                return Ok(0);
            }
        }

        // Nothing ready: park with multi-fd fan-in, bounded by the earlier
        // of the gather timeout and the soonest EVFILT_TIMER deadline.
        let park_deadline = if mode == MODE_TIMEOUT {
            let deadline = timeout_deadline.expect("timeout deadline fixed above");
            Some(match earliest_timer {
                Some(timer) => deadline.min(timer),
                None => deadline,
            })
        } else {
            // MODE_FOREVER (MODE_POLL returned above): the park is bounded
            // only by the soonest EVFILT_TIMER deadline, if any.
            debug_assert!(mode == MODE_FOREVER, "unexpected kevent gather mode {mode}");
            earliest_timer
        };
        // Fan-in on the reactor-neutral readiness sources (shared core),
        // until the next delivery to a watched socket too, plus the kq's
        // own waiter list, where an EVFILT_USER trigger and a registration
        // change wake it.
        let watched = watched_sources(&state, id);
        let (mut wait, park_deadline) =
            register_readiness_waiters(&mut state, me, &watched).bounded(park_deadline);
        let kq = &mut state.net.kqueues.get_mut(&id).expect("kqueue exists").kq;
        wait.enqueue(&mut kq.waiters, me, WaiterLoc::KqueueWait(id));
        let locs = wait.locs.clone();
        let step = match park_deadline {
            Some(deadline) => state.block_timed(me, "kevent", wait, ClockKind::Monotonic, deadline),
            None => state.block(me, "kevent", wait),
        };
        match step {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => {
                unregister_waiters(&mut state, me, &locs);
                return Err(failed(c_int::from(error.into_posix())));
            }
        }
        let mut state = lock_state();
        unregister_waiters(&mut state, me, &locs);
        state.timed_out.remove(&me);
        drop(state);
    }
}

/// Unlink `me` from a kqueue's waiter list (the `WaiterLoc::KqueueWait`
/// registration).
#[cfg(patina_posix_exports)]
pub(in crate::thread) fn unwait(state: &mut ThreadRuntime, id: u64, me: TaskId) {
    if let Some(slot) = state.net.kqueues.get_mut(&id)
        && let Some(index) = slot.kq.waiters.iter().position(|task| *task == me)
    {
        slot.kq.waiters.remove(index);
    }
}
