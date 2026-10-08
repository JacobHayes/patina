//! Linux epoll readiness model.
#![deny(clippy::undocumented_unsafe_blocks)]

use super::{BlockClass, Wait};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::{c_int, c_void};

use patina_dst_abi::ClockKind;

use super::{
    DescId, EPERM, FdKind, O_READ, O_WRITE, ReadyDir, Step, ThreadRuntime, current_task, fatal,
    lock_state, register_readiness_waiters, sched_point, switch_and_park, unregister_waiters,
    with_context_raw,
};

// <sys/epoll.h> control ops and event bits (the reactor is Linux-only).
const EPOLL_CTL_ADD: c_int = 1;
const EPOLL_CTL_DEL: c_int = 2;
const EPOLL_CTL_MOD: c_int = 3;

const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLET: u32 = 1 << 31;
/// One delivery, then the interest is disarmed until `EPOLL_CTL_MOD`
/// re-arms it (the kernel keeps only the mode bits; a MOD replaces
/// the whole mask).
const EPOLLONESHOT: u32 = 1 << 30;
/// Keep the system awake while the event is pending: it needs
/// CAP_BLOCK_SUSPEND, so the kernel drops it for the guest.
const EPOLLWAKEUP: u32 = 1 << 29;
/// Wake one of the epoll instances waiting on the source rather than
/// all: every instance sees the event here, which the flag's
/// contract ("one or more") allows.
const EPOLLEXCLUSIVE: u32 = 1 << 28;
/// EPOLL_CLOEXEC == O_CLOEXEC: FD_CLOEXEC on the new number.
const EPOLL_CLOEXEC: c_int = 0o2000000;

/// The kernel's `struct epoll_event`, written directly into the guest's
/// buffer with the kernel ABI layout: packed on x86_64 (the ABI keeps
/// the i386 12-byte layout there), natural alignment elsewhere. Pinned
/// against the platform definition by `_Static_assert`s in the C layer.
#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Clone, Copy)]
pub(crate) struct EpollEvent {
    events: u32,
    data: u64,
}

#[cfg(not(target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct KernelEpollEvent {
    events: u32,
    pad: u32,
    data: u64,
}

#[allow(dead_code)]
mod plain_impls {
    #![deny(clippy::undocumented_unsafe_blocks)]

    #[cfg(target_arch = "x86_64")]
    crate::plain!(super::EpollEvent {
        events: u32,
        data: u64
    });

    #[cfg(not(target_arch = "x86_64"))]
    crate::plain!(super::KernelEpollEvent {
        events: u32,
        pad: u32,
        data: u64,
    });
}

#[cfg(not(target_arch = "x86_64"))]
const _: () = {
    assert!(core::mem::size_of::<KernelEpollEvent>() == core::mem::size_of::<libc::epoll_event>());
    assert!(
        core::mem::offset_of!(KernelEpollEvent, events)
            == core::mem::offset_of!(libc::epoll_event, events)
    );
    assert!(
        core::mem::offset_of!(KernelEpollEvent, data)
            == core::mem::offset_of!(libc::epoll_event, u64)
    );
};

#[cfg(target_arch = "x86_64")]
fn read_event(address: usize) -> Result<(u32, u64), c_int> {
    let event = crate::uaccess::read::<EpollEvent>(address)?;
    Ok((event.events, event.data))
}

#[cfg(not(target_arch = "x86_64"))]
fn read_event(address: usize) -> Result<(u32, u64), c_int> {
    let event = crate::uaccess::read::<KernelEpollEvent>(address)?;
    Ok((event.events, event.data))
}

#[cfg(target_arch = "aarch64")]
fn write_event(address: usize, event: &EpollEvent) -> Result<(), c_int> {
    let events = event.events;
    let data = event.data;
    crate::uaccess::write(address, &events)?;
    crate::uaccess::write(
        address + std::mem::offset_of!(KernelEpollEvent, data),
        &data,
    )
}

#[cfg(not(target_arch = "aarch64"))]
fn write_event(address: usize, event: &EpollEvent) -> Result<(), c_int> {
    crate::uaccess::write(address, event)
}

/// The poll bits a read-direction wakeup carries (`EPOLLIN`, `EPOLLPRI`,
/// `EPOLLRDNORM`, `EPOLLRDBAND`, `EPOLLMSG`, `EPOLLRDHUP`), and a
/// write-direction one (`EPOLLOUT`, `EPOLLWRNORM`, `EPOLLWRBAND`).
const READ_BITS: u32 = EPOLLIN | 0x002 | 0x040 | 0x080 | 0x400 | EPOLLRDHUP;
const WRITE_BITS: u32 = EPOLLOUT | 0x100 | 0x200;
/// `EP_PRIVATE_BITS`: the mode bits, never reported.
const PRIVATE_BITS: u32 = EPOLLWAKEUP | EPOLLONESHOT | EPOLLET | EPOLLEXCLUSIVE;
/// `EPOLLEXCLUSIVE_OK_BITS`: what an exclusive interest may carry.
const EXCLUSIVE_OK_BITS: u32 =
    EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE;

/// One watched fd's interest (epoll semantics: at most one per fd).
struct Interest {
    /// The requested events with `EPOLLERR|EPOLLHUP` (always
    /// monitored) and the mode bits; a fired `EPOLLONESHOT` interest
    /// keeps the mode bits alone.
    events: u32,
    /// The caller's `epoll_data`, returned verbatim in delivered events.
    data: u64,
    /// The open file description the number named at registration — the
    /// kernel's `(fd, struct file)` key. The interest drops with the
    /// description's last reference.
    desc: DescId,
    /// The source's per-direction arrival sequences when last observed.
    seen: (u64, u64),
    /// What the interest's events read at the last observation.
    observed: u32,
}

/// A virtual epoll instance: its per-fd interest table and its ready
/// list (`ep->rdllist`).
#[derive(Default)]
struct Epoll {
    interests: BTreeMap<c_int, Interest>,
    ready: VecDeque<c_int>,
}

impl Epoll {
    /// `ep_poll_callback`, observed after the fact: an interest whose
    /// source woke it since the last observation — an arrival in a
    /// watched direction, or a watched condition rising — joins the
    /// tail of the ready list unless it is on it (or disarmed, or
    /// not ready at all, when `ep_send_events` would drop it).
    fn observe(&mut self, fd: c_int, mask: u32, seqs: (u64, u64)) {
        let Some(interest) = self.interests.get_mut(&fd) else {
            return;
        };
        let events = interest.events;
        let revents = mask & events;
        let woken = events & !PRIVATE_BITS != 0
            && ((events & READ_BITS != 0 && seqs.0 != interest.seen.0)
                || (events & WRITE_BITS != 0 && seqs.1 != interest.seen.1)
                || revents & !interest.observed != 0);
        interest.seen = seqs;
        interest.observed = revents;
        if woken && revents != 0 && !self.ready.contains(&fd) {
            self.ready.push_back(fd);
        }
    }

    /// `ep_send_events`: up to `max` events off the head of the ready
    /// list, each what its source's poll mask (`masks`) reads through
    /// the interest's events. An item that reads nothing leaves the
    /// list; a delivered `EPOLLONESHOT` item is disarmed, a delivered
    /// level-triggered one re-queued at the tail, an edge-triggered
    /// one dropped until its next wakeup. Items not reached stay at
    /// the head.
    #[cfg(test)]
    fn send(&mut self, masks: &BTreeMap<c_int, u32>, max: usize) -> Vec<EpollEvent> {
        let delivery = self.plan(masks, max);
        let events = delivery.events.clone();
        self.commit(delivery);
        events
    }

    /// [`Epoll::send`]'s outcome, decided without changing the
    /// instance: what a gather delivers, the ready list after it, and
    /// the one-shot interests it disarms. Only the ready list is
    /// copied, so deciding costs what the list holds, not what the
    /// instance watches.
    fn plan(&self, masks: &BTreeMap<c_int, u32>, max: usize) -> Delivery {
        let mut pending = self.ready.clone();
        let mut requeued = VecDeque::new();
        let mut events = Vec::new();
        let mut disarmed = Vec::new();
        while events.len() < max {
            let Some(fd) = pending.pop_front() else {
                break;
            };
            let Some(interest) = self.interests.get(&fd) else {
                continue;
            };
            let revents = masks.get(&fd).copied().unwrap_or(0) & interest.events;
            if revents == 0 {
                continue;
            }
            events.push(EpollEvent {
                events: revents,
                data: interest.data,
            });
            if interest.events & EPOLLONESHOT != 0 {
                disarmed.push(fd);
            } else if interest.events & EPOLLET == 0 {
                requeued.push_back(fd);
            }
        }
        pending.extend(requeued);
        Delivery {
            events,
            ready: pending,
            disarmed,
        }
    }

    fn commit(&mut self, delivery: Delivery) {
        self.ready = delivery.ready;
        for fd in delivery.disarmed {
            if let Some(interest) = self.interests.get_mut(&fd) {
                interest.events &= PRIVATE_BITS;
            }
        }
    }

    fn forget(&mut self, fd: c_int) -> bool {
        self.ready.retain(|queued| *queued != fd);
        self.interests.remove(&fd).is_some()
    }
}

/// What one gather delivers and leaves behind (see [`Epoll::plan`]).
struct Delivery {
    events: Vec<EpollEvent>,
    ready: VecDeque<c_int>,
    disarmed: Vec<c_int>,
}

/// An epoll registry. The descriptor table refcounts the description
/// (one per `epoll_create1`, shared by every `dup`/`F_DUPFD` of it — mio
/// clones its selector through `F_DUPFD_CLOEXEC`) and frees the registry
/// through [`epoll_close`] when the last number closes.
pub(super) struct EpollSlot {
    ep: Epoll,
}

/// Resolve a guest number to its epoll registry id: `EBADF` for a number
/// that names nothing, `EINVAL` for one that is not an epoll instance.
fn ep_id(fd: c_int) -> Result<u64, c_int> {
    match super::super::fd_table().lock().resolve(fd) {
        Some(resolved) if resolved.kind == FdKind::Epoll => Ok(resolved.handle),
        Some(_) => Err(super::EINVAL),
        None => Err(super::super::EBADF),
    }
}

/// Free an epoll registry whose description's last reference went. A
/// task parked in `epoll_wait` is NOT woken — the kernel's wait holds
/// its own file reference and keeps blocking, and mio's single-threaded
/// driver never closes underneath a wait.
pub(crate) fn epoll_close(handle: u64) {
    lock_state().net.epolls.remove(&handle);
}

/// The description an epoll instance's interest in `(tfd, toff)`
/// watches (`get_epoll_tfile_raw_ptr`, `ep_find_tfd`): the `toff`-th
/// of the interests registered for descriptor number `tfd`, of which
/// the model holds one at most.
pub(crate) fn epoll_target(handle: u64, tfd: c_int, toff: u32) -> Option<DescId> {
    let state = lock_state();
    let slot = state.net.epolls.get(&handle)?;
    let interest = slot.ep.interests.get(&tfd).filter(|_| toff == 0)?;
    Some(interest.desc)
}

/// Drop every interest registered against a description whose last
/// reference went: the kernel's `eventpoll_release` on the file's final
/// `fput`.
pub(crate) fn forget_description(desc: DescId) {
    let mut state = lock_state();
    for slot in state.net.epolls.values_mut() {
        let gone: Vec<c_int> = slot
            .ep
            .interests
            .iter()
            .filter(|(_, interest)| interest.desc == desc)
            .map(|(&fd, _)| fd)
            .collect();
        for fd in gone {
            slot.ep.forget(fd);
        }
    }
}

#[unsafe(no_mangle)]
/// Allocate a virtual epoll instance. Syscall-shaped
/// (`epoll_create1(flags)`) so a future syscall-user-dispatch SIGSYS
/// dispatcher can call it with raw register arguments; the C interposer
/// is thin marshaling over this. Activates the thread subsystem so a
/// later blocking `epoll_wait` can park through the baton.
///
/// # Safety
/// C ABI entry point.
pub extern "C" fn patina_epoll_create1(flags: c_int) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if flags & !EPOLL_CLOEXEC != 0 {
        return super::super::fail(super::EINVAL);
    }
    let mut state = lock_state();
    if let Err(error) = state.ensure_active() {
        return super::super::fail(c_int::from(error.into_posix()));
    }
    let id = state.net.next_epoll;
    state.net.next_epoll = state.net.next_epoll.wrapping_add(1);
    state.net.epolls.insert(
        id,
        EpollSlot {
            ep: Epoll::default(),
        },
    );
    // An epoll instance reports O_RDWR through F_GETFL.
    match super::super::install_fd(
        FdKind::Epoll,
        id,
        O_READ | O_WRITE,
        flags & EPOLL_CLOEXEC != 0,
    ) {
        Ok(fd) => {
            super::super::set_errno(0);
            fd
        }
        Err(errno) => {
            state.net.epolls.remove(&id);
            super::super::fail(errno)
        }
    }
}

#[unsafe(no_mangle)]
/// Apply one `epoll_ctl` op. Syscall-shaped (`epoll_ctl(epfd, op, fd,
/// event)`) for the SUD dispatcher. Registry mutation only — no
/// scheduling point, no trace event. The kernel's `do_epoll_ctl`
/// order: the event is copied in for every op but DEL (`EFAULT`);
/// both numbers must name something (`EBADF`, `epfd` first); the
/// target must be pollable (`EPERM`: a file, a directory, a device,
/// a Landlock ruleset); `EPOLLWAKEUP` is dropped (it needs
/// CAP_BLOCK_SUSPEND); `epfd` must
/// be an epoll instance other than the target (`EINVAL`);
/// `EPOLLEXCLUSIVE` is `EINVAL` on MOD, with bits outside
/// `EPOLLEXCLUSIVE_OK_BITS` or on an epoll target; then ADD is
/// `EEXIST` for a registered fd, DEL and MOD `ENOENT` for an
/// unregistered one, MOD `EINVAL` for an exclusive interest, and an
/// unknown op `EINVAL`. A registered interest that is ready joins the
/// ready list.
///
/// # Safety
/// `event` is the guest's `struct epoll_event` for every op but DEL;
/// it is copied in through `uaccess`.
pub unsafe extern "C" fn patina_epoll_ctl(
    epfd: c_int,
    op: c_int,
    fd: c_int,
    event: *const EpollEvent,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let fail = super::super::fail;
    let (events, data) = if op == EPOLL_CTL_DEL {
        (0, 0)
    } else {
        match read_event(event as usize) {
            Ok((events, data)) => (events & !EPOLLWAKEUP, data),
            Err(errno) => return fail(errno),
        }
    };
    let mut state = lock_state();
    let id = match ep_id(epfd) {
        Err(errno) if errno == super::super::EBADF => return fail(errno),
        id => id,
    };
    // `fdget` of the target: an `O_PATH` descriptor opened nothing
    // to watch.
    let Some(target) = super::super::fd_table()
        .lock()
        .resolve(fd)
        .filter(|target| !target.kind.is_path_only())
    else {
        return fail(super::super::EBADF);
    };
    if matches!(
        target.kind,
        FdKind::File | FdKind::Dir | FdKind::Urandom | FdKind::LandlockRuleset | FdKind::Namespace
    ) {
        return fail(EPERM);
    }
    let id = match id {
        Ok(id) if fd != epfd => id,
        _ => return fail(super::EINVAL),
    };
    if op != EPOLL_CTL_DEL
        && events & EPOLLEXCLUSIVE != 0
        && (op == EPOLL_CTL_MOD
            || (op == EPOLL_CTL_ADD
                && (target.kind == FdKind::Epoll || events & !EXCLUSIVE_OK_BITS != 0)))
    {
        return fail(super::EINVAL);
    }
    // Readiness is defined over every pollable kind but another epoll
    // instance: nested epoll is not modeled and fails closed loudly.
    if target.kind == FdKind::Epoll {
        fatal(&format!(
            "epoll_ctl registered epoll descriptor {fd} on another epoll instance: \
             nested epoll is not modeled; failing closed"
        ));
    }
    let (mask, seqs) = super::fd_poll(&state, fd, Some(target.desc)).unwrap_or((0, (0, 0)));
    let ep = &mut state.net.epolls.get_mut(&id).expect("epoll was checked").ep;
    let registered = Interest {
        events: events | EPOLLERR | EPOLLHUP,
        data,
        desc: target.desc,
        seen: seqs,
        observed: 0,
    };
    match op {
        EPOLL_CTL_ADD => {
            if ep.interests.contains_key(&fd) {
                return fail(super::super::EEXIST);
            }
            ep.interests.insert(fd, registered);
        }
        EPOLL_CTL_DEL => {
            return if ep.forget(fd) {
                0
            } else {
                fail(super::super::ENOENT)
            };
        }
        EPOLL_CTL_MOD => {
            let Some(interest) = ep.interests.get_mut(&fd) else {
                return fail(super::super::ENOENT);
            };
            if interest.events & EPOLLEXCLUSIVE != 0 {
                return fail(super::EINVAL);
            }
            *interest = registered;
        }
        _ => return fail(super::EINVAL),
    }
    // `ep_insert`/`ep_modify` poll the item once and queue it if ready.
    ep.observe(fd, mask, seqs);
    0
}

/// Observe every interest of instance `id` (see [`Epoll::observe`]),
/// in descriptor order — wakeups between two observations are queued
/// in that order, the model keeping no clock across sources — and
/// return what each source's poll mask reads now.
fn scan(state: &mut ThreadRuntime, id: u64) -> BTreeMap<c_int, u32> {
    let polled: Vec<(c_int, u32, (u64, u64))> = state
        .net
        .epolls
        .get(&id)
        .expect("epoll exists")
        .ep
        .interests
        .iter()
        .map(|(&fd, interest)| {
            let (mask, seqs) =
                super::fd_poll(state, fd, Some(interest.desc)).unwrap_or((0, (0, 0)));
            (fd, mask, seqs)
        })
        .collect();
    let ep = &mut state.net.epolls.get_mut(&id).expect("epoll exists").ep;
    let mut masks = BTreeMap::new();
    for (fd, mask, seqs) in polled {
        ep.observe(fd, mask, seqs);
        masks.insert(fd, mask);
    }
    masks
}

/// The watched fds as reactor-neutral `(direction, fd)` pairs for the
/// shared fan-in park: every armed interest watches the read side
/// (where hang-ups and errors arrive too), and the write side when it
/// asks for it. A wake simply rescans.
fn watched_sources(state: &ThreadRuntime, id: u64) -> Vec<(ReadyDir, c_int)> {
    let ep = &state.net.epolls.get(&id).expect("epoll exists").ep;
    let mut watched = Vec::new();
    for (&fd, interest) in &ep.interests {
        if interest.events & !PRIVATE_BITS == 0 {
            continue;
        }
        watched.push((ReadyDir::Read, fd));
        if interest.events & WRITE_BITS != 0 {
            watched.push((ReadyDir::Write, fd));
        }
    }
    watched
}

/// `EP_MAX_EVENTS`: the most events one wait may ask for.
const MAX_EVENTS: c_int = (c_int::MAX as usize / std::mem::size_of::<EpollEvent>()) as c_int;

#[unsafe(no_mangle)]
/// Gather up to `maxevents` ready events into `events`, blocking per the
/// millisecond `timeout_ms` (-1 = block until ready, 0 = poll, > 0 =
/// relative virtual-clock deadline). Syscall-shaped (`epoll_wait(epfd,
/// events, maxevents, timeout)`) for the SUD dispatcher; the C
/// epoll_wait/epoll_pwait interposers are thin marshaling over this.
/// `maxevents` outside `1..=EP_MAX_EVENTS` is `EINVAL`; the events are
/// copied out through `uaccess`, and one that cannot be ends the
/// delivery there (`EFAULT` if it was the first).
///
/// # Safety
/// C ABI entry point; `events` is the guest's buffer.
pub unsafe extern "C" fn patina_epoll_wait(
    epfd: c_int,
    events: *mut c_void,
    maxevents: c_int,
    timeout_ms: c_int,
) -> c_int {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let fail = super::super::fail;
    if let Err(errno) = sched_point() {
        return fail(errno);
    }
    if !(1..=MAX_EVENTS).contains(&maxevents) {
        return fail(super::EINVAL);
    }
    let capacity = maxevents as usize;
    let me = current_task();
    // Absolute deadline for a positive timeout, fixed on the first scan
    // so it does not drift across rescans.
    let mut timeout_deadline: Option<u64> = None;
    loop {
        let mut state = lock_state();
        let id = match ep_id(epfd) {
            Ok(id) => id,
            Err(errno) => return fail(errno),
        };
        let now = match with_context_raw(|c| c.monotonic_now_unrecorded()) {
            Ok(now) => now,
            Err(errno) => return fail(errno),
        };
        let masks = scan(&mut state, id);
        let ep = &mut state.net.epolls.get_mut(&id).expect("epoll exists").ep;
        let delivery = ep.plan(&masks, capacity);
        if !delivery.events.is_empty() {
            let size = std::mem::size_of::<EpollEvent>();
            let written = delivery
                .events
                .iter()
                .enumerate()
                .take_while(|(at, event)| write_event(events as usize + at * size, event).is_ok())
                .count();
            if written == 0 {
                return fail(super::super::EFAULT);
            }
            let delivery = if written < delivery.events.len() {
                ep.plan(&masks, written)
            } else {
                delivery
            };
            ep.commit(delivery);
            return c_int::try_from(written).unwrap_or(c_int::MAX);
        }

        if timeout_ms == 0 {
            return 0;
        }
        // A bounded gather whose deadline has passed with nothing ready
        // returns zero events — never re-parks on an elapsed deadline
        // (which would live-lock the deadlock rescue).
        if timeout_ms > 0 {
            let deadline =
                *timeout_deadline.get_or_insert(now.saturating_add(timeout_ms as u64 * 1_000_000));
            if now >= deadline {
                return 0;
            }
        }
        // Nothing ready: park with multi-fd fan-in on the shared core.
        let watched = watched_sources(&state, id);
        let locs = register_readiness_waiters(&mut state, me, &watched);
        let step = if timeout_ms > 0 {
            let deadline = timeout_deadline.expect("timeout deadline fixed above");
            state.block_timed(
                me,
                "epoll-wait",
                Wait::new(BlockClass::Readiness, locs.clone()),
                ClockKind::Monotonic,
                deadline,
            )
        } else {
            state.block(
                me,
                "epoll-wait",
                Wait::new(BlockClass::Readiness, locs.clone()),
            )
        };
        match step {
            Ok(Step::Switch(picked)) => switch_and_park(state, picked, me),
            Ok(Step::Continue) => drop(state),
            Err(error) => {
                let mut state = lock_state();
                unregister_waiters(&mut state, me, &locs);
                return super::super::fail(c_int::from(error.into_posix()));
            }
        }
        let mut state = lock_state();
        unregister_waiters(&mut state, me, &locs);
        state.timed_out.remove(&me);
        drop(state);
        if super::signals::resume() == super::signals::Resumed::Eintr {
            return super::super::fail(super::super::EINTR);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BTreeMap, EPOLLERR, EPOLLET, EPOLLHUP, EPOLLIN, EPOLLONESHOT, EPOLLOUT, Epoll, EpollEvent,
        Interest,
    };

    /// The Rust struct is written straight into the guest's buffer, so
    /// its layout must be the kernel ABI (also pinned from the C side
    /// by `_Static_assert`s against the platform `struct epoll_event`).
    #[test]
    fn epoll_event_layout_matches_kernel_abi() {
        assert_eq!(std::mem::offset_of!(EpollEvent, events), 0);
        if cfg!(target_arch = "x86_64") {
            assert_eq!(std::mem::size_of::<EpollEvent>(), 12);
            assert_eq!(std::mem::offset_of!(EpollEvent, data), 4);
        } else {
            assert_eq!(std::mem::size_of::<EpollEvent>(), 16);
            assert_eq!(std::mem::offset_of!(EpollEvent, data), 8);
        }
    }

    fn interest(events: u32) -> Interest {
        Interest {
            events: events | EPOLLERR | EPOLLHUP,
            data: 0,
            desc: 0,
            seen: (0, 0),
            observed: 0,
        }
    }

    fn delivered(ep: &mut Epoll, masks: &[(i32, u32)], max: usize) -> Vec<u32> {
        let masks: BTreeMap<i32, u32> = masks.iter().copied().collect();
        ep.send(&masks, max)
            .iter()
            .map(|event| event.events)
            .collect()
    }

    /// The pipe of readiness/epoll: the writer is ready first, the
    /// reader after a write; level-triggered items re-queue at the
    /// tail, so `maxevents` 1 takes the one queued first.
    #[test]
    fn ready_list_is_fifo_by_wakeup_with_level_items_requeued_at_the_tail() {
        let mut ep = Epoll::default();
        ep.interests.insert(3, interest(EPOLLIN));
        ep.interests.insert(4, interest(EPOLLOUT));
        ep.observe(3, EPOLLOUT, (0, 0));
        ep.observe(4, EPOLLOUT, (0, 0));
        assert_eq!(ep.ready, [4]);
        assert_eq!(
            delivered(&mut ep, &[(3, EPOLLOUT), (4, EPOLLOUT)], 8),
            [EPOLLOUT]
        );
        ep.observe(3, EPOLLIN, (1, 0));
        ep.observe(4, EPOLLOUT, (0, 0));
        assert_eq!(ep.ready, [4, 3]);
        let both = [(3, EPOLLIN), (4, EPOLLOUT)];
        assert_eq!(delivered(&mut ep, &both, 8), [EPOLLOUT, EPOLLIN]);
        assert_eq!(delivered(&mut ep, &both, 1), [EPOLLOUT]);
        assert_eq!(ep.ready, [3, 4]);
    }

    /// Edge-triggered: every arrival is a wakeup, readiness that
    /// merely persists is none; a rising condition (a hang-up) is.
    #[test]
    fn edge_items_fire_per_arrival_and_per_rising_condition() {
        let mut ep = Epoll::default();
        ep.interests.insert(5, interest(EPOLLIN | EPOLLET));
        ep.observe(5, EPOLLIN, (1, 0));
        assert_eq!(delivered(&mut ep, &[(5, EPOLLIN)], 8), [EPOLLIN]);
        ep.observe(5, EPOLLIN, (1, 0));
        assert!(ep.ready.is_empty());
        ep.observe(5, EPOLLIN, (2, 0));
        assert_eq!(delivered(&mut ep, &[(5, EPOLLIN)], 8), [EPOLLIN]);
        ep.observe(5, EPOLLIN | EPOLLHUP, (2, 0));
        assert_eq!(
            delivered(&mut ep, &[(5, EPOLLIN | EPOLLHUP)], 8),
            [EPOLLIN | EPOLLHUP]
        );
    }

    /// A socket's write-space arrivals: an edge-triggered EPOLLOUT item
    /// the reactor saw writable, whose writer then filled and was
    /// drained before the next wait, is queued again by the drain
    /// alone — the mask never read unwritable at a scan.
    #[test]
    fn a_write_space_arrival_requeues_an_edge_triggered_writer() {
        let mut ep = Epoll::default();
        ep.interests.insert(8, interest(EPOLLOUT | EPOLLET));
        ep.observe(8, EPOLLOUT, (0, 0));
        assert_eq!(delivered(&mut ep, &[(8, EPOLLOUT)], 8), [EPOLLOUT]);
        ep.observe(8, EPOLLOUT, (0, 0));
        assert!(ep.ready.is_empty());
        ep.observe(8, EPOLLOUT, (0, 1));
        assert_eq!(delivered(&mut ep, &[(8, EPOLLOUT)], 8), [EPOLLOUT]);
    }

    /// A delivered one-shot item is disarmed: nothing wakes it until
    /// a MOD re-arms it; an item that reads nothing leaves the list.
    #[test]
    fn oneshot_disarms_and_unready_items_leave_the_list() {
        let mut ep = Epoll::default();
        ep.interests.insert(6, interest(EPOLLIN | EPOLLONESHOT));
        ep.interests.insert(7, interest(EPOLLIN));
        ep.observe(6, EPOLLIN, (1, 0));
        ep.observe(7, EPOLLIN, (1, 0));
        assert_eq!(delivered(&mut ep, &[(6, EPOLLIN), (7, 0)], 8), [EPOLLIN]);
        assert!(ep.ready.is_empty());
        ep.observe(6, EPOLLIN, (2, 0));
        assert!(ep.ready.is_empty());
    }
}
