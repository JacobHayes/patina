//! Pending signal delivery and host action selection.
//!
//! A delivery is three returning steps around the releases that start the
//! guest's handlers: [`begin`] (what any delivery point does first), [`next`]
//! (dequeue a batch and put it on the host, or the first member of one that
//! is released a member at a time) and [`released`] (what the handlers'
//! returns left; the next member). Between them a driver performs each
//! release ([`Release`]). The C driver (`c/posix/delivery.c`) does, at the
//! exit of a trap handler that holds the thread (the counter trap, the fault
//! front's return): every step has returned by then, so no Rust frame of the
//! shim is beneath a handler, which may leave by `siglongjmp`. Every other
//! delivery point still releases from Rust ([`deliver`]); under a trap
//! handler's hold it leaves the signals pending for that exit instead.

use super::*;
use std::cell::RefCell;

#[unsafe(no_mangle)]
/// Called at the boundary return, not at generation. No lock survives a host
/// unblock: handlers can re-enter either door and acquire the runtime normally.
pub extern "C" fn patina_signal_deliver() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    deliver();
}

/// Host masks are authoritative inside nested guest handlers, inside a
/// handler the counter trap ran, and inside any a fault front ran (each of
/// which `siglongjmp` may have left, restoring a mask the shim never saw:
/// glibc's restore is its own system call). Refresh at
/// the boundary, before generation chooses a recipient; generation itself
/// stays host-free. Outside both the no-pending path needs no host syscall.
pub(crate) fn refresh_handler_mask() {
    if RELEASING_FRAMES.with(Cell::get) || fault::scoped() || frames::handlers_running() {
        let mask = with_segv(read_mask());
        if let Some(task) = lock_state().signals.tasks.get_mut(&current_task()) {
            task.mask = mask;
        }
    }
}

/// How a release starts the handlers of what [`next`] prepared.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Release {
    /// Install `mask`: the batch queued on the host blocked is built at once.
    Unblock = 1,
    /// Queue `info` for `sig` on this thread (`rt_tgsigqueueinfo`) under the
    /// mask already installed, which leaves it unblocked: its frame is built
    /// as the queue returns. A routed SIGSEGV is never blocked on the host,
    /// so its queue is its release too.
    Queue = 2,
}

/// One delivery's state between its steps, in its driver's frame: C's
/// `struct patina_exit` (`c/posix/delivery.c`), whose layout this mirrors.
/// Only [`next`] fills it.
#[repr(C)]
pub struct Exit {
    /// [`Release::Unblock`]'s host mask; under [`Release::Queue`], the mask
    /// the member's frame saves.
    mask: u64,
    /// The word of the delivery's SIGSEGV scope ([`fault::open_scope_at`]).
    scope_word: u64,
    /// The signals whose dequeued action stands in on the host until their
    /// frames are built ([`current_action`]).
    swapped: u64,
    /// The batch released a member at a time, 0 when none ([`Remainders`]).
    ticket: u64,
    /// The entry the C driver hands the thread to the handlers from.
    held: crate::panic_boundary::Held,
    /// [`Release::Queue`]'s siginfo, where the queue reads it.
    info: Info,
    pid: i32,
    tid: i32,
    sig: i32,
    release: u8,
    scope_open: u8,
    /// `RELEASING_FRAMES` and `FRAME_DIRTY` as the delivery found them.
    was_releasing: u8,
    outer_dirty: u8,
    /// The [`Plan`] this delivery carries out: the mask a temporary-mask
    /// wait restores once its handlers ran, the temporary mask whose SIGSEGV
    /// block they run under, and its scope's word.
    plan_old: u64,
    plan_segv: u64,
    plan_word: u64,
    plan: u8,
    /// The charge state of the call the handlers interrupt, given back when
    /// they return to the trap exit ([`patina_trap_take_back`]), whatever
    /// their own calls left (one a `siglongjmp` abandoned never ends itself).
    call: crate::charge::Began,
    /// [`PLAN_ERRNO`]'s value.
    plan_errno: i32,
}

const _: () = assert!(size_of::<Exit>() == 224 && align_of::<Exit>() == 8);

/// [`Exit::plan`]: restore `plan_old` once the handlers ran.
const PLAN_RESTORE: u8 = 1;
/// The call restarts if it answers `EINTR` (a wait `SA_RESTART` restarts).
const PLAN_RESTART: u8 = 2;
/// The first frame the delivery builds saves `plan_old`, not the temporary
/// mask (`sigmask_to_save`), until it is built.
const PLAN_SAVED: u8 = 4;
/// A frame saved `plan_old`: its return restores it.
const PLAN_CARRIED: u8 = 8;
/// The scope at `plan_word` is open.
const PLAN_SCOPE: u8 = 16;
/// A libc door failed with `plan_errno`: written after the handlers ran
/// unless the call runs again, as glibc's wrapper writes it after the
/// kernel's return delivered them.
const PLAN_ERRNO: u8 = 32;

/// What a call under a trap handler's hold leaves its trap's C exit to do
/// after delivering ([`file_temporary_mask`], [`file_restart`]): one per
/// thread, taken by the exit's [`patina_exit_begin`] before any handler
/// runs, so a handler's own calls start from an empty one.
#[derive(Clone, Copy, Default)]
struct Plan {
    flags: u8,
    old: u64,
    segv: u64,
    errno: i32,
}

thread_local! {
    static PLAN: Cell<Plan> = const {
        Cell::new(Plan {
            flags: 0,
            old: 0,
            segv: 0,
            errno: 0,
        })
    };
}

/// A libc door under a hold fails with `errno` ([`PLAN_ERRNO`]).
pub(crate) fn owe_errno(errno: i32) {
    PLAN.with(|plan| {
        let mut filed = plan.get();
        filed.flags |= PLAN_ERRNO;
        filed.errno = errno;
        plan.set(filed);
    });
}

/// A temporary-mask wait under a trap handler's hold returns with `requested`
/// still installed: its exit delivers under it, has the first frame save
/// `old`, and restores `old` after (unless that frame's return did).
pub(super) fn file_temporary_mask(old: u64, requested: u64) {
    PLAN.with(|plan| {
        let mut filed = plan.get();
        filed.flags |= PLAN_RESTORE | PLAN_SAVED;
        filed.old = old;
        filed.segv = requested;
        plan.set(filed);
    });
}

/// A wait `SA_RESTART` restarts, under a trap handler's hold: answering
/// `EINTR`, the call runs again from its arguments once its exit delivered.
pub(super) fn file_restart() {
    PLAN.with(|plan| {
        let mut filed = plan.get();
        filed.flags |= PLAN_RESTART;
        plan.set(filed);
    });
}

/// Whether a call left a plan no exit took: a trap handler taking the
/// thread from guest code finds none.
pub(super) fn plan_pending() -> bool {
    PLAN.with(|plan| plan.get().flags != 0)
}

impl Exit {
    fn new() -> Self {
        Self {
            mask: 0,
            scope_word: 0,
            swapped: 0,
            ticket: 0,
            held: crate::panic_boundary::Held::default(),
            info: Info { words: [0; 16] },
            pid: 0,
            tid: 0,
            sig: 0,
            release: 0,
            scope_open: 0,
            was_releasing: 0,
            outer_dirty: 0,
            plan_old: 0,
            plan_segv: 0,
            plan_word: 0,
            plan: 0,
            call: crate::charge::Began::NONE,
            plan_errno: 0,
        }
    }

    /// A Rust delivery for a temporary-mask wait: its first frame saves
    /// `old` ([`PLAN_SAVED`]).
    fn saving(old: u64) -> Self {
        let mut exit = Self::new();
        exit.plan_old = old;
        exit.plan = PLAN_SAVED;
        exit
    }

    /// The mask the first frame built saves instead of the temporary one,
    /// once: from the next frame on the kernel saves what is blocked.
    fn first_frame_saves(&mut self) -> Option<u64> {
        if self.plan & PLAN_SAVED == 0 {
            return None;
        }
        self.plan &= !PLAN_SAVED;
        self.plan |= PLAN_CARRIED;
        let old = self.plan_old;
        let segv = if trap_routed(SIGSEGV) {
            old & bit(SIGSEGV)
        } else {
            0
        };
        Some(host_mask(old) | segv)
    }
}

/// A batch released a member at a time, between its releases: the members
/// whose frames are still to be built, last dequeued first.
struct Remainder {
    ticket: u64,
    batch: Vec<(Instance, Action, u32)>,
    blocks: Vec<SegvBlock>,
    segv: SegvBlock,
    mask: u64,
    /// The member released last; those below it are still to run.
    at: usize,
}

/// This thread's batches released a member at a time, innermost last. A
/// driver whose handler left by `siglongjmp` leaves its own behind: an outer
/// one's step drops those above it, and past [`REMAINDERS`] left at once the
/// run stops by name.
struct Remainders {
    live: Vec<Remainder>,
    next: u64,
}

/// How many batches released a member at a time a thread holds at once.
const REMAINDERS: usize = 64;

thread_local! {
    static REMAINDER: RefCell<Remainders> = const {
        RefCell::new(Remainders { live: Vec::new(), next: 1 })
    };
}

/// What every delivery point does first: answers whether one can deliver.
/// A dequeued action a handler left by `siglongjmp` before its batch gave
/// the current one back ([`dequeued_action`]): its frame is built.
fn begin() -> bool {
    if crate::in_shim_bootstrap() || task_completed() || main_returned() {
        return false;
    }
    let swapped = lock_state().signals.swapped;
    if swapped != 0 {
        current_action(swapped);
    }
    super::timers::fire_due();
    refresh_handler_mask();
    frames::resync_on_guest_stack();
    pending()
}

/// Whether anything is pending for this thread to deliver. Explicit C-ABI
/// embedders may have a Context but no managed task or host-alias link: an
/// inactive delivery point must remain a no-op.
fn pending() -> bool {
    let me = current_task();
    let state = lock_state();
    let Some(task) = state.signals.tasks.get(&me) else {
        return false;
    };
    task.private.mask() | state.signals.shared.mask() != 0
}

/// Dequeue the next batch for this thread and put it on the host, every
/// member blocked, or prepare the first member of one released a member at a
/// time: answers whether `exit` holds a release to perform.
fn next(exit: &mut Exit) -> bool {
    let me = current_task();
    if !pending() {
        return false;
    }
    let segv = segv_blocked();
    let mask = read_mask() | segv_bit(segv);
    let batch = {
        let mut state = lock_state();
        if segv == SegvBlock::Unknown
            && (state.signals.tasks[&me].private.mask() | state.signals.shared.mask())
                & bit(SIGSEGV)
                != 0
        {
            drop(state);
            crate::trap_fatal(SEGV_UNKNOWN);
        }
        state.signals.tasks.get_mut(&me).unwrap().mask = mask;
        let mut batch = Vec::new();
        let mut eligible = !mask;
        while let Some(instance) = state.dequeue_signal(me, eligible, true) {
            let action = state.signals.actions[instance.sig as usize];
            if action.handler == SIG_IGN || (action.handler == SIG_DFL && ignored(instance.sig)) {
                continue;
            }
            let seen = state.signals.changes[instance.sig as usize];
            if action.flags & SA_RESETHAND != 0 {
                // Linux resets only sa_handler; flags, mask and restorer
                // remain observable through rt_sigaction after delivery.
                state.signals.actions[instance.sig as usize].handler = SIG_DFL;
            }
            // Later members blocked by this frame stay virtual, visible to
            // sigpending/signalfd inside the handler. Independent frames still
            // stack through one host unblock. Host masks encode nesting, so
            // a separate in_delivery flag would wrongly forbid nested delivery.
            if action.handler != SIG_DFL {
                eligible &= !action.mask;
                if action.flags & SA_NODEFER == 0 {
                    eligible &= !bit(instance.sig);
                }
            }
            batch.push((instance, action, seen));
        }
        if !batch.is_empty() {
            // A cancel that reached this thread inside a sleep, before
            // the sleep waits, has ended glibc's thread: no handler runs.
            if state.cancels.acts_in_point(me, state.signals.depth(me)) {
                fatal(
                    "a signal handler would run inside a sleep whose thread a pending \
                     cancellation has ended under glibc: not modeled",
                );
            }
            state.signals.tasks.get_mut(&me).unwrap().delivering += 1;
        }
        batch
    };
    if batch.is_empty() {
        return false;
    }
    // The SIGSEGV block each member's handler runs under: the batch's,
    // or blocked from the first member whose frame blocks it on.
    let mut running = segv;
    let blocks = batch
        .iter()
        .map(|(instance, action, _)| {
            if action.handler != SIG_DFL
                && (action.mask & bit(SIGSEGV) != 0
                    || (instance.sig == SIGSEGV && action.flags & SA_NODEFER == 0))
            {
                running = SegvBlock::Yes;
            }
            running
        })
        .collect::<Vec<_>>();
    // The kernel dequeues the members in order and builds each frame
    // over the last, so the last dequeued runs first. Re-queued on the
    // host (all this thread's), they are built in the host's order,
    // synchronous first then by number: one unblock releases them all
    // when that is the batch's order, no signal repeats (the host would
    // merge it) and their handlers share one SIGSEGV block. Otherwise
    // each is queued and released alone at its own turn, last dequeued
    // first, as a trap-routed SIGSEGV (which cannot wait blocked on the
    // host) always is: nothing of the batch waits on the host while an
    // earlier handler runs, which may leave by `siglongjmp` (natively
    // losing the frames below it) or change a later member's action.
    let key = |sig: u8| (SYNCHRONOUS & bit(sig) == 0, sig);
    let one_by_one = batch.iter().any(routed)
        || batch
            .windows(2)
            .any(|pair| key(pair[0].0.sig) > key(pair[1].0.sig))
        || (1..batch.len()).any(|i| batch[..i].iter().any(|m| m.0.sig == batch[i].0.sig))
        || (trap_routed(SIGSEGV) && blocks.windows(2).any(|pair| pair[0] != pair[1]));
    install_mask(u64::MAX);
    exit.pid = host(SYS_GETPID, [0; 6]) as i32;
    exit.tid = host(SYS_GETTID, [0; 6]) as i32;
    let mut swapped = 0;
    for (instance, action, seen) in &batch {
        if action.handler == SIG_DFL {
            if matches!(instance.sig, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU) {
                fatal("default Stop-class signal would stop the only virtual process");
            }
            if crate::shutdown_run() != 0 {
                fatal("signal termination finalization failed");
            }
            let default = Action::default();
            if instance.sig != SIGKILL
                && host(
                    SYS_RT_SIGACTION,
                    [
                        instance.sig as u64,
                        &default as *const _ as u64,
                        0,
                        SIGSET_BYTES as u64,
                        0,
                        0,
                    ],
                ) != 0
            {
                fatal("host default signal action install failed (rt_sigaction)");
            }
            // Release only the dying signal; queued handler frames stay
            // blocked. No handler runs: the default action ends the run.
            install_mask(!bit(instance.sig));
            queue(exit, instance);
        } else if !one_by_one {
            if fault::front_routed(instance.sig) {
                // The batch's first member's frame is built first.
                let saves = if std::ptr::eq(instance, &batch[0].0) {
                    exit.first_frame_saves()
                } else {
                    None
                };
                fault::send(instance.sig, *action, &instance.info, saves);
            }
            swapped |= dequeued_action(instance.sig, *action, *seen);
            queue(exit, instance);
        }
    }
    exit.was_releasing = u8::from(RELEASING_FRAMES.with(|flag| flag.replace(true)));
    exit.outer_dirty = FRAME_DIRTY.with(Cell::get);
    RESTORED_SEGV.set(false);
    exit.scope_open = u8::from(fault::open_scope_at(&mut exit.scope_word));
    if !one_by_one {
        fault::set(blocks[0]);
        FRAME_DIRTY.with(|dirty| dirty.set(dirty.get() | FRAME_MASK));
        exit.mask = host_mask(mask);
        exit.swapped = swapped;
        exit.release = Release::Unblock as u8;
        return true;
    }
    let ticket = REMAINDER.with_borrow_mut(|remainders| {
        if remainders.live.len() == REMAINDERS {
            crate::trap_fatal(
                "more signal batches released a member at a time were left by siglongjmp \
                 than the shim tracks: not modeled",
            );
        }
        let ticket = remainders.next;
        remainders.next += 1;
        remainders.live.push(Remainder {
            ticket,
            at: batch.len(),
            batch,
            blocks,
            segv,
            mask,
        });
        ticket
    });
    exit.ticket = ticket;
    if !next_member(exit) {
        // A member-at-a-time batch always holds a member with a handler.
        unreachable!("a batch released a member at a time with no handler to run");
    }
    true
}

/// A batch member, released alone when it is routed to the counter trap.
fn routed((instance, action, _): &(Instance, Action, u32)) -> bool {
    action.handler != SIG_DFL && trap_routed(instance.sig)
}

/// Queue `instance` on this thread on the host, where `exit` sends.
fn queue(exit: &Exit, instance: &Instance) {
    let rc = host(
        SYS_RT_TGSIGQUEUEINFO,
        [
            exit.pid as u64,
            exit.tid as u64,
            instance.sig as u64,
            &instance.info as *const _ as u64,
            0,
            0,
        ],
    );
    if rc != 0 {
        fatal("host signal-frame queue failed (rt_tgsigqueueinfo)");
    }
}

/// The member-at-a-time batch `exit` holds: its next member with a handler,
/// under the mask its frame saves natively (the earlier members' handlers'
/// masks), with the action its dequeue captured. Answers whether there was
/// one; `exit` describes its release.
fn next_member(exit: &mut Exit) -> bool {
    REMAINDER.with_borrow_mut(|remainders| {
        let remainder = remainders
            .live
            .iter_mut()
            .rfind(|remainder| remainder.ticket == exit.ticket)
            .expect("a member-at-a-time batch outlives its driver's steps");
        while remainder.at > 0 {
            remainder.at -= 1;
            let i = remainder.at;
            let (instance, action, seen) = remainder.batch[i];
            if action.handler == SIG_DFL {
                continue;
            }
            let saved =
                remainder.batch[..i]
                    .iter()
                    .fold(remainder.mask, |held, (member, action, _)| {
                        let own = if action.flags & SA_NODEFER == 0 {
                            bit(member.sig)
                        } else {
                            0
                        };
                        held | action.mask | own
                    });
            let sig = if routed(&remainder.batch[i]) {
                // The trap's frame runs the action its dequeue captured.
                fault::set(if i == 0 {
                    remainder.segv
                } else {
                    remainder.blocks[i - 1]
                });
                install_mask(saved);
                let saves = if i == 0 {
                    exit.first_frame_saves()
                } else {
                    None
                };
                fault::send(SIGSEGV, action, &instance.info, saves);
                SIGSEGV
            } else {
                fault::set(remainder.blocks[i]);
                if fault::front_routed(instance.sig) {
                    let saves = if i == 0 {
                        exit.first_frame_saves()
                    } else {
                        None
                    };
                    fault::send(instance.sig, action, &instance.info, saves);
                }
                install_mask(saved);
                instance.sig
            };
            exit.swapped = dequeued_action(sig, action, seen);
            exit.mask = saved;
            exit.info = instance.info;
            exit.sig = i32::from(instance.sig);
            exit.release = Release::Queue as u8;
            return true;
        }
        false
    })
}

/// The handlers a release started returned (by then the host holds the
/// mask the last frame's return restored). Answers whether `exit` holds
/// another release: the batch's next member.
fn released(exit: &mut Exit) -> bool {
    current_action(exit.swapped);
    if exit.ticket != 0 {
        // Natively the next member's handler starts under what this one's
        // `rt_sigreturn` installed: its frame's saved mask, which the handler
        // may have edited.
        let more = REMAINDER.with_borrow(|remainders| {
            remainders
                .live
                .iter()
                .rfind(|remainder| remainder.ticket == exit.ticket)
                .is_some_and(|remainder| remainder.at > 0)
        });
        if more && read_mask() != host_mask(exit.mask) {
            crate::trap_fatal(
                "a signal handler edited its frame's saved mask (uc_sigmask) while more \
                 frames of its delivery batch were still to run: not modeled",
            );
        }
        if next_member(exit) {
            return true;
        }
        // This batch is done, and so is every one a driver left above it.
        REMAINDER.with_borrow_mut(|remainders| {
            if let Some(at) = remainders
                .live
                .iter()
                .rposition(|remainder| remainder.ticket == exit.ticket)
            {
                remainders.live.truncate(at);
            }
        });
        exit.ticket = 0;
    }
    // Inner SIGSYS fixups may consume these bits while handlers run. The
    // enclosing frame still owns its changes, including the release mask.
    FRAME_DIRTY.with(|dirty| dirty.set(dirty.get() | exit.outer_dirty | FRAME_MASK));
    RELEASING_FRAMES.with(|flag| flag.set(exit.was_releasing != 0));
    // Nested boundary calls observed the handler mask. rt_sigreturn restored
    // the mask each frame saved: this enclosing one, unless a handler edited
    // its frame's, which the kernel honours. Read it back either way, even
    // if no pending work remains for another loop. glibc's restorer (and
    // arm64's kernel trampoline) returns with no trap to strip that mask,
    // so a containment signal a handler added is taken out again here,
    // before a later raw syscall or counter read meets it blocked; a
    // SIGSEGV block it added is kept virtually.
    let restored = read_mask();
    let kept = host_mask(restored);
    if kept != restored {
        containment_kept_unblocked(restored & !kept);
        install_mask(kept);
    }
    if exit.scope_open != 0 {
        fault::close_scope_at(&exit.scope_word as *const u64 as usize);
        exit.scope_open = 0;
    }
    fault::batch_returned();
    if trap_routed(SIGSEGV) && (RESTORED_SEGV.take() || restored & bit(SIGSEGV) != 0) {
        fault::set(SegvBlock::Yes);
    }
    let mask = with_segv(kept);
    let mut state = lock_state();
    let task = state.signals.tasks.get_mut(&current_task()).unwrap();
    task.mask = mask;
    task.delivering -= 1;
    false
}

/// Perform `exit`'s release from Rust: the delivery points whose exit is not
/// yet C. The handlers run with the thread theirs.
fn release(exit: &Exit) {
    crate::sud::with_signal_delivery(|| {
        let _guest = crate::panic_boundary::PanicScope::suspend();
        match exit.release {
            r if r == Release::Unblock as u8 => install_raw_mask(exit.mask),
            _ => {
                let rc = host(
                    SYS_RT_TGSIGQUEUEINFO,
                    [
                        exit.pid as u64,
                        exit.tid as u64,
                        exit.sig as u64,
                        &exit.info as *const _ as u64,
                        0,
                        0,
                    ],
                );
                if rc != 0 {
                    fatal("host signal-frame queue failed (rt_tgsigqueueinfo)");
                }
            }
        }
    });
}

/// Install the host mask `mask` as it is ([`next`] already kept the
/// containment signals out of it).
fn install_raw_mask(mask: u64) {
    if host(
        SYS_RT_SIGPROCMASK,
        [
            SIG_SETMASK as u64,
            &mask as *const _ as u64,
            0,
            SIGSET_BYTES as u64,
            0,
            0,
        ],
    ) != 0
    {
        fatal("host signal mask install failed (rt_sigprocmask)");
    }
}

/// Deliver what is pending, from Rust: every delivery point whose exit is
/// not yet C. Under a trap handler's hold it leaves the signals pending for
/// the handler's C exit, which delivers once every Rust frame returned.
pub(crate) fn deliver() {
    if !crate::panic_boundary::exit_owned() {
        deliver_from_rust(&mut Exit::new());
    }
}

/// [`deliver`] for a temporary-mask wait returning under its mask: the first
/// frame saves `old`, the mask the wait restores. Under a trap handler's hold
/// the wait's plan leaves that to the exit ([`file_temporary_mask`]).
pub(crate) fn deliver_saving(old: u64) {
    if !crate::panic_boundary::exit_owned() {
        deliver_from_rust(&mut Exit::saving(old));
    }
}

/// [`deliver`]'s releases, from Rust, carrying out `exit`'s plan.
fn deliver_from_rust(exit: &mut Exit) {
    if !begin() {
        return;
    }
    while next(exit) {
        loop {
            release(exit);
            if !released(exit) {
                break;
            }
        }
    }
}

/// Take this thread's [`Plan`] into `exit`: open the temporary mask's SIGSEGV
/// scope in `exit` (where it stays until [`end`]) and block SIGSEGV as that
/// mask does.
fn take_plan(exit: &mut Exit) {
    let plan = PLAN.with(|plan| plan.replace(Plan::default()));
    exit.plan = plan.flags;
    exit.plan_old = plan.old;
    exit.plan_segv = plan.segv;
    exit.plan_errno = plan.errno;
    if exit.plan & PLAN_RESTORE != 0 {
        if fault::open_scope_at(&mut exit.plan_word) {
            exit.plan |= PLAN_SCOPE;
        }
        set_segv(exit.plan_segv);
    }
}

/// After the deliveries: a temporary-mask wait's old mask is back (unless
/// the first frame's return put it back, or a handler's edit of it), and
/// answers whether the call runs again: a restart was asked and the call
/// answered `EINTR` (`ret`, the raw result).
fn end(exit: &mut Exit, ret: i64) -> bool {
    if exit.plan & PLAN_SCOPE != 0 {
        fault::close_scope_at(&exit.plan_word as *const u64 as usize);
    }
    if exit.plan & PLAN_RESTORE != 0 {
        let me = current_task();
        let mask = if exit.plan & PLAN_CARRIED == 0 {
            install_mask(exit.plan_old);
            exit.plan_old
        } else {
            with_segv(read_mask())
        };
        if let Some(task) = lock_state().signals.tasks.get_mut(&me) {
            task.mask = mask;
        }
    }
    // A raw call answers `-EINTR`; a libc door owes errno `EINTR`.
    let eintr = ret == -i64::from(EINTR) || exit.plan & PLAN_ERRNO != 0 && exit.plan_errno == EINTR;
    let restart = exit.plan & PLAN_RESTART != 0 && eintr;
    // Only a final outcome writes the errno it owes; a call that runs again
    // owes nothing yet.
    if exit.plan & PLAN_ERRNO != 0 && !restart {
        crate::abi::restore_host_errno(exit.plan_errno);
    }
    exit.plan = 0;
    restart
}

/// A step's entry: called by the C exit of the trap handler holding the
/// thread, or a named stop.
fn from_trap_exit() {
    if !crate::panic_boundary::entered_by_trap_exit() {
        crate::trap_fatal(
            "a signal delivery's step was called with a shim Rust frame beneath it, where a \
             handler that leaves by siglongjmp would discard it: not modeled",
        );
    }
}

/// A step that leads to a release from C: never with shim Rust frames
/// suspended beneath ([`patina_exit_begin`] delivers from Rust there).
fn releasing_from_trap_exit() {
    from_trap_exit();
    if crate::panic_boundary::frames_suspended() {
        crate::trap_fatal(
            "a release from C was prepared with shim Rust frames suspended beneath the trap: \
             not modeled",
        );
    }
}

#[unsafe(no_mangle)]
/// [`begin`], for the C driver: bit 0 whether anything is pending (the
/// driver releases it, [`patina_exit_next`]), bit 1 whether the trapped call
/// left a plan ([`patina_exit_end`] carries it out). Where shim Rust frames are suspended beneath
/// the trap (a delivery from Rust ran the handler that took it), a release
/// from C would run handlers over them as one from Rust does: the delivery
/// is made here, as that delivery makes it, and the driver releases nothing.
///
/// # Safety
/// `exit` is the C driver's `struct patina_exit`, writable for the call.
pub unsafe extern "C" fn patina_exit_begin(exit: *mut Exit) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_glue();
    from_trap_exit();
    // SAFETY: the C driver's own record, per this function's contract.
    let exit = unsafe { &mut *exit };
    take_plan(exit);
    let planned = i32::from(exit.plan != 0) << 1;
    if crate::panic_boundary::frames_suspended() {
        deliver_from_rust(exit);
        return planned;
    }
    i32::from(begin()) | planned
}

#[unsafe(no_mangle)]
/// [`end`], for the C driver, whose record `exit` is: whether the trapped
/// call that answered `ret` runs again.
///
/// # Safety
/// `exit` is the C driver's `struct patina_exit`, writable for the call.
pub unsafe extern "C" fn patina_exit_end(exit: *mut Exit, ret: i64) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_glue();
    from_trap_exit();
    // SAFETY: the C driver's own record, per this function's contract.
    i32::from(end(unsafe { &mut *exit }, ret))
}

#[unsafe(no_mangle)]
/// [`next`], for the C driver, whose record `exit` is.
///
/// # Safety
/// `exit` is the C driver's `struct patina_exit`, writable for the call.
pub unsafe extern "C" fn patina_exit_next(exit: *mut Exit) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_glue();
    releasing_from_trap_exit();
    // SAFETY: the C driver's own record, per this function's contract.
    i32::from(next(unsafe { &mut *exit }))
}

#[unsafe(no_mangle)]
/// [`released`], for the C driver, whose record `exit` is.
///
/// # Safety
/// `exit` is the C driver's `struct patina_exit`, writable for the call.
pub unsafe extern "C" fn patina_exit_released(exit: *mut Exit) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter_glue();
    releasing_from_trap_exit();
    // SAFETY: the C driver's own record, per this function's contract.
    i32::from(released(unsafe { &mut *exit }))
}

#[unsafe(no_mangle)]
/// Hand the thread to the handlers `exit`'s release starts (for the C
/// driver): the trap handler's hold is kept in `exit` until
/// [`patina_trap_take_back`].
///
/// # Safety
/// `exit` is the C driver's `struct patina_exit`, writable for the call.
pub unsafe extern "C" fn patina_trap_hand_over(exit: *mut Exit) {
    // SAFETY: the C driver's own record, per this function's contract.
    unsafe {
        (*exit).held = crate::panic_boundary::hand_over();
        (*exit).call = crate::charge::interrupted();
    }
}

#[unsafe(no_mangle)]
/// The handlers `exit`'s release started returned: the trap handler holds
/// the thread again (for the C driver).
///
/// # Safety
/// `exit` is the C driver's `struct patina_exit`, readable for the call.
pub unsafe extern "C" fn patina_trap_take_back(exit: *const Exit) {
    // SAFETY: the C driver's own record, per this function's contract.
    unsafe {
        crate::panic_boundary::take_back((*exit).held);
        crate::charge::end((*exit).call);
    }
}

/// A delivery driven from under a shim Rust frame (for the detectors' must-fail
/// control, a shim built with `planted-faults`): its first step stops the run
/// by name.
#[cfg(feature = "planted-faults")]
#[unsafe(no_mangle)]
pub extern "C" fn patina_planted_drive_under_scope() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    unsafe extern "C" {
        fn patina_exit_drive(exit: *mut Exit, ret: i64) -> i32;
    }
    let mut exit = Exit::new();
    // SAFETY: a record of the driver's own layout, writable for the call.
    unsafe { patina_exit_drive(&mut exit, 0) };
}

/// Before a batch member's frame is built: the host holds the action `sig`
/// was dequeued with (`action`, when its change count was `seen`), as the
/// kernel builds the frame natively, where the guest set another since (an
/// earlier handler of the batch, or another thread meanwhile) or another
/// frame's dequeued action stands in for it. Answers the signal to give its
/// current action back once the frame is built ([`current_action`]). For a
/// signal an instruction raises, whose host handler is the shim's, that
/// handler gives it back as the frame enters, before the guest's handler
/// runs ([`fault_entered`]), so no genuine fault meets the dequeued action
/// once the frame ran, `siglongjmp` or not. For any other it is given back
/// once the handler returned: the kernel enters it on the unblock's return
/// with no shim code between. A handler that leaves by `siglongjmp` skips
/// that, and the next delivery point makes it; nothing but a delivery raises
/// such a signal on the host.
fn dequeued_action(sig: u8, action: Action, seen: u32) -> u64 {
    {
        let mut state = lock_state();
        let signals = &mut state.signals;
        if signals.changes[usize::from(sig)] == seen && signals.swapped & bit(sig) == 0 {
            return 0;
        }
        signals.swapped |= bit(sig);
    }
    install_host_action(sig, action);
    bit(sig)
}

/// The frames of `signals` are built: the host holds their current actions
/// again. Each is read under the state lock and installed after it is
/// dropped, as `deliver`'s own installs are: that relies on the execution
/// baton, under which one thread at a time runs guest or shim code, so no
/// `sigaction` of another thread lands between the read and the install
/// (one that did would leave the host holding the older action).
fn current_action(signals: u64) {
    if signals == 0 {
        return;
    }
    for sig in (1..=64u8).filter(|sig| signals & bit(*sig) != 0) {
        let action = {
            let mut state = lock_state();
            state.signals.swapped &= !bit(sig);
            state.signals.actions[usize::from(sig)]
        };
        install_host_action(sig, action);
    }
}

/// The host action that stands for the guest's `action` of `sig`. Its mask
/// keeps the containment signals out, as every mask the host runs guest code
/// under ([`host_mask`]): the kernel blocks an action's mask while its
/// handler runs, and a counter read or raw syscall there would otherwise be
/// forced to the default action. A SIGSEGV the mask names is blocked
/// virtually for the handler instead (`deliver`, [`fault`]); a SIGSYS it
/// names is dropped silently, as from a mask the guest installs itself, so
/// the handler reads SIGSYS back unblocked.
pub(super) fn install_host_action(sig: u8, action: Action) -> i64 {
    // SIGSYS belongs to SUD even on kernels where arming is unavailable.
    // The guest's disposition is observable process state, never a host action.
    if sig == SIGSYS {
        return 0;
    }
    if trap_routed(sig) {
        return 0;
    }
    let action = host_action(sig, action);
    host(
        SYS_RT_SIGACTION,
        [
            u64::from(sig),
            &action as *const _ as u64,
            0,
            SIGSET_BYTES as u64,
            0,
            0,
        ],
    )
}

/// What [`install_host_action`] installs for `sig` (not trap-routed): the
/// front handler for a guest handler, and for every action of a signal an
/// instruction raises.
pub(super) fn host_action(sig: u8, action: Action) -> Action {
    let action = Action {
        mask: host_mask(action.mask),
        ..action
    };
    let handler = !matches!(action.handler, SIG_DFL | SIG_IGN);
    if fault::front_routed(sig) && (handler || SYNCHRONOUS & bit(sig) != 0) {
        fault::front_action(action)
    } else {
        action
    }
}

/// A signal an instruction raises entered its fault handler (`sent`: the
/// frame [`deliver`] queued for it). Every frame a dequeued action stood in
/// for on the host is built by now (each is built as its member is queued,
/// with only shim code between), so the host holds the current actions again
/// from here: a handler that leaves by `siglongjmp` cannot leave a dequeued
/// one behind for the next fault. A genuine fault whose own frame the kernel
/// built under one (a frame of the same signal still below the handler that
/// faulted) is a named stop where that frame is not the current action's.
pub(super) fn fault_entered(sig: u8, sent: bool) {
    let (swapped, current) = {
        let state = lock_state();
        (
            state.signals.swapped,
            state.signals.actions[usize::from(sig)],
        )
    };
    if !sent && swapped & bit(sig) != 0 {
        let mut built = Action::default();
        if host(
            SYS_RT_SIGACTION,
            [
                u64::from(sig),
                0,
                &mut built as *mut _ as u64,
                SIGSET_BYTES as u64,
                0,
                0,
            ],
        ) != 0
        {
            fatal("host fault action query failed (rt_sigaction)");
        }
        // The trap's frame is the same for every action.
        let differs = if trap_routed(sig) {
            false
        } else {
            let expected = host_action(sig, current);
            (built.flags & UAPI_SA_FLAGS, built.mask, built.restorer)
                != (
                    expected.flags & UAPI_SA_FLAGS,
                    expected.mask,
                    expected.restorer,
                )
        };
        if differs {
            crate::trap_fatal(
                "a fault met the action a delivery batch put on the host for a frame of the \
                 same signal still to run, which differs from the current one: not modeled",
            );
        }
    }
    current_action(swapped);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charge::Op;
    use crate::panic_boundary::PanicScope;
    use patina_dst_abi::ChargeClass;

    #[test]
    fn handlers_a_trap_exit_releases_give_the_interrupted_call_its_class_back() {
        let _ = crate::charge::taken();
        {
            // A lock call's handlers are released from a trap exit; one
            // raises a signal whose handler `siglongjmp`s back, so the raise
            // never returns. The lock still parks as itself.
            let _lock = PanicScope::enter_op(Op::PthreadSync);
            let mut exit = Exit::new();
            // SAFETY: the record is local and writable.
            unsafe { patina_trap_hand_over(&mut exit) };
            std::mem::forget(PanicScope::enter());
            // SAFETY: as above.
            unsafe { patina_trap_take_back(&exit) };
            crate::charge::parked();
        }
        let counts = crate::charge::taken();
        assert_eq!(counts.calls(ChargeClass::Sync), 1);
        // The abandoned raise, and the lock's surcharge.
        assert_eq!(counts.calls(ChargeClass::Syscall), 2);
    }
}
