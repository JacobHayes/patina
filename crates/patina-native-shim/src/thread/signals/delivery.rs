//! Pending signal delivery and host action selection.

use super::*;

#[unsafe(no_mangle)]
/// Called at the boundary return, not at generation. No lock survives a host
/// unblock: handlers can re-enter either door and acquire the runtime normally.
pub extern "C" fn patina_signal_deliver() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    deliver();
}

/// Host masks are authoritative inside nested guest handlers, and inside a
/// handler the counter trap ran (which `siglongjmp` may have left). Refresh at
/// the boundary, before generation chooses a recipient; generation itself
/// stays host-free. Outside both the no-pending path needs no host syscall.
pub(crate) fn refresh_handler_mask() {
    if RELEASING_FRAMES.with(Cell::get) || fault::scoped() {
        let mask = with_segv(read_mask());
        if let Some(task) = lock_state().signals.tasks.get_mut(&current_task()) {
            task.mask = mask;
        }
    }
}

pub(crate) fn deliver() {
    if crate::in_shim_bootstrap() || task_completed() || main_returned() {
        return;
    }
    // A dequeued action a handler left by `siglongjmp` before its batch gave
    // the current one back ([`dequeued_action`]): its frame is built.
    let swapped = lock_state().signals.swapped;
    if swapped != 0 {
        current_action(swapped);
    }
    super::timers::fire_due();
    refresh_handler_mask();
    frames::resync_on_guest_stack();
    loop {
        let me = current_task();
        // Explicit C-ABI embedders may have a Context but no managed task or
        // host-alias link. An inactive delivery point must remain a no-op.
        {
            let state = lock_state();
            let Some(task) = state.signals.tasks.get(&me) else {
                return;
            };
            if task.private.mask() | state.signals.shared.mask() == 0 {
                return;
            }
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
                if action.handler == SIG_IGN || (action.handler == SIG_DFL && ignored(instance.sig))
                {
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
            return;
        }
        let routed = |(instance, action, _): &(Instance, Action, u32)| {
            action.handler != SIG_DFL && trap_routed(instance.sig)
        };
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
        let pid = host(SYS_GETPID, [0; 6]);
        let tid = host(SYS_GETTID, [0; 6]);
        let queue = |instance: &Instance| {
            let rc = host(
                SYS_RT_TGSIGQUEUEINFO,
                [
                    pid as u64,
                    tid as u64,
                    instance.sig as u64,
                    &instance.info as *const _ as u64,
                    0,
                    0,
                ],
            );
            if rc != 0 {
                fatal("host signal-frame queue failed (rt_tgsigqueueinfo)");
            }
        };
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
                // Release only the dying signal; queued handler frames stay blocked.
                install_mask(!bit(instance.sig));
                queue(instance);
            } else if !one_by_one {
                if fault::front_routed(instance.sig) {
                    fault::send(instance.sig, *action, &instance.info);
                }
                swapped |= dequeued_action(instance.sig, *action, *seen);
                queue(instance);
            }
        }
        let was_releasing = RELEASING_FRAMES.with(|flag| flag.replace(true));
        let outer_dirty = FRAME_DIRTY.with(Cell::get);
        RESTORED_SEGV.set(false);
        let mut scope = Scoped::new();
        scope.open();
        crate::sud::with_signal_delivery(|| {
            let _guest = crate::panic_boundary::PanicScope::suspend();
            if !one_by_one {
                fault::set(blocks[0]);
                install_mask(mask);
                current_action(swapped);
                return;
            }
            // Each member at its turn, under the mask its frame saves
            // natively (the earlier members' handlers' masks), with the
            // action its dequeue captured.
            for (i, member) in batch.iter().enumerate().rev() {
                let (instance, action, seen) = *member;
                let saved = batch[..i].iter().fold(mask, |held, (member, action, _)| {
                    let own = if action.flags & SA_NODEFER == 0 {
                        bit(member.sig)
                    } else {
                        0
                    };
                    held | action.mask | own
                });
                if routed(member) {
                    // The trap's frame runs the action its dequeue captured.
                    fault::set(if i == 0 { segv } else { blocks[i - 1] });
                    install_mask(saved);
                    fault::send(SIGSEGV, action, &instance.info);
                    let swapped = dequeued_action(SIGSEGV, action, seen);
                    queue(&instance);
                    current_action(swapped);
                } else if action.handler != SIG_DFL {
                    fault::set(blocks[i]);
                    if fault::front_routed(instance.sig) {
                        fault::send(instance.sig, action, &instance.info);
                    }
                    let swapped = dequeued_action(instance.sig, action, seen);
                    install_mask(saved);
                    queue(&instance);
                    current_action(swapped);
                }
                // Natively the next member's handler starts under what this
                // one's `rt_sigreturn` installed: its frame's saved mask,
                // which the handler may have edited.
                if i > 0 && action.handler != SIG_DFL && read_mask() != host_mask(saved) {
                    crate::trap_fatal(
                        "a signal handler edited its frame's saved mask (uc_sigmask) while more \
                         frames of its delivery batch were still to run: not modeled",
                    );
                }
            }
            // The first member's frame saved `mask`: its `rt_sigreturn` left
            // that installed, or what its handler edited it to.
        });
        // Inner SIGSYS fixups may consume these bits while handlers run. The
        // enclosing frame still owns its changes, including the release mask.
        FRAME_DIRTY.with(|dirty| dirty.set(dirty.get() | outer_dirty | FRAME_MASK));
        RELEASING_FRAMES.with(|flag| flag.set(was_releasing));
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
        scope.close();
        fault::batch_returned();
        if trap_routed(SIGSEGV) && (RESTORED_SEGV.take() || restored & bit(SIGSEGV) != 0) {
            fault::set(SegvBlock::Yes);
        }
        let mask = with_segv(kept);
        let mut state = lock_state();
        let task = state.signals.tasks.get_mut(&me).unwrap();
        task.mask = mask;
        task.delivering -= 1;
    }
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
