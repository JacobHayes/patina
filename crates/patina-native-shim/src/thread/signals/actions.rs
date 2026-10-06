//! Signal actions, masks, pending sets, and alternate stacks.

use super::*;

/// Libc-layout marshalling supplies glibc's init-time restorer; raw callers keep
/// their exact flags/restorer. Both doors perform one install through the core.
/// # Safety
/// Non-null pointers name readable/writable kernel action records.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_action_libc(
    sig: i32,
    action: *const Action,
    old: *mut Action,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let converted = if action.is_null() {
        None
    } else {
        Some(unsafe { *action })
    };
    #[cfg(target_arch = "x86_64")]
    let converted = converted.map(|mut action| {
        if action.flags & SA_RESTORER == 0 {
            action.restorer = RESTORER.load(Ordering::Relaxed);
            if action.restorer == 0 {
                fatal("glibc signal restorer was not captured at init");
            }
            action.flags |= SA_RESTORER;
        }
        action
    });
    unsafe {
        patina_signal_action(
            sig,
            converted.as_ref().map_or(std::ptr::null(), |action| action),
            old,
            SIGSET_BYTES,
        )
    }
}

/// Kernel-layout action entry shared by both syscall doors.
/// # Safety
/// Non-null pointers must name readable/writable kernel sigaction structures.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_action(
    sig: i32,
    action: *const Action,
    old: *mut Action,
    size: usize,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // `rt_sigaction`: the size, then the new action copied in, then the
    // signal judged; the old action is copied out once the new one took.
    if size != SIGSET_BYTES {
        return -i64::from(EINVAL);
    }
    let action = if action.is_null() {
        None
    } else {
        match crate::uaccess::read::<Action>(action as usize) {
            // Installed and stored with the flag bits 6.8 keeps.
            Ok(action) => Some(Action {
                flags: action.flags & UAPI_SA_FLAGS,
                ..action
            }),
            Err(_) => return -i64::from(EFAULT),
        }
    };
    if !(1..=SIGNAL_MAX).contains(&sig)
        || (action.is_some() && matches!(sig as u8, SIGKILL | SIGSTOP))
    {
        return -i64::from(EINVAL);
    }
    // Rust std performs registration before a deferred harness installs Context.
    // Dispositions are unrecorded process state; do not activate the scheduler.
    let mut state = lock_state();
    let previous = state.signals.actions[sig as usize];
    if let Some(action) = action {
        // A trap-routed action stays virtual: the host keeps the trap's
        // handler, which runs this one for each fault it does not answer. A
        // front-routed one too: the host keeps the front handler, with this
        // action's flags, mask and restorer.
        let rc = install_host_action(sig as u8, action);
        if rc != 0 {
            return -i64::from(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or_else(|| fatal("host signal syscall failed without errno")),
            );
        }
        state.signals.action(sig as u8, action);
    }
    drop(state);
    if !old.is_null() && crate::uaccess::write(old as usize, &previous).is_err() {
        return -i64::from(EFAULT);
    }
    0
}

/// # Safety
/// The optional mask pointers must be valid for eight bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_mask(
    how: i32,
    set: *const u64,
    old: *mut u64,
    size: usize,
) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // `rt_sigprocmask`: the size, then the new set copied in, then `how`
    // judged; the old set is copied out once the new one took.
    if size != SIGSET_BYTES {
        return -i64::from(EINVAL);
    }
    let set = if set.is_null() {
        None
    } else {
        match crate::uaccess::read::<u64>(set as usize) {
            Ok(set) => Some(set),
            Err(_) => return -i64::from(EFAULT),
        }
    };
    if set.is_some() && !matches!(how, SIG_BLOCK | SIG_UNBLOCK | SIG_SETMASK) {
        return -i64::from(EINVAL);
    }
    let me = activate();
    let previous = read_mask();
    let segv = segv_blocked();
    if !old.is_null() && segv == SegvBlock::Unknown {
        crate::trap_fatal(SEGV_UNKNOWN);
    }
    let old_value = previous | segv_bit(segv);
    let (mask, segv) = match set {
        None => (previous, segv),
        Some(set) => {
            // SIGSEGV's block is the guest's own under the counter trap.
            let named = set & bit(SIGSEGV) != 0;
            let segv = match how {
                SIG_BLOCK if named => SegvBlock::Yes,
                SIG_UNBLOCK if named => SegvBlock::No,
                SIG_SETMASK if named => SegvBlock::Yes,
                SIG_SETMASK => SegvBlock::No,
                _ => segv,
            };
            if trap_routed(SIGSEGV) && (named || how == SIG_SETMASK) {
                fault::set(segv);
            }
            let mask = host_mask(match how {
                SIG_BLOCK => previous | set,
                SIG_UNBLOCK => previous & !set,
                _ => set,
            });
            (mask, segv)
        }
    };
    lock_state().signals.tasks.get_mut(&me).unwrap().mask = mask | segv_bit(segv);
    install_mask(mask);
    if !old.is_null() && crate::uaccess::write(old as usize, &old_value).is_err() {
        return -i64::from(EFAULT);
    }
    0
}

/// # Safety
/// `set` must be writable for `size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_pending(set: *mut u8, size: usize) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if size > SIGSET_BYTES {
        return -i64::from(EINVAL);
    }
    let me = activate();
    super::timers::fire_due();
    let segv = segv_blocked();
    let mask = read_mask() | segv_bit(segv);
    let mut state = lock_state();
    state.signals.tasks.get_mut(&me).unwrap().mask = mask;
    if segv == SegvBlock::Unknown
        && (state.signals.tasks[&me].private.mask() | state.signals.shared.mask()) & bit(SIGSEGV)
            != 0
    {
        drop(state);
        crate::trap_fatal(SEGV_UNKNOWN);
    }
    let pending = state.signals.pending(me).to_ne_bytes();
    drop(state);
    if crate::uaccess::write_bytes(set as usize, &pending[..size]).is_err() {
        return -i64::from(EFAULT);
    }
    0
}

/// # Safety
/// Stack pointers must be valid Linux stack_t buffers when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_signal_altstack(stack: *const Stack, old: *mut Stack) -> i64 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    // One managed task per host thread. Where the thread's shim handlers
    // build their frames privately the registration is virtual
    // ([`frames`]), judged at the guest code's stack pointer; elsewhere (no
    // C layer) the kernel is the store and validator. Startup stack
    // registration requires no Context/scheduler either way.
    // `sigaltstack`: the new stack copied in first, once.
    let stack = if stack.is_null() {
        None
    } else {
        match crate::uaccess::read::<Stack>(stack as usize) {
            Ok(stack) => Some(stack),
            Err(_) => return -i64::from(EFAULT),
        }
    };
    let previous = if frames::armed() {
        match frames::sigaltstack(stack, crate::panic_boundary::guest_entry().0) {
            Ok(previous) => previous,
            Err(errno) => return -i64::from(errno),
        }
    } else {
        let mut previous = Stack::default();
        let rc = host(
            SYS_SIGALTSTACK,
            [
                stack.as_ref().map_or(0, |stack| stack as *const _ as u64),
                &mut previous as *mut _ as u64,
                0,
                0,
                0,
                0,
            ],
        );
        if rc != 0 {
            return -(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_else(|| fatal("host signal syscall failed without errno"))
                as i64);
        }
        previous
    };
    // The new stack took, whether or not the old one can be copied out.
    if let Some(stack) = stack {
        if trap_routed(SIGSEGV) {
            fault::registered(stack);
        }
    }
    if !old.is_null() && crate::uaccess::write(old as usize, &previous).is_err() {
        return -i64::from(EFAULT);
    }
    0
}
