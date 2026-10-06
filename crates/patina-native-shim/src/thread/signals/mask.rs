//! Host and guest signal masks, frames, and diagnostic writes.

use super::*;

// All host operations use the already-resolved syscall alias in glibc's allowed
// text region, never a guest-visible symbol or an inline syscall instruction.
pub(super) fn host(nr: i64, args: [u64; 6]) -> i64 {
    #[cfg(test)]
    tests::observe_host_call(nr, args);
    unsafe {
        crate::sud_host_syscall(
            nr,
            args[0] as i64,
            args[1] as i64,
            args[2] as i64,
            args[3] as i64,
            args[4] as i64,
            args[5] as i64,
        )
    }
}

pub(crate) fn host_mask(mask: u64) -> u64 {
    let mut mask = uncatchable(mask) & !bit(SIGSYS);
    if crate::PATINA_TSC_ARMED.load(Ordering::Relaxed) != 0 {
        mask &= !bit(SIGSEGV);
    }
    mask
}
/// The guest's view of a host mask this thread runs under: SIGSEGV, which the
/// host never blocks under the counter trap, is blocked where the guest has
/// it blocked ([`fault::blocked`]); an unknown block reads as unblocked, and
/// every reader it matters to names it.
pub(in crate::thread) fn with_segv(host: u64) -> u64 {
    host | segv_bit(segv_blocked())
}
pub(super) fn segv_blocked() -> SegvBlock {
    if trap_routed(SIGSEGV) {
        fault::blocked()
    } else {
        SegvBlock::No
    }
}
/// A mask the guest installs whole sets SIGSEGV's block.
pub(in crate::thread) fn set_segv(mask: u64) {
    if trap_routed(SIGSEGV) {
        fault::set(if mask & bit(SIGSEGV) != 0 {
            SegvBlock::Yes
        } else {
            SegvBlock::No
        });
    }
}
pub(super) fn segv_bit(blocked: SegvBlock) -> u64 {
    if blocked == SegvBlock::Yes {
        bit(SIGSEGV)
    } else {
        0
    }
}
pub(super) const SEGV_UNKNOWN: &str = "SIGSEGV's block is read below a SIGSEGV handler that blocks it: a \
                            handler still running and one left by siglongjmp cannot be told \
                            apart there";

pub(in crate::thread) fn read_mask() -> u64 {
    let mut mask = 0u64;
    if host(
        SYS_RT_SIGPROCMASK,
        [
            SIG_BLOCK as u64,
            0,
            &mut mask as *mut _ as u64,
            SIGSET_BYTES as u64,
            0,
            0,
        ],
    ) != 0
    {
        fatal("host signal mask query failed (rt_sigprocmask)");
    }
    mask
}
pub(in crate::thread) fn install_mask(mask: u64) {
    FRAME_DIRTY.with(|dirty| dirty.set(dirty.get() | FRAME_MASK));
    let mask = host_mask(mask);
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

pub(in crate::thread) fn activate() -> TaskId {
    let mut state = lock_state();
    if let Err(error) = state.ensure_active() {
        let _ = c_int::from(error.into_posix());
    }
    current_task()
}

#[unsafe(no_mangle)]
/// A SIGSYS frame's return: the mask a guest syscall installed, and the
/// private registration guest code runs under ([`frames`]).
/// # Safety
/// Pointers name the signal frame's mask and alternate-stack fields.
pub unsafe extern "C" fn patina_signal_frame(mask: *mut u64, stack: *mut Stack) {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let dirty = FRAME_DIRTY.with(|dirty| dirty.replace(0));
    if dirty & FRAME_MASK != 0 {
        unsafe {
            mask.write(read_mask());
        }
    }
    frames::trap_return(stack);
}

#[unsafe(no_mangle)]
/// A guest restorer's `rt_sigreturn` (both doors, `c/posix/init.c`): the frame
/// at `mask` is the guest's own, and the kernel installs its saved mask as the
/// return's. Keep the containment signals out of it, as every mask the guest
/// installs ([`host_mask`]); a frame that cannot be read is left to the
/// kernel's `rt_sigreturn`, which faults it as it would natively. Answers the
/// vehicle that issues the kernel's `rt_sigreturn`: glibc's real `syscall(2)`.
pub extern "C" fn patina_signal_return(mask: usize) -> usize {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    if let Ok(saved) = crate::uaccess::read::<u64>(mask) {
        let kept = host_mask(saved);
        if trap_routed(SIGSEGV) && saved & bit(SIGSEGV) != 0 {
            RESTORED_SEGV.set(true);
        }
        if kept != saved {
            containment_kept_unblocked(saved & !kept);
            if crate::uaccess::write(mask, &kept).is_err() {
                // Natively the kernel would install this mask: a read-only
                // frame that blocks a containment signal cannot be honoured.
                crate::trap_fatal(
                    "a guest rt_sigreturn frame blocks a containment signal (SIGSYS, or \
                     SIGSEGV under the timestamp-counter trap) and cannot be written to keep \
                     it unblocked",
                );
            }
        }
    }
    crate::hostapi::get().host_syscall as usize
}

/// A handler asked, through its frame's saved mask, to block a signal the
/// host must keep unblocked (`dropped`). SIGSEGV's block under the counter
/// trap is kept virtually ([`fault`]); SIGSYS stays unblocked, where natively
/// the handler's return would block it. Said once per run on the host's
/// stderr.
pub(super) fn containment_kept_unblocked(dropped: u64) {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if dropped & bit(SIGSYS) == 0 || SAID.swap(true, Ordering::Relaxed) {
        return;
    }
    let _ = crate::host_write_all(
        2,
        b"patina: a signal handler's frame mask blocks SIGSYS, which containment keeps \
          unblocked: the handler's return leaves it unblocked, where a native run would \
          block it\n",
    );
}

/// Write `bytes`, captured from the guest, through to the host's descriptor
/// `fd` with SIGPIPE held back: a host reader that went away is the host's
/// business, never the guest's, so the SIGPIPE the kernel sends this thread
/// for it is taken back before the mask is (a guest handler would otherwise
/// run inside shim code, or the default action end the run). Answers whether
/// the host reader is still there. Any other failure of the host write (a
/// descriptor the supervisor closed) is dropped, as the end-of-run flush
/// drops it.
pub(crate) fn write_through(fd: c_int, bytes: &[u8]) -> bool {
    // Called holding the capture's lock, which `fatal`'s flush would take.
    let refuse = || -> ! {
        let _ = crate::host_write_all(
            2,
            b"patina native shim fatal: host signal mask change around a captured write \
              failed (rt_sigprocmask)\n",
        );
        crate::host_abort()
    };
    let pipe = bit(SIGPIPE);
    let mut held = 0u64;
    if host(
        SYS_RT_SIGPROCMASK,
        [
            SIG_BLOCK as u64,
            &pipe as *const _ as u64,
            &mut held as *mut _ as u64,
            SIGSET_BYTES as u64,
            0,
            0,
        ],
    ) != 0
    {
        refuse();
    }
    let written = crate::host_write_all(fd, bytes);
    let gone = written.is_err_and(|error| error.raw_os_error() == Some(crate::EPIPE));
    if gone {
        let now = [0i64; 2];
        host(
            SYS_RT_SIGTIMEDWAIT,
            [
                &pipe as *const _ as u64,
                0,
                &now as *const _ as u64,
                SIGSET_BYTES as u64,
                0,
                0,
            ],
        );
    }
    if held & pipe == 0
        && host(
            SYS_RT_SIGPROCMASK,
            [
                SIG_SETMASK as u64,
                &held as *const _ as u64,
                0,
                SIGSET_BYTES as u64,
                0,
                0,
            ],
        ) != 0
    {
        refuse();
    }
    !gone
}
