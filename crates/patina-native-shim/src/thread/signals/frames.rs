//! Private signal frames (Linux). Every host signal handler the shim owns
//! (the syscall trap, the counter trap, the front handler that runs a guest's
//! handler) is installed `SA_ONSTACK`, and the host alternate stack of every
//! managed thread is a guarded mapping of the shim's own, registered
//! `SS_AUTODISARM`. So the kernel builds each of those frames (siginfo,
//! ucontext and the CPU's extended state) there, never on the guest's stack:
//! a trapped raw syscall or counter read uses no guest stack at all, and a
//! guest handler runs on the stack it asked for (its alternate stack under
//! `SA_ONSTACK`, else the interrupted one) with only the shim's 16-byte slot,
//! and on x86-64 a return address, above its own frames: 24 to 39 bytes
//! (x86-64; 16 to 31 on arm64) from the stack's top or the red zone's
//! bottom, as alignment falls. A kernel frame's size depends on the host
//! CPU's xsave area; keeping it private keeps the guest's stack use the same
//! on every host.
//!
//! **The guest's alternate stack** is virtual: the registration a guest makes
//! (`sigaltstack`, `uc_stack` at a handler's return) is kept here, per host
//! thread, with 6.8's rules (`do_sigaltstack`, `__save_altstack`,
//! `restore_altstack`), and never reaches the host.
//!
//! **Levels.** The private stack is [`RECORDS`] + 1 levels of one fixed
//! budget each. A trap from guest code lands at the top of the level the host
//! registration names, and everything the shim runs for it stays in that
//! level. When a trap runs a guest handler, the handler's [`Record`] owns
//! that level while it runs, and the registration names the highest level no
//! running handler owns, where every trap the handler takes lands; at the
//! handler's return the kernel's `rt_sigreturn` installs the registration its
//! frame names. So a handler's frames are never built over, whatever its
//! guest code does meanwhile: a handler may swapcontext to a coroutine on any
//! stack (a local array of a caller, an `alloca`, a mapping) and come back,
//! which is what `SS_AUTODISARM` exists for.
//!
//! A handler that leaves by `siglongjmp` (or `setcontext`) abandons its
//! frame and skips that return, so its level is freed only on proof that it
//! was left, which no stack pointer gives (a coroutine may run anywhere): the
//! word the shim wrote to its slot overwritten, found at each trap from guest
//! code and before a libc door delivers ([`resync`]), or a later delivery
//! whose slot overlaps its own ([`enter`]). Until then its level stays
//! reserved: at worst the named stop at [`RECORDS`] running handlers, the
//! same on every host, recording or not. A handler left over and over from
//! the same place frees the level of the last one each time, so the levels
//! alternate and nothing accumulates.
//!
//! A handler left in shapes that give no such proof keeps its level: leaving
//! by `siglongjmp` from ever shallower points of one stack, whose slots
//! nothing writes again, stops by name after [`RECORDS`] such handlers where
//! natively it runs on. A jump's target above a slot is no proof either (the
//! guest's `siglongjmp` is glibc's, not the shim's, and even seen, it would
//! prove nothing): a coroutine stack carved from a frame above the handler
//! is above its slot, and a handler on an alternate stack left for an older
//! context can still be resumed from its coroutine and return.
//!
//! **Guards.** While a running handler owns a level, the bottom page of the
//! level directly above it is inaccessible, so shim code overrunning its own
//! level faults there instead of writing over the suspended handler's
//! frames. The fault cannot be a named stop: it happens with the stack
//! pointer at the guard, where the kernel cannot build the SIGSEGV's frame,
//! so the kernel kills the run with SIGSEGV. The level budget
//! (`native_containment::private_signal_stack_levels_fit_their_budget`) keeps
//! that from happening.
use super::*;
use std::cell::RefCell;

/// `SS_ONSTACK`, `SS_AUTODISARM` (`<linux/signal.h>`).
pub(super) const SS_ONSTACK: i32 = 1;
pub(super) const SS_AUTODISARM: i32 = i32::MIN;
const ENOMEM: i32 = 12;
/// The architecture's `MINSIGSTKSZ`, which `sigaltstack` requires.
#[cfg(target_arch = "x86_64")]
const MINSIGSTKSZ: usize = 2048;
#[cfg(target_arch = "aarch64")]
const MINSIGSTKSZ: usize = 5120;
/// The x86-64 ABI's red zone below the interrupted stack pointer, which the
/// kernel steps over before building a frame on the interrupted stack.
#[cfg(target_arch = "x86_64")]
const RED_ZONE: usize = 128;
#[cfg(target_arch = "aarch64")]
const RED_ZONE: usize = 0;
/// The private stack one level may use besides the kernel's frame (at most
/// `AT_MINSIGSTKSZ`): a trap's dispatch (tens of KiB when recording), a
/// delivery's front handler, and the margin below its frame.
/// `native_containment::private_signal_stack_levels_fit_their_budget`
/// measures it.
pub(crate) const NESTED_MIN: usize = 128 * 1024;
/// How many guest handlers one thread can have running at once. The private
/// stack holds one level more, where the traps of the innermost run.
const RECORDS: usize = 64;
/// `PATINA_FRAME_MARGIN` (`c/posix/init.c`): the C front handler's frame is
/// this far above the floor it reports.
const FRAME_MARGIN: usize = 4096;

#[derive(Clone, Copy)]
struct Private {
    base: usize,
    size: usize,
    page: usize,
    /// The budget of one level: [`NESTED_MIN`] and a kernel frame.
    level: usize,
}

/// A guest handler running from a private frame.
#[derive(Clone, Copy)]
struct Record {
    /// The shim's 16-byte slot on the guest stack, right above the
    /// handler's frames.
    slot: usize,
    /// What the shim wrote to the slot's first word.
    value: u64,
    /// The level of the private stack its frame is in.
    level: usize,
}

struct Records {
    live: [Option<Record>; RECORDS],
    depth: usize,
    next: u64,
}

thread_local! {
    static PRIVATE: Cell<Option<Private>> = const { Cell::new(None) };
    /// The guest's alternate stack registration (`sas_ss_sp`, `sas_ss_size`,
    /// `sas_ss_flags`); a new thread has none.
    static GUEST: Cell<Stack> = const {
        Cell::new(Stack { base: 0, flags: SS_DISABLE, size: 0 })
    };
    /// Bit `m`: the bottom page of level `m - 1` is a guard, because a
    /// running handler owns level `m`.
    static GUARDED: Cell<u128> = const { Cell::new(0) };
    static LIVE: RefCell<Records> = const {
        RefCell::new(Records { live: [None; RECORDS], depth: 0, next: 0x7e5c_a1ab_1e00_0001 })
    };
}

/// The kernel's `on_sig_stack` test against one stack.
fn on(sp: usize, (base, size): (usize, usize)) -> bool {
    sp > base && sp - base <= size
}

/// Whether this thread's shim handlers build their frames privately.
pub(super) fn armed() -> bool {
    PRIVATE.get().is_some()
}

/// Whether `sp` is on this thread's private stack: shim code runs there.
pub(super) fn private_contains(sp: usize) -> bool {
    PRIVATE
        .get()
        .is_some_and(|private| on(sp, (private.base, private.size)))
}

/// The highest level (0 at the private stack's top) no running handler owns.
fn free_level(owned: impl Iterator<Item = usize> + Clone) -> usize {
    (0..=RECORDS)
        .find(|level| !owned.clone().any(|owner| owner == *level))
        .expect("one level more than running handlers")
}

/// The host registration guest code runs under: the highest level no running
/// handler owns.
fn registration() -> Option<Stack> {
    let private = PRIVATE.get()?;
    let level = LIVE.with_borrow(|live| {
        free_level(
            live.live[..live.depth]
                .iter()
                .flatten()
                .map(|record| record.level),
        )
    });
    Some(Stack {
        base: private.base + private.size - (level + 1) * private.level,
        flags: SS_AUTODISARM,
        size: private.level,
    })
}

/// Raise the guard above each level a running handler owns, and lower the
/// rest ([`GUARDED`]).
fn sync_guards() {
    let Some(private) = PRIVATE.get() else {
        return;
    };
    let owned = LIVE.with_borrow(|live| {
        live.live[..live.depth]
            .iter()
            .flatten()
            .fold(0u128, |owned, record| owned | 1 << record.level)
    }) & !1;
    let changed = owned ^ GUARDED.get();
    if changed == 0 {
        return;
    }
    let end = private.base + private.size;
    for level in (1..=RECORDS).filter(|level| changed & 1 << level != 0) {
        // The bottom page of the level above: PROT_NONE, or read-write again.
        let page = end - level * private.level;
        let protection = if owned & 1 << level != 0 { 0 } else { 3 };
        if host(
            patina_dst_syscalls::Syscall::N_mprotect.number().into(),
            [page as u64, private.page as u64, protection, 0, 0, 0],
        ) != 0
        {
            fatal("host private signal stack guard failed (mprotect)");
        }
    }
    GUARDED.set(owned);
}

fn install(stack: &Stack) {
    if host(SYS_SIGALTSTACK, [stack as *const _ as u64, 0, 0, 0, 0, 0]) != 0 {
        fatal("host private signal stack install failed (sigaltstack)");
    }
}

/// Map and register this thread's private stack, before any guest code runs
/// on it. Idempotent.
pub(crate) fn arm() {
    if armed() {
        return;
    }
    use patina_dst_syscalls::Syscall;
    const AT_PAGESZ: u64 = 6;
    const AT_MINSIGSTKSZ: u64 = 51;
    let page = crate::sud::auxv_value(AT_PAGESZ).expect("host page size") as usize;
    let minimum = crate::sud::auxv_value(AT_MINSIGSTKSZ).unwrap_or(0) as usize;
    let level = (NESTED_MIN + minimum).div_ceil(page) * page;
    let size = (RECORDS + 1) * level;
    let length = size + 2 * page;
    // PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE (reserved, not
    // committed: a level's pages are touched only as deep as it goes). Host
    // aliases only: this mapping never enters the guest's mapping tables.
    let base = host(
        Syscall::N_mmap.number().into(),
        [0, length as u64, 0, 0x4022, u64::MAX, 0],
    );
    if base < 0 {
        fatal("host private signal stack allocation failed (mmap)");
    }
    let base = base as usize + page;
    if host(
        Syscall::N_mprotect.number().into(),
        [base as u64, size as u64, 3, 0, 0, 0],
    ) != 0
    {
        fatal("host private signal stack protection failed (mprotect)");
    }
    PRIVATE.set(Some(Private {
        base,
        size,
        page,
        level,
    }));
    install(&registration().expect("armed"));
}

/// The thread is done with guest code: unregister and unmap its private
/// stack, unless it is running on it (a raw `exit` the syscall trap serves),
/// which the host thread's end then leaves mapped.
pub(crate) fn release() {
    let Some(private) = PRIVATE.get() else {
        return;
    };
    let here = 0u8;
    if private_contains(std::hint::black_box(&here) as *const u8 as usize) {
        return;
    }
    PRIVATE.set(None);
    // Nothing of the thread's guest handlers outlives it: a trap after this
    // (a thread-local destructor's raw syscall) has no private frames.
    LIVE.with_borrow_mut(|live| {
        live.live = [None; RECORDS];
        live.depth = 0;
    });
    GUEST.set(Stack::default());
    GUARDED.set(0);
    install(&Stack::default());
    if host(
        patina_dst_syscalls::Syscall::N_munmap.number().into(),
        [
            (private.base - private.page) as u64,
            (private.size + 2 * private.page) as u64,
            0,
            0,
            0,
            0,
        ],
    ) != 0
    {
        fatal("host private signal stack release failed (munmap)");
    }
}

/// The calling thread's private signal stack, for the containment tests'
/// budget detector (a shim built with `planted-faults`): its base, its size
/// and one level's budget, written to `out[0..3]`. Answers -1 on a thread
/// without one.
///
/// # Safety
/// `out` is writable for three words.
#[cfg(feature = "planted-faults")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn patina_planted_private_stack(out: *mut usize) -> i32 {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    let Some(private) = PRIVATE.get() else {
        return -1;
    };
    // SAFETY: the caller's three words.
    unsafe {
        out.write(private.base);
        out.add(1).write(private.size);
        out.add(2).write(private.level);
    }
    0
}

/// The guest code an interrupted stack pointer stands for: shim code on the
/// private stack runs for the guest code of the entry it serves.
pub(super) fn guest_position(sp: usize) -> usize {
    if private_contains(sp) {
        crate::panic_boundary::guest_entry().0
    } else {
        sp
    }
}

// ---- The guest's alternate stack (6.8 `kernel/signal.c`). ----

/// `on_sig_stack`: never while the registration is `SS_AUTODISARM`.
fn on_guest(stack: Stack, sp: usize) -> bool {
    stack.flags & SS_AUTODISARM == 0 && on(sp, (stack.base, stack.size))
}

/// `sas_ss_flags`.
fn sas_flags(stack: Stack, sp: usize) -> i32 {
    if stack.size == 0 {
        SS_DISABLE
    } else if on_guest(stack, sp) {
        SS_ONSTACK
    } else {
        0
    }
}

/// `do_sigaltstack` for guest code at `sp`: answers the old registration as
/// `sigaltstack` reports it, and applies `new`, or the errno refusing it.
fn altstack(stack: &mut Stack, new: Option<Stack>, sp: usize) -> Result<Stack, i32> {
    let old = Stack {
        flags: sas_flags(*stack, sp) | (stack.flags & SS_AUTODISARM),
        ..*stack
    };
    let Some(new) = new else {
        return Ok(old);
    };
    if on_guest(*stack, sp) {
        return Err(EPERM);
    }
    let mode = new.flags & !SS_AUTODISARM;
    if !matches!(mode, SS_DISABLE | SS_ONSTACK | 0) {
        return Err(EINVAL);
    }
    if *stack == new {
        return Ok(old);
    }
    *stack = if mode == SS_DISABLE {
        Stack {
            base: 0,
            flags: new.flags,
            size: 0,
        }
    } else if new.size < MINSIGSTKSZ {
        return Err(ENOMEM);
    } else {
        new
    };
    Ok(old)
}

/// The guest's `sigaltstack` at `sp`.
pub(super) fn sigaltstack(new: Option<Stack>, sp: usize) -> Result<Stack, i32> {
    let mut stack = GUEST.get();
    let old = altstack(&mut stack, new, sp)?;
    GUEST.set(stack);
    Ok(old)
}

/// The guest's registration as the kernel stores it.
pub(super) fn guest_stack() -> Stack {
    GUEST.get()
}

// ---- Handler records. ----

/// Whether `record`'s handler was provably left: the word the shim wrote to
/// its slot is gone (guest code ran over it).
fn left(record: &Record) -> bool {
    !crate::uaccess::read::<u64>(record.slot).is_ok_and(|value| value == record.value)
}

/// Drop the records whose handlers were provably left. Answers whether any
/// were.
fn drop_left() -> bool {
    LIVE.with_borrow_mut(|live| {
        let depth = live.depth;
        let mut kept = 0;
        for index in 0..depth {
            let record = live.live[index].expect("live record");
            if left(&record) {
                continue;
            }
            live.live[kept] = Some(record);
            kept += 1;
        }
        live.live[kept..depth].fill(None);
        live.depth = kept;
        kept != depth
    })
}

/// A trap interrupted guest code (never shim code): drop the records of the
/// handlers it has provably left, and if any were, make the trap's frame
/// (`stack`, its `uc_stack`) restore the registration the rest leave.
pub(super) fn resync(stack: *mut Stack) {
    if !armed() || stack.is_null() || LIVE.with_borrow(|live| live.depth) == 0 {
        return;
    }
    if drop_left() {
        sync_guards();
        // SAFETY: the trap frame's `uc_stack`.
        unsafe { stack.write(registration().expect("armed")) };
    }
}

/// Shim code serving guest code on the guest's own stack (a libc door's,
/// before it delivers): drop the records of the handlers that guest code
/// has provably left and install at once the registration the rest leave.
/// A delivery whose handlers leave by `siglongjmp` never returns through a
/// trap that would.
pub(super) fn resync_on_guest_stack() {
    if !armed() || LIVE.with_borrow(|live| live.depth) == 0 {
        return;
    }
    let here = 0u8;
    if private_contains(std::hint::black_box(&here) as *const u8 as usize) {
        return;
    }
    if drop_left() {
        sync_guards();
        install(&registration().expect("armed"));
    }
}

/// Where a guest handler runs, and what the shim holds meanwhile.
pub(super) struct Entered {
    /// The guest stack pointer the handler is called at (16-byte aligned):
    /// the shim's slot is the 16 bytes there.
    pub(super) slot: usize,
    /// The host registration while it runs.
    pub(super) nested: Stack,
    /// The registration the kernel saves in the handler's frame
    /// (`uc_stack`).
    pub(super) saved: Stack,
}

/// A guest handler with `flags` is about to run for a delivery that
/// interrupted guest code at `sp`, from a private frame whose C handler's
/// frame stands [`FRAME_MARGIN`] above `floor`. Chooses its stack as
/// `get_sigframe` and `sigsp` do, applies `SS_AUTODISARM` as
/// `__save_altstack` does, and records it as owning the level its frame is
/// in. `None` where this thread has no private stack: the handler runs where
/// the frame is. A guest stack the slot cannot be written to is the kernel's
/// failed frame setup: the default SIGSEGV.
pub(super) fn enter(flags: u64, sp: usize, floor: usize) -> Option<Entered> {
    let private = PRIVATE.get()?;
    let saved = GUEST.get();
    // `get_sigframe`: past the red zone, then the alternate stack if the
    // action asks for it and that point is not on it already.
    let below = sp - RED_ZONE;
    let top = if flags & SA_ONSTACK != 0 && sas_flags(saved, below) == 0 {
        saved.base + saved.size
    } else {
        below
    };
    if saved.flags & SS_AUTODISARM != 0 {
        GUEST.set(Stack::default());
    }
    let slot = (top - 16) & !15;
    // x86-64's call pushes the handler's return address right below the
    // slot; arm64's leaves it in the link register.
    #[cfg(target_arch = "x86_64")]
    let (low, pushed) = (slot - 8, true);
    #[cfg(not(target_arch = "x86_64"))]
    let (low, pushed) = (slot, false);
    let value = LIVE.with_borrow_mut(|live| {
        live.next = live.next.wrapping_add(2);
        live.next
    });
    if crate::uaccess::write(slot, &[value, 0]).is_err()
        || (pushed && crate::uaccess::write(low, &0u64).is_err())
    {
        fault::take_default(SIGSEGV);
    }
    // The level this delivery's frames are in. They were built from its
    // top: they fit it only if the floor is in it too.
    let end = private.base + private.size;
    let frame = floor + FRAME_MARGIN;
    let level = end.saturating_sub(frame) / private.level;
    if frame > end || level > RECORDS || floor <= end - (level + 1) * private.level {
        crate::trap_fatal(
            "a signal's shim frames outgrew their level of the private signal stack: not \
             modeled",
        );
    }
    LIVE.with_borrow_mut(|live| {
        // An older record whose slot this delivery just overwrote was left
        // (by `siglongjmp`, say): its handler's frames are where this one's
        // go.
        let depth = live.depth;
        let mut kept = 0;
        for index in 0..depth {
            let record = live.live[index].expect("live record");
            if record.slot + 16 > low && record.slot < slot + 16 {
                continue;
            }
            live.live[kept] = Some(record);
            kept += 1;
        }
        live.live[kept..depth].fill(None);
        live.depth = kept;
        if live.live[..kept]
            .iter()
            .flatten()
            .any(|record| record.level == level)
        {
            crate::trap_fatal(
                "a trap landed in a level of the private signal stack a running handler owns: \
                 shim state is corrupt",
            );
        }
        if kept == RECORDS {
            crate::trap_fatal(
                "more signal handlers running at once on one thread than the shim tracks: not \
                 modeled",
            );
        }
        live.live[kept] = Some(Record { slot, value, level });
        live.depth += 1;
    });
    sync_guards();
    Some(Entered {
        slot,
        nested: registration().expect("armed"),
        saved,
    })
}

/// The handler whose slot is `slot` returned into the shim: drop its record,
/// and install the registration its frame's `uc_stack` holds now
/// (`restore_altstack`: a handler may edit it) for the guest code it resumes
/// at `sp`, ignoring a refusal as 6.8 does. Handlers it ran that have not
/// returned (suspended in a coroutine, say) keep theirs.
pub(super) fn leave(slot: usize, restored: Stack, sp: usize) {
    LIVE.with_borrow_mut(|live| {
        if let Some(index) = live.live[..live.depth]
            .iter()
            .rposition(|record| record.is_some_and(|record| record.slot == slot))
        {
            live.live.copy_within(index + 1..live.depth, index);
            live.depth -= 1;
            let depth = live.depth;
            live.live[depth] = None;
        }
    });
    sync_guards();
    let mut stack = GUEST.get();
    let _ = altstack(&mut stack, Some(restored), sp);
    GUEST.set(stack);
}

/// The registration a private frame's return must install for the context
/// it resumes, interrupted at `sp`: the one the kernel saved (`host`) for
/// shim code on the private stack, else the one guest code runs under.
pub(super) fn frame_return(sp: usize, host: Stack) -> Stack {
    if private_contains(sp) {
        host
    } else {
        registration().unwrap_or(host)
    }
}

/// The registration a syscall trap's frame restores: the one guest code
/// runs under.
pub(super) fn trap_return(stack: *mut Stack) {
    if let Some(registration) = registration() {
        // SAFETY: the trap frame's `uc_stack`.
        unsafe { stack.write(registration) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stack(base: usize, size: usize, flags: i32) -> Stack {
        Stack { base, flags, size }
    }

    /// 6.8's `do_sigaltstack`: the old registration with `SS_ONSTACK` where
    /// the caller runs on it (never under `SS_AUTODISARM`), `EPERM` for a
    /// change made from it, `EINVAL` for an unknown mode, `ENOMEM` below
    /// `MINSIGSTKSZ`, and a disabled one forgets its range.
    #[test]
    fn the_guest_registration_follows_do_sigaltstack() {
        let alt = stack(0x10_000, 0x4000, 0);
        let mut current = Stack::default();
        assert_eq!(
            altstack(&mut current, None, 0x1_000_000),
            Ok(Stack::default())
        );
        assert_eq!(
            altstack(&mut current, Some(alt), 0x1_000_000),
            Ok(Stack::default())
        );
        assert_eq!(current, alt);
        let inside = 0x12_000;
        assert_eq!(
            altstack(&mut current, None, inside).map(|old| old.flags),
            Ok(SS_ONSTACK)
        );
        assert_eq!(
            altstack(&mut current, Some(Stack::default()), inside),
            Err(EPERM)
        );
        assert_eq!(
            altstack(
                &mut current,
                Some(stack(0x20_000, 0x4000, 0x4000)),
                0x1_000_000
            ),
            Err(EINVAL)
        );
        assert_eq!(
            altstack(
                &mut current,
                Some(stack(0x20_000, MINSIGSTKSZ - 1, 0)),
                0x1_000_000
            ),
            Err(ENOMEM)
        );
        assert_eq!(current, alt);
        let disarming = stack(0x10_000, 0x4000, SS_AUTODISARM);
        assert!(altstack(&mut current, Some(disarming), 0x1_000_000).is_ok());
        assert_eq!(
            altstack(&mut current, None, inside).map(|old| old.flags),
            Ok(SS_AUTODISARM),
            "an SS_AUTODISARM stack is never reported in use"
        );
        assert!(altstack(&mut current, Some(Stack::default()), inside).is_ok());
        assert_eq!(current, stack(0, 0, SS_DISABLE));
        assert_eq!(
            altstack(&mut current, None, inside).map(|old| old.flags),
            Ok(SS_DISABLE)
        );
    }

    /// A handler record is left only once the word the shim wrote to its
    /// slot is gone: no stack pointer is proof, since the handler may be
    /// suspended in a coroutine on any stack.
    #[test]
    fn a_record_is_left_only_when_its_slot_is_overwritten() {
        let mut words = [0u64; 4];
        let slot = words.as_mut_ptr() as usize;
        // SAFETY: a word of `words`.
        unsafe { (slot as *mut u64).write(0x5eed) };
        let record = Record {
            slot,
            value: 0x5eed,
            level: 0,
        };
        assert!(!left(&record));
        // SAFETY: as above.
        unsafe { (slot as *mut u64).write(0x5eee) };
        assert!(left(&record));
    }

    /// The registration names the highest level no running handler owns,
    /// so a handler left and reentered from one place alternates two levels.
    #[test]
    fn the_registration_is_the_highest_free_level() {
        assert_eq!(free_level([].into_iter()), 0);
        assert_eq!(free_level([0].into_iter()), 1);
        assert_eq!(free_level([1].into_iter()), 0);
        assert_eq!(free_level([0, 2, 1].into_iter()), 3);
        assert_eq!(free_level(0..RECORDS), RECORDS);
    }
}
