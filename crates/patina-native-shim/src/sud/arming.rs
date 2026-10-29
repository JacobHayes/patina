//! Per-thread arming of the traps the main thread armed at startup
//! (`posix::lifecycle`): syscall-user-dispatch and the timestamp-counter trap.
//! Neither setting survives clone(2), so the main thread arms in
//! `__libc_start_main` and every managed thread arms itself before its guest
//! code runs. Both are no-ops on a run that did not arm them (a non-SUD
//! kernel, no `PR_SET_TSC`, a standalone binary, or a link without the POSIX
//! layer).
//!
//! What syscall-user-dispatch lets reach the host kernel untrapped is an
//! explicit contract, decided by what holds the thread, never by where a
//! call comes from. The kernel allows a system call made from its allowed
//! region and traps every other one (the selector byte, [`SELECTOR`], stays
//! blocking but for the brackets below):
//!
//! - **Guest code holds the thread**: the allowed region is the one
//!   system-call instruction of the vehicle a signal frame returns through
//!   ([`vehicle_syscall`]: glibc's `__restore_rt` on x86-64), which a SIGSYS
//!   handler's own return, and a guest handler's, take after the thread went
//!   back to guest code. Every other call traps wherever it is made: in the
//!   guest's executable, in glibc's internals a guest call reached
//!   (`getloadavg`'s read of `/proc/loadavg`, a lock's futex wait), in any
//!   shared library, or in a vDSO fallback.
//! - **The shim holds the thread**: the allowed region is glibc's text, so
//!   the host code the shim calls (glibc's functions, `std` through its host
//!   bindings) reaches the host, and guest code that host code calls back
//!   (glibc's internal `malloc` reaching the guest's allocator) still traps
//!   and nests in the shim's call. glibc code such a callback calls itself
//!   passes: a guest callback beneath the shim is not separately contained.
//! - **Between holds**: the C side's few host calls made while guest code
//!   holds the thread (a signal frame's stack switch, the fault stop) open
//!   the selector around themselves ([`patina_sud_host_open`]), as the
//!   region switch's own `prctl` does.
//!
//! `panic_boundary` reports every change of owner ([`follow`]); the region
//! changes with it, one `prctl` per change between guest and shim. The
//! vDSO's own answers are no system call and stay out of reach here
//! (`scrub_vdso` hides it from code that looks it up after startup; glibc
//! found it before).
use std::cell::Cell;
use std::ffi::{c_int, c_ulong};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// `prctl` SUD operations (6.8 UAPI headers may predate the constants).
pub(crate) const PR_SET_SYSCALL_USER_DISPATCH: c_int = 59;
const PR_SYS_DISPATCH_ON: c_ulong = 1;
/// The selector's two values (`SYSCALL_DISPATCH_FILTER_*`).
const FILTER_ALLOW: u8 = 0;
const FILTER_BLOCK: u8 = 1;

pub(crate) type Prctl = unsafe extern "C" fn(c_int, c_ulong, c_ulong, c_ulong, c_ulong) -> c_int;

/// glibc's `prctl`, resolved at startup through the private host resolver.
pub(crate) static PRCTL: AtomicUsize = AtomicUsize::new(0);
/// glibc's single executable segment (base, length): the allowed region
/// while the shim holds the thread.
pub(crate) static LIBC_TEXT: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];
/// The allowed region while guest code holds it (offset, length): the signal
/// return vehicle's system-call instruction, as the kernel sees it (the
/// address after the instruction).
pub(crate) static VEHICLE: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];
/// Set once the main thread armed SUD, and the counter trap: thread arming
/// follows these, not the exported trace-metadata flags.
pub(crate) static SUD: AtomicBool = AtomicBool::new(false);
pub(crate) static TSC: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// The byte the kernel reads on each of this thread's system calls
    /// outside the allowed region once it is armed.
    static SELECTOR: Cell<u8> = const { Cell::new(FILTER_BLOCK) };
    /// Whether this thread armed SUD: only an armed thread's region follows
    /// its owner.
    static ARMED: Cell<bool> = const { Cell::new(false) };
    /// Whether the region the kernel holds for this thread is the vehicle's
    /// (else glibc's text). Written after the `prctl` that set it, so a
    /// signal handler that interrupts a switch at worst repeats it.
    static VEHICLE_REGION: Cell<bool> = const { Cell::new(false) };
    /// Set once the thread's task completed ([`thread_completed`]).
    static COMPLETED: Cell<bool> = const { Cell::new(false) };
}

/// The resolved host `prctl`, if startup resolved it.
pub(crate) fn prctl() -> Option<Prctl> {
    let address = PRCTL.load(Ordering::Relaxed);
    // SAFETY: only ever stored from the resolved glibc `prctl`.
    (address != 0).then(|| unsafe { std::mem::transmute::<usize, Prctl>(address) })
}

/// The thread's owner changed (`panic_boundary`): `guest` while guest code
/// holds it. An armed thread's region follows.
#[inline(always)]
pub(crate) fn follow(guest: bool) {
    if !ARMED.with(Cell::get) {
        return;
    }
    let vehicle = guest && !COMPLETED.with(Cell::get);
    if VEHICLE_REGION.with(Cell::get) != vehicle {
        configure(vehicle);
    }
}

/// Arm syscall-user-dispatch on the calling thread over the vehicle's
/// instruction (`vehicle`) or glibc's text, with this thread's selector.
/// Fatal on failure: a thread left unarmed would make its guest's calls
/// silent escapes.
#[inline(never)]
fn configure(vehicle: bool) {
    let region = if vehicle { &VEHICLE } else { &LIBC_TEXT };
    let (offset, length) = (
        region[0].load(Ordering::Relaxed),
        region[1].load(Ordering::Relaxed),
    );
    let selector = SELECTOR.with(Cell::as_ptr) as c_ulong;
    // glibc's `prctl` is outside the vehicle's region.
    let previous = patina_sud_host_open();
    // SAFETY: the flag is set only after `prctl` resolved; the selector is
    // this thread's, live while the thread is.
    let armed = prctl().is_some_and(|prctl| unsafe {
        prctl(
            PR_SET_SYSCALL_USER_DISPATCH,
            PR_SYS_DISPATCH_ON,
            offset as c_ulong,
            length as c_ulong,
            selector,
        ) == 0
    });
    patina_sud_host_close(previous);
    if !armed {
        crate::trap_fatal("SUD: failed to arm syscall-user-dispatch on a managed thread");
    }
    VEHICLE_REGION.with(|region| region.set(vehicle));
}

/// Arm syscall-user-dispatch on the calling thread.
pub(crate) fn arm_sud() {
    if !SUD.load(Ordering::Relaxed) {
        return;
    }
    ARMED.with(|armed| armed.set(true));
    configure(!crate::panic_boundary::in_shim() && !COMPLETED.with(Cell::get));
}

/// The calling managed thread's task completed: what runs on it from here
/// is glibc's teardown of the host thread, which still calls guest code (its
/// `pthread_key_create` destructors, the C allocator's `free`) and makes its
/// own calls for no task. The region stays glibc's text for the rest of the
/// thread's life: glibc's own calls pass, and guest code's still trap.
pub(crate) fn thread_completed() {
    COMPLETED.with(|completed| completed.set(true));
    follow(!crate::panic_boundary::in_shim());
}

/// The C side's host system calls made outside any hold (a signal frame's
/// stack switch, the fault stop): the selector allows until
/// [`patina_sud_host_close`] puts back the answered value.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sud_host_open() -> u8 {
    SELECTOR.with(|selector| {
        let previous = selector.get();
        // SAFETY: this thread's own live byte.
        unsafe { selector.as_ptr().write_volatile(FILTER_ALLOW) };
        previous
    })
}

/// A guest signal handler runs from here (the C side's
/// `patina_run_guest_handler`): the selector blocks while it does, even when
/// its signal arrived inside a host call's allowance (the release whose
/// unblocking delivers it), and [`patina_sud_host_close`] puts back what the
/// interrupted code had once it returns.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sud_guest_open() -> u8 {
    SELECTOR.with(|selector| {
        let previous = selector.get();
        // SAFETY: this thread's own live byte.
        unsafe { selector.as_ptr().write_volatile(FILTER_BLOCK) };
        previous
    })
}

/// End [`patina_sud_host_open`]'s allowance, or [`patina_sud_guest_open`]'s
/// block: the selector is `previous` again.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sud_host_close(previous: u8) {
    // SAFETY: this thread's own live byte.
    SELECTOR.with(|selector| unsafe { selector.as_ptr().write_volatile(previous) });
}

core::arch::global_asm!(
    ".hidden patina_sud_host_open",
    ".hidden patina_sud_host_close",
    ".hidden patina_sud_guest_open"
);

/// Where the kernel sees the signal return vehicle's system call (the
/// address after its instruction), from the vehicle's leading bytes `code`
/// at `vehicle`. On x86-64 the vehicle is glibc's `__restore_rt`, every
/// frame's restorer: `mov $15, %rax` (or `%eax`) then `syscall`. On arm64 the
/// kernel returns its own frames through the vDSO, exempt from dispatch, and
/// a guest frame's return goes through glibc's `syscall(2)`: its `svc #0`.
/// None for any other code: arming fails closed rather than allow an
/// instruction it did not recognize.
#[cfg(any(test, patina_posix_exports))]
pub(crate) fn vehicle_syscall(code: &[u8], vehicle: usize) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        const SYSCALL: [u8; 2] = [0x0f, 0x05];
        let mov = [
            &[0x48, 0xc7, 0xc0, 0x0f, 0x00, 0x00, 0x00][..],
            &[0xb8, 0x0f, 0x00, 0x00, 0x00][..],
        ];
        let body = code
            .strip_prefix(&[0xf3, 0x0f, 0x1e, 0xfa][..])
            .unwrap_or(code);
        let skipped = code.len() - body.len();
        mov.iter().find_map(|mov| {
            let rest = body.strip_prefix(*mov)?;
            rest.starts_with(&SYSCALL)
                .then(|| vehicle + skipped + mov.len() + SYSCALL.len())
        })
    }
    #[cfg(target_arch = "aarch64")]
    {
        const SVC: [u8; 4] = 0xd400_0001u32.to_le_bytes();
        code.as_chunks::<4>()
            .0
            .iter()
            .position(|word| *word == SVC)
            .map(|at| vehicle + 4 * (at + 1))
    }
}

/// How many leading bytes of the vehicle [`vehicle_syscall`] reads.
#[cfg(patina_posix_exports)]
pub(crate) const VEHICLE_CODE: usize = 32;

/// Arm the timestamp-counter trap on the calling thread.
pub(crate) fn arm_tsc() {
    if !TSC.load(Ordering::Relaxed) {
        return;
    }
    // SAFETY: as above.
    let armed = prctl().is_some_and(|prctl| unsafe {
        prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV as c_ulong, 0, 0, 0) == 0
    });
    if !armed {
        crate::trap_fatal("TSC: failed to arm the timestamp-counter trap on a managed thread");
    }
}

/// The prefixed ABI's re-arm (`patina_native.h`): a no-op unless the run
/// armed SUD.
#[unsafe(no_mangle)]
pub extern "C" fn patina_sud_arm_thread() {
    let _panic_scope = crate::panic_boundary::PanicScope::enter();
    arm_sud();
}

/// One /proc/self/maps line's executable mapping: its span and path.
#[cfg(any(test, patina_posix_exports))]
fn executable_mapping(line: &[u8]) -> Option<(usize, usize, &[u8])> {
    let hex = |field: &[u8]| {
        let digits = field
            .iter()
            .take_while(|byte| byte.is_ascii_hexdigit())
            .count();
        let value = field[..digits].iter().fold(0usize, |value, &byte| {
            (value << 4) | (byte as char).to_digit(16).unwrap_or(0) as usize
        });
        (value, digits)
    };
    let (start, length) = hex(line);
    let rest = line[length..].strip_prefix(b"-")?;
    let (end, length) = hex(rest);
    let perms = rest[length..].strip_prefix(b" ")?;
    // perms are exactly 4 characters, e.g. "r-xp".
    if perms.len() < 3 || perms[2] != b'x' {
        return None;
    }
    let path = line
        .iter()
        .position(|&byte| byte == b'/')
        .map_or(&[][..], |at| &line[at..]);
    Some((start, end, path))
}

/// The spans a /proc/self/maps image names, each `[start, end)`.
#[cfg_attr(not(any(test, patina_posix_exports)), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Regions {
    /// The executable mapping holding the marker: the main executable's text,
    /// which guest, shim and std share.
    pub text: [usize; 2],
    /// glibc's single executable segment.
    pub libc: [usize; 2],
    /// The dynamic loader's executable segment, if one is mapped (a static
    /// binary has none).
    pub loader: Option<[usize; 2]>,
}

/// The [`Regions`] of a /proc/self/maps image whose main-executable text
/// holds `marker`. None unless exactly one libc segment and the text were
/// found (and at most one loader segment): arming fails closed rather than
/// guess a region.
#[cfg(any(test, patina_posix_exports))]
pub(crate) fn maps_regions(maps: &[u8], marker: usize) -> Option<Regions> {
    let (mut text, mut libc, mut segments) = (None, [0; 2], 0);
    let (mut loader, mut loaders) = (None, 0);
    for line in maps.split(|&byte| byte == b'\n') {
        let Some((start, end, path)) = executable_mapping(line) else {
            continue;
        };
        if (start..end).contains(&marker) {
            text = Some([start, end]);
        }
        // libc by the mapped path's basename. `libc-` is the legacy glibc
        // spelling (libc-2.31.so), so it must be followed by the version
        // digit: a guest binary named `libc-something` is not glibc, and
        // counting it would refuse the whole run on a name.
        let base = path.rsplit(|&byte| byte == b'/').next().unwrap_or(path);
        if path.is_empty() {
            continue;
        }
        if base.starts_with(b"libc.so.6")
            || base
                .strip_prefix(b"libc-")
                .is_some_and(|rest| rest.first().is_some_and(u8::is_ascii_digit))
        {
            segments += 1;
            libc = [start, end];
        }
        // The loader is the interpreter glibc names `ld-linux-<arch>.so.N`
        // (`ld-linux.so.2`, legacy `ld-2.31.so`).
        if base.starts_with(b"ld-linux")
            || base
                .strip_prefix(b"ld-")
                .is_some_and(|rest| rest.first().is_some_and(u8::is_ascii_digit))
        {
            loaders += 1;
            loader = Some([start, end]);
        }
    }
    (segments == 1 && loaders <= 1)
        .then_some(())
        .and(text)
        .map(|text| Regions { text, libc, loader })
}

#[cfg(test)]
mod tests {
    use super::Regions;

    #[test]
    fn maps_name_the_text_holding_the_marker_glibc_and_the_loader_by_basename() {
        let maps = [
            &b"55d0c0000000-55d0c0100000 r-xp 00001000 08:01 12 /work/libc-tool\n"[..],
            b"7f0000000000-7f0000028000 r--p 00000000 08:01 45 /usr/lib/libc.so.6\n",
            b"7f0000028000-7f00001bd000 r-xp 00028000 08:01 45 /usr/lib/libc.so.6\n",
            b"7f1000001000-7f1000027000 r-xp 00001000 08:01 46 /usr/lib/ld-linux-x86-64.so.2\n",
            b"7ffd00000000-7ffd00002000 r-xp 00000000 00:00 0 [vdso]\n",
        ]
        .concat();
        let marker = 0x55d0_c000_1000;
        let regions = Regions {
            text: [0x55d0_c000_0000, 0x55d0_c010_0000],
            libc: [0x7f00_0002_8000, 0x7f00_001b_d000],
            loader: Some([0x7f10_0000_1000, 0x7f10_0002_7000]),
        };
        assert_eq!(super::maps_regions(&maps, marker), Some(regions));
        // The legacy spelling is glibc too, and two segments refuse.
        let legacy = b"7f1000028000-7f10001bd000 r-xp 00028000 08:01 46 /lib/libc-2.31.so";
        assert_eq!(
            super::maps_regions(&[&maps[..], legacy].concat(), marker),
            None
        );
        assert_eq!(super::maps_regions(&maps, 0x1000), None);
        // A static binary maps no loader.
        let alone: Vec<u8> = maps
            .split_inclusive(|&byte| byte == b'\n')
            .filter(|line| !line.ends_with(b".so.2\n"))
            .flatten()
            .copied()
            .collect();
        let found = super::maps_regions(&alone, marker).unwrap();
        assert_eq!(found.loader, None);
    }

    /// The vehicle's system call is found after either `mov` of 15 (behind an
    /// `endbr64` or not), and any other code is refused.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_vehicle_syscall_is_recognized_only_after_a_sigreturn_number() {
        let wide = [0x48, 0xc7, 0xc0, 0x0f, 0, 0, 0, 0x0f, 0x05, 0x90];
        assert_eq!(super::vehicle_syscall(&wide, 0x1000), Some(0x1009));
        let narrow = [0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0x0f, 0, 0, 0, 0x0f, 0x05];
        assert_eq!(super::vehicle_syscall(&narrow, 0x1000), Some(0x100b));
        let other = [0x48, 0xc7, 0xc0, 0x27, 0, 0, 0, 0x0f, 0x05, 0x90];
        assert_eq!(super::vehicle_syscall(&other, 0x1000), None);
    }

    /// The vehicle's system call is the address after its first `svc #0`,
    /// and code without one is refused.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn the_vehicle_syscall_is_the_first_supervisor_call() {
        let words = |words: &[u32]| {
            words
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>()
        };
        let nop = 0xd503_201f;
        let svc = 0xd400_0001;
        let code = words(&[nop, nop, svc, svc]);
        assert_eq!(super::vehicle_syscall(&code, 0x1000), Some(0x100c));
        assert_eq!(super::vehicle_syscall(&words(&[nop, nop]), 0x1000), None);
    }
}
