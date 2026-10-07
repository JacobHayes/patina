//! Per-thread arming of the traps the main thread armed at startup
//! (`posix::lifecycle`): syscall-user-dispatch and the timestamp-counter trap.
//! Neither setting survives clone(2), so the main thread arms in
//! `__libc_start_main` and every managed thread arms itself before its guest
//! code runs. Both are no-ops on a run that did not arm them (a non-SUD
//! kernel, no `PR_SET_TSC`, a standalone binary, or a link without the POSIX
//! layer).
use std::ffi::{c_int, c_ulong};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// `prctl` SUD operations (6.8 UAPI headers may predate the constants).
pub(crate) const PR_SET_SYSCALL_USER_DISPATCH: c_int = 59;
const PR_SYS_DISPATCH_ON: c_ulong = 1;

pub(crate) type Prctl = unsafe extern "C" fn(c_int, c_ulong, c_ulong, c_ulong, c_ulong) -> c_int;

/// glibc's `prctl`, resolved at startup through the private host resolver.
pub(crate) static PRCTL: AtomicUsize = AtomicUsize::new(0);
/// glibc's single executable segment (base, length): where SUD allows syscalls.
pub(crate) static LIBC_TEXT: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];
/// Set once the main thread armed SUD, and the counter trap: thread arming
/// follows these, not the exported trace-metadata flags.
pub(crate) static SUD: AtomicBool = AtomicBool::new(false);
pub(crate) static TSC: AtomicBool = AtomicBool::new(false);

/// The resolved host `prctl`, if startup resolved it.
pub(crate) fn prctl() -> Option<Prctl> {
    let address = PRCTL.load(Ordering::Relaxed);
    // SAFETY: only ever stored from the resolved glibc `prctl`.
    (address != 0).then(|| unsafe { std::mem::transmute::<usize, Prctl>(address) })
}

/// Arm syscall-user-dispatch on the calling thread over glibc's text.
pub(crate) fn arm_sud() {
    if !SUD.load(Ordering::Relaxed) {
        return;
    }
    let (base, length) = (
        LIBC_TEXT[0].load(Ordering::Relaxed),
        LIBC_TEXT[1].load(Ordering::Relaxed),
    );
    // SAFETY: the flag is set only after `prctl` resolved.
    let armed = prctl().is_some_and(|prctl| unsafe {
        prctl(
            PR_SET_SYSCALL_USER_DISPATCH,
            PR_SYS_DISPATCH_ON,
            base as c_ulong,
            length as c_ulong,
            0,
        ) == 0
    });
    if !armed {
        crate::trap_fatal("SUD: failed to arm syscall-user-dispatch on a managed thread");
    }
}

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

/// The spans a /proc/self/maps image names, each `[start, end)`: the
/// executable mapping holding `marker` (the main executable's text, which
/// guest, shim and std share) and glibc's single executable segment. None
/// unless exactly one libc segment and the text were found: arming fails
/// closed rather than guess a region.
#[cfg(any(test, patina_posix_exports))]
pub(crate) fn maps_regions(maps: &[u8], marker: usize) -> Option<([usize; 2], [usize; 2])> {
    let (mut text, mut libc, mut segments) = (None, [0; 2], 0);
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
        if !path.is_empty()
            && (base.starts_with(b"libc.so.6")
                || base
                    .strip_prefix(b"libc-")
                    .is_some_and(|rest| rest.first().is_some_and(u8::is_ascii_digit)))
        {
            segments += 1;
            libc = [start, end];
        }
    }
    (segments == 1)
        .then_some(())
        .and(text)
        .map(|text| (text, libc))
}

#[cfg(test)]
mod tests {
    #[test]
    fn maps_name_the_text_holding_the_marker_and_glibc_by_basename() {
        let maps = [
            &b"55d0c0000000-55d0c0100000 r-xp 00001000 08:01 12 /work/libc-tool\n"[..],
            b"7f0000000000-7f0000028000 r--p 00000000 08:01 45 /usr/lib/libc.so.6\n",
            b"7f0000028000-7f00001bd000 r-xp 00028000 08:01 45 /usr/lib/libc.so.6\n",
            b"7ffd00000000-7ffd00002000 r-xp 00000000 00:00 0 [vdso]\n",
        ]
        .concat();
        let marker = 0x55d0_c000_1000;
        let text = [0x55d0_c000_0000, 0x55d0_c010_0000];
        let libc = [0x7f00_0002_8000, 0x7f00_001b_d000];
        assert_eq!(super::maps_regions(&maps, marker), Some((text, libc)));
        // The legacy spelling is glibc too, and two segments refuse.
        let legacy = b"7f1000028000-7f10001bd000 r-xp 00028000 08:01 46 /lib/libc-2.31.so";
        assert_eq!(
            super::maps_regions(&[&maps[..], legacy].concat(), marker),
            None
        );
        assert_eq!(super::maps_regions(&maps, 0x1000), None);
    }
}
