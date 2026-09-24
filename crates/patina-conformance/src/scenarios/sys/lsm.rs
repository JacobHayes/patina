//! sys/lsm — the Linux Security Module attribute rows
//! (security/lsm_syscalls.c, security/security.c), which need no privilege.
//! Which modules run is the host's configuration (its boot's LSM list), so
//! the scenario asserts only what every configuration answers:
//!
//! * every size is a `u32` (the 6.9 fix "lsm: use 32-bit compatible data
//!   types in LSM syscalls", carried by Ubuntu's 6.8; the v6.8 tag had
//!   `size_t`): a size in memory is read and written as 4 bytes, a size
//!   argument's upper half is ignored;
//! * `lsm_list_modules` refuses a flag (`EINVAL`) and an unreadable size
//!   (`EFAULT`); into too little room it is `E2BIG` and writes the size
//!   needed; otherwise it answers the module count, writes 8 bytes per
//!   module, and lists the capability module (`LSM_ID_CAPABILITY`, 100),
//!   which every kernel runs;
//! * `lsm_get_self_attr` refuses `LSM_ATTR_UNDEF` and a NULL size
//!   (`EINVAL`), an unreadable size (`EFAULT`), a flag other than
//!   `LSM_FLAG_SINGLE` (`EINVAL`), and `LSM_FLAG_SINGLE` without a context
//!   or naming no module (`EINVAL`); an attribute no module answers, or a
//!   module no kernel has, is `EOPNOTSUPP` with size 0 written;
//! * `lsm_set_self_attr` refuses a flag (`EINVAL`), a size short of a
//!   context (`EINVAL`) or past a page (`E2BIG`), an unreadable context
//!   (`EFAULT`), a context whose lengths disagree (`EINVAL`), and a module
//!   no kernel has (`EOPNOTSUPP`).
//!
//! No call ever names a module that exists, so the probe's own attributes
//! (its AppArmor or SELinux label) never change.

use crate::catalog::{Arc, DEFAULTS, Gap, Scenario, Status};
use crate::compare::{Ending, Failure};
use crate::probe::{Probe, neg};
use crate::vehicle::Vehicle;
use libc::*;
use patina_dst_syscalls::Syscall;

const LSM_ID_CAPABILITY: u64 = 100;
/// No module has this id.
const NO_MODULE: u64 = 999;
const LSM_ATTR_UNDEF: i64 = 0;
const LSM_ATTR_CURRENT: i64 = 100;
/// No `LSM_ATTR_*` attribute.
const UNKNOWN_ATTR: i64 = 99;
const LSM_FLAG_SINGLE: i64 = 1;

/// `struct lsm_ctx` with no context bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct Context {
    id: u64,
    flags: u64,
    len: u64,
    ctx_len: u64,
}
const CONTEXT_SIZE: usize = std::mem::size_of::<Context>();

/// A `u32` size (the rows' width since the 6.9 fix "lsm: use 32-bit
/// compatible data types in LSM syscalls", which Ubuntu's 6.8 carries; the
/// v6.8 tag had `size_t`) followed by a guard word no call may touch. The
/// guard also makes an 8-byte read of the size far larger than the size.
#[repr(C)]
struct Size {
    size: u32,
    guard: u32,
}
const GUARD: u32 = 0xdead_beef;

impl Size {
    fn new(size: usize) -> Size {
        Size {
            size: size as u32,
            guard: GUARD,
        }
    }
}

/// An address no page is mapped at.
const UNMAPPED: usize = 8;

pub fn run(p: &Probe) {
    let mut ids = [0u64; 32];
    let mut size = Size::new(0);
    let list = |size: *mut Size, flags: i64| {
        p.call_observed(
            Syscall::N_lsm_list_modules,
            [ids.as_ptr() as i64, size as i64, flags, 0, 0, 0],
        )
    };
    p.check(
        "lsm_list_modules with a flag is EINVAL",
        list(&mut size, 1) == neg(EINVAL),
    );
    p.check(
        "an unreadable size is EFAULT",
        list(std::ptr::null_mut(), 0) == neg(EFAULT),
    );
    p.check(
        "too little room is E2BIG: the size is 32 bits wide, the guard word past it unread",
        list(&mut size, 0) == neg(E2BIG),
    );
    p.check("and unwritten", size.guard == GUARD);
    let needed = size.size as usize;
    size = Size::new(std::mem::size_of_val(&ids));
    let count = p.call_unrecorded(
        Syscall::N_lsm_list_modules,
        [
            ids.as_mut_ptr() as i64,
            &mut size as *mut Size as i64,
            0,
            0,
            0,
            0,
        ],
    );
    p.check(
        "the room needed is 8 bytes a module, and the list is written into it",
        count >= 1 && needed == count as usize * 8 && size.size as usize == needed,
    );
    p.check(
        "the capability module is listed",
        ids[..(count.max(0) as usize).min(ids.len())].contains(&LSM_ID_CAPABILITY),
    );

    let mut buf = [0u64; 64];
    let get = |attr: i64, ctx: *mut u64, size: *mut Size, flags: i64| {
        p.call_observed(
            Syscall::N_lsm_get_self_attr,
            [attr, ctx as i64, size as i64, flags, 0, 0],
        )
    };
    let room = std::mem::size_of_val(&buf);
    let mut size = Size::new(room);
    p.check(
        "lsm_get_self_attr of LSM_ATTR_UNDEF is EINVAL",
        get(LSM_ATTR_UNDEF, buf.as_mut_ptr(), &mut size, 0) == neg(EINVAL),
    );
    p.check(
        "a NULL size is EINVAL",
        get(LSM_ATTR_CURRENT, buf.as_mut_ptr(), std::ptr::null_mut(), 0) == neg(EINVAL),
    );
    p.check(
        "an unreadable size is EFAULT",
        get(LSM_ATTR_CURRENT, buf.as_mut_ptr(), UNMAPPED as *mut Size, 0) == neg(EFAULT),
    );
    p.check(
        "a flag other than LSM_FLAG_SINGLE is EINVAL",
        get(LSM_ATTR_CURRENT, buf.as_mut_ptr(), &mut size, 2) == neg(EINVAL),
    );
    p.check(
        "LSM_FLAG_SINGLE without a context is EINVAL",
        get(
            LSM_ATTR_CURRENT,
            std::ptr::null_mut(),
            &mut size,
            LSM_FLAG_SINGLE,
        ) == neg(EINVAL),
    );
    buf[0] = 0;
    p.check(
        "LSM_FLAG_SINGLE naming no module is EINVAL",
        get(
            LSM_ATTR_CURRENT,
            buf.as_mut_ptr(),
            &mut size,
            LSM_FLAG_SINGLE,
        ) == neg(EINVAL),
    );
    buf[0] = NO_MODULE;
    size = Size::new(room);
    p.check(
        "LSM_FLAG_SINGLE naming a module no kernel has is EOPNOTSUPP, size 0",
        get(
            LSM_ATTR_CURRENT,
            buf.as_mut_ptr(),
            &mut size,
            LSM_FLAG_SINGLE,
        ) == neg(EOPNOTSUPP)
            && size.size == 0
            && size.guard == GUARD,
    );
    size = Size::new(room);
    p.check(
        "an attribute no module answers is EOPNOTSUPP, size 0",
        get(UNKNOWN_ATTR, buf.as_mut_ptr(), &mut size, 0) == neg(EOPNOTSUPP)
            && size.size == 0
            && size.guard == GUARD,
    );

    let context = |len: u64| Context {
        id: NO_MODULE,
        flags: 0,
        len,
        ctx_len: 0,
    };
    let set = |ctx: *const Context, size: usize, flags: i64| {
        p.call_observed(
            Syscall::N_lsm_set_self_attr,
            [LSM_ATTR_CURRENT, ctx as i64, size as i64, flags, 0, 0],
        )
    };
    let whole = context(CONTEXT_SIZE as u64);
    p.check(
        "lsm_set_self_attr with a flag is EINVAL",
        set(&whole, CONTEXT_SIZE, 1) == neg(EINVAL),
    );
    p.check(
        "a size short of a context is EINVAL",
        set(&whole, 8, 0) == neg(EINVAL),
    );
    p.check(
        "a size past a page is E2BIG",
        set(&whole, 8192, 0) == neg(E2BIG),
    );
    p.check(
        "an unreadable context is EFAULT",
        set(std::ptr::null(), CONTEXT_SIZE, 0) == neg(EFAULT),
    );
    p.check(
        "a context shorter than its header is EINVAL",
        set(&context(8), CONTEXT_SIZE, 0) == neg(EINVAL),
    );
    p.check(
        "a module no kernel has is EOPNOTSUPP: the size is 32 bits wide, its upper half ignored",
        set(&whole, (1 << 32) | CONTEXT_SIZE, 0) == neg(EOPNOTSUPP),
    );
}

pub const SCENARIO: Scenario = Scenario {
    name: "sys/lsm",
    run,
    // glibc has no wrapper for these rows: the libc spelling would be
    // `syscall(2)` again.
    vehicles: Vehicle::KERNEL,
    covers: &[
        Syscall::N_lsm_list_modules,
        Syscall::N_lsm_get_self_attr,
        Syscall::N_lsm_set_self_attr,
    ],
    gaps: &[Gap {
        status: Status::Pending(Arc::Privileged),
        vehicles: Vehicle::KERNEL,
        what: "lsm_list_modules is a fatal privileged trap (patina-syscalls linux.rs Trap(TRAP_PRIVILEGED)), as are lsm_get_self_attr and lsm_set_self_attr, where the kernel answers any caller about its own attributes and the running modules",
        failure: Failure::Stops {
            events: 0,
            ending: Ending::Signal(SIGABRT),
            diagnostic: "patina: SUD trapped unsupported syscall lsm_list_modules (nr 461, class privileged",
        },
    }],
    ..DEFAULTS
};
