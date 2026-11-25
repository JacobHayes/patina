//! The commands of the multiplexed calls the runtime passes or answers (`fcntl`, `ioctl`,
//! `prctl`, `arch_prctl`), each with the arguments it reads after the command, from the
//! kernel's handler for that command (Linux 7.0: `fs/fcntl.c` `do_fcntl`, `fs/ioctl.c`
//! `do_vfs_ioctl`, `kernel/sys.c` `prctl`, `arch/x86/kernel/process_64.c` `do_arch_prctl_64`).
//!
//! One list per call is three things at once, so that a command cannot be let through
//! without saying what it reads: the allowlist (the runtime refuses a command the list lacks,
//! rt `sys::fd`, `sys::proc`), the arguments the boundary record keeps (`nargs::live`: a
//! command's unread registers hold whatever the program left there) and the pointers the
//! containment check follows (`Len::Command`, rt `guest::names_runtime`).

/// What a command does with one argument register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Use {
    /// A number: flags, a descriptor, a size, an address the call acts on.
    Value,
    /// A pointer to this many bytes, read or written.
    Ptr(u32),
    /// A pointer to a NUL-terminated string (at most a path's length), or NULL.
    CStr,
    /// `FIDEDUPERANGE`'s `struct file_dedupe_range`: a 24-byte header, then `dest_count`
    /// (the `u16` at offset 16) 32-byte records.
    DedupeRange,
}

/// A command and the arguments after it that it reads, in order; the registers after the
/// last one are not read.
#[derive(Clone, Copy, Debug)]
pub struct Cmd {
    pub cmd: u64,
    pub args: &'static [Use],
}

const fn c(cmd: u64, args: &'static [Use]) -> Cmd {
    Cmd { cmd, args }
}

use Use::*;

const NONE: &[Use] = &[];
const VALUE: &[Use] = &[Value];
const INT: &[Use] = &[Ptr(4)];
/// `struct flock` (the same 32 bytes on x86_64 and arm64).
const FLOCK: &[Use] = &[Ptr(32)];
const U64: &[Use] = &[Ptr(8)];

/// `fcntl(fd, cmd, arg)`: `arg` is argument 2.
pub static FCNTL: &[Cmd] = &[
    c(0, VALUE),    // F_DUPFD
    c(1, NONE),     // F_GETFD
    c(2, VALUE),    // F_SETFD
    c(3, NONE),     // F_GETFL
    c(4, VALUE),    // F_SETFL
    c(5, FLOCK),    // F_GETLK
    c(6, FLOCK),    // F_SETLK
    c(7, FLOCK),    // F_SETLKW
    c(36, FLOCK),   // F_OFD_GETLK
    c(37, FLOCK),   // F_OFD_SETLK
    c(38, FLOCK),   // F_OFD_SETLKW
    c(1027, VALUE), // F_DUPFD_QUERY: another descriptor
    c(1030, VALUE), // F_DUPFD_CLOEXEC
    c(1031, VALUE), // F_SETPIPE_SZ
    c(1032, NONE),  // F_GETPIPE_SZ
    c(1033, VALUE), // F_ADD_SEALS
    c(1034, NONE),  // F_GET_SEALS
    c(1035, U64),   // F_GET_RW_HINT
    c(1036, U64),   // F_SET_RW_HINT
    c(1037, U64),   // F_GET_FILE_RW_HINT
    c(1038, U64),   // F_SET_FILE_RW_HINT
];

/// `ioctl(fd, request, arg)`: `arg` is argument 2; requests are compared on their low 32 bits
/// (the kernel's `unsigned int cmd`). Terminal requests (type `'T'`) are answered `ENOTTY`
/// without reading `arg` and are not listed.
pub static IOCTL: &[Cmd] = &[
    c(0x541b, INT),                 // FIONREAD
    c(0x5421, INT),                 // FIONBIO
    c(0x5450, NONE),                // FIONCLEX
    c(0x5451, NONE),                // FIOCLEX
    c(0x4004_9409, VALUE),          // FICLONE: the source descriptor
    c(0x4020_940d, &[Ptr(32)]),     // FICLONERANGE
    c(0xc018_9436, &[DedupeRange]), // FIDEDUPERANGE
    c(0x8008_6601, INT),            // FS_IOC_GETFLAGS (an int, whatever the request's size says)
    c(0x801c_581f, &[Ptr(28)]),     // FS_IOC_FSGETXATTR
    c(2, INT),                      // FIGETBSZ
];

/// `PR_SET_VMA`: its sub-option is the only one with arguments after it (`nargs::live`).
pub const PR_SET_VMA: u64 = 0x5356_4d41;
/// `PR_SET_VMA_ANON_NAME`, the only sub-option of `PR_SET_VMA`.
pub const PR_SET_VMA_ANON_NAME: u64 = 0;

/// `prctl(option, arg2, arg3, arg4, arg5)`: `arg2` is argument 1.
pub static PRCTL: &[Cmd] = &[
    c(1, VALUE),                                 // PR_SET_PDEATHSIG
    c(2, INT),                                   // PR_GET_PDEATHSIG
    c(3, NONE),                                  // PR_GET_DUMPABLE
    c(15, &[Ptr(16)]),                           // PR_SET_NAME
    c(16, &[Ptr(16)]),                           // PR_GET_NAME
    c(25, INT),                                  // PR_GET_TSC
    c(26, VALUE),                                // PR_SET_TSC
    c(36, NONE),                                 // PR_SET_CHILD_SUBREAPER: answered EINVAL
    c(PR_SET_VMA, &[Value, Value, Value, CStr]), // sub-option, address, size, name
];

/// `arch_prctl(code, addr)`: `addr` is argument 1.
pub static ARCH_PRCTL: &[Cmd] = &[
    c(0x1001, VALUE), // ARCH_SET_GS
    c(0x1002, VALUE), // ARCH_SET_FS
    c(0x1003, U64),   // ARCH_GET_FS
    c(0x1004, U64),   // ARCH_GET_GS
];

#[inline]
fn find(list: &'static [Cmd], cmd: u64) -> Option<&'static Cmd> {
    list.iter().find(|e| e.cmd == cmd)
}

#[inline]
pub fn fcntl(cmd: u64) -> Option<&'static Cmd> {
    if cmd <= 7 {
        return Some(&FCNTL[cmd as usize]);
    }
    find(&FCNTL[8..], cmd)
}

#[inline]
pub fn ioctl(request: u64) -> Option<&'static Cmd> {
    find(IOCTL, request & 0xffff_ffff)
}

#[inline]
pub fn prctl(option: u64) -> Option<&'static Cmd> {
    find(PRCTL, option)
}

#[inline]
pub fn arch_prctl(code: u64) -> Option<&'static Cmd> {
    find(ARCH_PRCTL, code)
}

/// For a multiplexed call: the index of its first argument after the command, and what the
/// command (`a`'s selecting argument) reads from there on. `None` for other calls; an empty
/// list for a command the runtime does not let through (it reads nothing more).
#[inline]
pub fn args_of(nr: u64, a: &[u64; 6]) -> Option<(usize, &'static [Use])> {
    let (first, e) = match nr {
        super::nr::FCNTL => (2, fcntl(a[1])),
        super::nr::IOCTL => (2, ioctl(a[1])),
        super::nr::PRCTL => (1, prctl(a[0])),
        super::nr::ARCH_PRCTL => (1, arch_prctl(a[0])),
        _ => return None,
    };
    Some((first, e.map_or(NONE, |e| e.args)))
}
