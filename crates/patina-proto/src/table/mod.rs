//! The syscall table as data.
//!
//! One file per class of call, so that later tasks add rows without
//! conflicts. Rows name calls (`nr::OPENAT`), so each is written once for every
//! architecture. Every number known to the kernel has a row: numbers without a
//! written row are `Stop`, and so is any number beyond the kernel's table.
//! A row is only built by `Row::new`, which requires a class, a strength and a
//! non-empty reason (checked at compile time, because the table is a `static`).
//! A row naming a call the architecture lacks is left out.

pub mod cmds;
pub mod nargs;

pub mod fd;
pub mod fs;
pub mod mem;
pub mod misc;
pub mod net;
pub mod proc;
pub mod sched;
pub mod sig;
pub mod time;

use super::nr;
pub use super::nr::{NAMES, NR_COUNT};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Pass,
    Virt,
    Attempt,
    Rewrite,
    Place,
    Deny(i32),
    Stop,
}

impl Class {
    /// Code stored in boundary records.
    pub const fn code(self) -> u8 {
        match self {
            Class::Pass => 1,
            Class::Virt => 2,
            Class::Attempt => 3,
            Class::Rewrite => 4,
            Class::Place => 5,
            Class::Deny(_) => 6,
            Class::Stop => 7,
        }
    }
    pub fn code_name(code: u8) -> &'static str {
        match code {
            1 => "Pass",
            2 => "Virt",
            3 => "Attempt",
            4 => "Rewrite",
            5 => "Place",
            6 => "Deny",
            7 => "Stop",
            _ => "-",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strength {
    /// C: computed by patina from the seed and earlier boundary events.
    Construction,
    /// A: computed by the kernel; hidden inputs argued away, then attacked.
    Argument,
    /// D: a known uncontrolled source, detected on replay or labelled.
    Detected,
}

impl Strength {
    pub fn letter(self) -> char {
        match self {
            Strength::Construction => 'C',
            Strength::Argument => 'A',
            Strength::Detected => 'D',
        }
    }
}

/// Which handler module of the runtime serves the row (one per table file).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Time,
    Mem,
    Fs,
    Fd,
    Sched,
    Sig,
    Proc,
    Net,
    Misc,
    /// The SDK channel (`crate::sdk`).
    Sdk,
}

/// Length rule of guest memory named by an argument. Every rule has an extent before the call
/// (what the kernel may touch, checked against the runtime's region before the call is
/// forwarded: rt `guest::names_runtime`) and, for `ins` and `outs`, an extent after it (what is
/// hashed into the boundary record). A rule applies only when the call reads its argument for
/// the values of the others (`nargs::live`): a pointer the call ignores is neither checked nor
/// hashed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Len {
    /// The return value, when positive; before the call, at most the value of argument `max`.
    Ret { max: u8 },
    /// The value of argument `n`.
    Arg(u8),
    /// A fixed size, when the call succeeded.
    Fixed(u32),
    /// The argument is an iovec array with the count in argument `cnt`; covers `ret` bytes in
    /// total (before the call: the array and every segment).
    IovRet { cnt: u8 },
    /// A NUL-terminated string (input only).
    CStr,
    /// The return value times a record size; before the call, argument `max` records.
    RetTimes { max: u8, size: u32 },
    /// The value of argument `arg` times a record size, when the call succeeded.
    ArgTimes { arg: u8, size: u32 },
    /// The argument is a `struct msghdr`; its iovec array covers `ret` bytes in total (before
    /// the call: the header, its name, iovec array, segments and control buffer).
    MsgIovRet,
    // Rules used only in `refs` (checked before the call, not hashed):
    /// An array of `struct mmsghdr`, the count in argument `cnt`; each one's message as
    /// `MsgIovRet`.
    Mmsg { cnt: u8 },
    /// A buffer whose length is the `u32` the pointer in argument `lenp` points at (indirect)
    /// (socket addresses with `socklen_t *`, `getsockopt`'s value).
    Indirect { lenp: u8 },
    /// An `fd_set` for the descriptor count in argument `nfds`.
    FdSet { nfds: u8 },
    /// `pselect6`'s `{ const sigset_t *, size_t }` pair and the set it points at.
    SigPair,
    /// `struct xattr_args` (`*xattrat`), its size in argument `size`, and the value it points at.
    XattrArgs { size: u8 },
    /// The arguments after a multiplexed call's command (`fcntl`, `ioctl`, `prctl`,
    /// `arch_prctl`), from the first (`Out::arg`) on, as the command's entry in `cmds` says.
    Command,
    /// `futex`'s words and timeout for the operations that read them.
    Futex,
    /// A NULL-terminated array of string pointers and the strings (`execve`'s `argv`, `envp`).
    StrVec,
}

/// A guest buffer: which argument holds the pointer and how long it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Out {
    pub arg: u8,
    pub len: Len,
}

pub const fn out(arg: u8, len: Len) -> Out {
    Out { arg, len }
}

#[derive(Clone, Copy, Debug)]
pub struct Row {
    pub nr: u32,
    pub name: &'static str,
    pub class: Class,
    pub strength: Strength,
    pub why: &'static str,
    /// Output buffers (hashed into `out_hash`).
    pub outs: &'static [Out],
    /// Input buffers (hashed into `in_hash`).
    pub ins: &'static [Out],
    /// Other guest memory the kernel reads or writes for the call (pointers inside structures,
    /// optional arguments, request-dependent ones): checked before the call like `ins` and
    /// `outs`, not hashed.
    pub refs: &'static [Out],
    /// Bit `i` set: argument `i` is a descriptor; hidden numbers give `EBADF` when the call
    /// reads it (`nargs::live`: `mmap` ignores the descriptor of an anonymous mapping).
    pub fds: u8,
    pub group: Group,
    /// false only for the generated `Stop` rows of numbers nobody has written yet.
    pub written: bool,
}

impl Row {
    pub const fn new(
        group: Group,
        nr: u64,
        class: Class,
        strength: Strength,
        why: &'static str,
    ) -> Row {
        assert!(!why.is_empty(), "every row needs a reason");
        if !nr::present(nr) {
            // The architecture lacks the call: `add` leaves the row out.
            return Row {
                nr: ABSENT,
                name: "",
                class,
                strength,
                why,
                outs: &[],
                ins: &[],
                refs: &[],
                fds: 0,
                group,
                written: false,
            };
        }
        assert!((nr as usize) < NR_COUNT, "number beyond the kernel's table");
        let name = match NAMES[nr as usize] {
            Some(n) => n,
            None => panic!("number not in the kernel headers"),
        };
        Row {
            nr: nr as u32,
            name,
            class,
            strength,
            why,
            outs: &[],
            ins: &[],
            refs: &[],
            fds: 0,
            group,
            written: true,
        }
    }
    pub const fn outs(mut self, outs: &'static [Out]) -> Row {
        assert!(hashable(outs), "a refs-only length rule in outs");
        self.outs = outs;
        self
    }
    pub const fn ins(mut self, ins: &'static [Out]) -> Row {
        assert!(hashable(ins), "a refs-only length rule in ins");
        self.ins = ins;
        self
    }
    pub const fn refs(mut self, refs: &'static [Out]) -> Row {
        self.refs = refs;
        self
    }
    /// Mark argument `i` as a descriptor.
    pub const fn fd(mut self, i: u8) -> Row {
        self.fds |= 1 << i;
        self
    }
    const fn unwritten(nr: usize) -> Row {
        Row {
            nr: nr as u32,
            name: match NAMES[nr] {
                Some(n) => n,
                None => "",
            },
            class: Class::Stop,
            strength: Strength::Construction,
            why: "No row written yet: the run ends as unsupported, naming the call.",
            outs: &[],
            ins: &[],
            refs: &[],
            fds: 0,
            group: Group::Misc,
            written: false,
        }
    }
}

/// Whether every rule can be hashed after the call (the boundary record's `ins` and `outs`).
const fn hashable(bufs: &[Out]) -> bool {
    let mut i = 0;
    while i < bufs.len() {
        if matches!(
            bufs[i].len,
            Len::Mmsg { .. }
                | Len::Indirect { .. }
                | Len::FdSet { .. }
                | Len::SigPair
                | Len::XattrArgs { .. }
                | Len::Command
                | Len::Futex
                | Len::StrVec
        ) {
            return false;
        }
        i += 1;
    }
    true
}

/// The `nr` of a row whose call the architecture lacks.
const ABSENT: u32 = u32::MAX;

static UNKNOWN: Row = Row {
    nr: u32::MAX,
    name: "unknown",
    class: Class::Stop,
    strength: Strength::Construction,
    why: "Not a syscall number known to the kernel headers: the run ends as unsupported.",
    outs: &[],
    ins: &[],
    refs: &[],
    fds: 0,
    group: Group::Misc,
    written: false,
};

const fn add(t: &mut [Row; NR_COUNT], rows: &[Row]) {
    let mut i = 0;
    while i < rows.len() {
        let r = rows[i];
        i += 1;
        if r.nr == ABSENT {
            continue;
        }
        assert!(!t[r.nr as usize].written, "two rows for one syscall");
        t[r.nr as usize] = r;
    }
}

const fn build() -> [Row; NR_COUNT] {
    let mut t = [Row::unwritten(0); NR_COUNT];
    let mut i = 0;
    while i < NR_COUNT {
        t[i] = Row::unwritten(i);
        i += 1;
    }
    add(&mut t, time::ROWS);
    add(&mut t, mem::ROWS);
    add(&mut t, fs::ROWS);
    add(&mut t, fd::ROWS);
    add(&mut t, sched::ROWS);
    add(&mut t, sig::ROWS);
    add(&mut t, proc::ROWS);
    add(&mut t, net::ROWS);
    add(&mut t, misc::ROWS);
    t
}

static TABLE: [Row; NR_COUNT] = build();

/// The SDK channel: one number beyond the kernel's table (`crate::sdk`).
pub static SDK_ROW: Row = Row {
    nr: crate::sdk::SYSCALL as u32,
    name: "patina_sdk",
    class: Class::Virt,
    strength: Strength::Construction,
    why: "The SDK channel: assertions, fault points, knobs, delays and marks, answered by the runtime from the seed and recorded; outside Patina the kernel answers ENOSYS.",
    // The payload's hash is the record's `in_hash`, computed by the handler from the copy it
    // validated (a bad pointer or length must not be read here).
    outs: &[],
    ins: &[],
    refs: &[],
    fds: 0,
    group: Group::Sdk,
    written: true,
};

/// The row for a syscall number. Unknown numbers map to a `Stop` row.
pub fn row(nr: u32) -> &'static Row {
    if (nr as usize) < NR_COUNT {
        &TABLE[nr as usize]
    } else if nr as u64 == crate::sdk::SYSCALL {
        &SDK_ROW
    } else {
        &UNKNOWN
    }
}

/// Every number the kernel headers know, in order, then the SDK channel.
pub fn known() -> impl Iterator<Item = &'static Row> {
    TABLE
        .iter()
        .filter(|r| NAMES[r.nr as usize].is_some())
        .chain(core::iter::once(&SDK_ROW))
}

/// Name for a number (or "unknown").
pub fn name(nr: u64) -> &'static str {
    if (nr as usize) < NR_COUNT {
        NAMES[nr as usize].unwrap_or("unknown")
    } else if nr == crate::sdk::SYSCALL {
        SDK_ROW.name
    } else {
        "unknown"
    }
}

// Shorthands for the per-class files.
pub(crate) use Class::{Attempt, Deny, Pass, Place, Rewrite, Virt};
pub(crate) use Strength::{Argument as A, Construction as C};

pub(crate) mod errno {
    pub const EPERM: i32 = 1;
    pub const ENOSYS: i32 = 38;
}
