//! The syscall table as data.
//!
//! One file per class of call, so that later tasks add rows without
//! conflicts. Every number known to the kernel headers has a row: numbers
//! without a written row are `Stop`, and so is any number beyond the headers.
//! A row is only built by `Row::new`, which requires a class, a strength and a
//! non-empty reason (checked at compile time, because the table is a `static`).

mod names;
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

pub use names::{NAMES, NR_COUNT};

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
}

/// Length rule of a guest buffer named by an argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Len {
    /// The return value, when positive.
    Ret,
    /// The value of argument `n`.
    Arg(u8),
    /// A fixed size, when the call succeeded.
    Fixed(u32),
    /// The argument is an iovec array with the count in argument `cnt`; covers `ret` bytes in total.
    IovRet { cnt: u8 },
    /// A NUL-terminated string (input only).
    CStr,
    /// The return value times a record size.
    RetTimes(u32),
    /// The value of argument `arg` times a record size, when the call succeeded.
    ArgTimes { arg: u8, size: u32 },
    /// The argument is a `struct msghdr`; its iovec array covers `ret` bytes in total.
    MsgIovRet,
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
    /// Bit `i` set: argument `i` is a descriptor; hidden numbers give `EBADF`.
    pub fds: u8,
    pub group: Group,
    /// false only for the generated `Stop` rows of numbers nobody has written yet.
    pub written: bool,
}

impl Row {
    pub const fn new(
        group: Group,
        nr: u32,
        class: Class,
        strength: Strength,
        why: &'static str,
    ) -> Row {
        assert!(!why.is_empty(), "every row needs a reason");
        assert!((nr as usize) < NR_COUNT, "number beyond the kernel headers");
        let name = match NAMES[nr as usize] {
            Some(n) => n,
            None => panic!("number not in the kernel headers"),
        };
        Row {
            nr,
            name,
            class,
            strength,
            why,
            outs: &[],
            ins: &[],
            fds: 0,
            group,
            written: true,
        }
    }
    pub const fn outs(mut self, outs: &'static [Out]) -> Row {
        self.outs = outs;
        self
    }
    pub const fn ins(mut self, ins: &'static [Out]) -> Row {
        self.ins = ins;
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
            fds: 0,
            group: Group::Misc,
            written: false,
        }
    }
}

static UNKNOWN: Row = Row {
    nr: u32::MAX,
    name: "unknown",
    class: Class::Stop,
    strength: Strength::Construction,
    why: "Not a syscall number known to the kernel headers: the run ends as unsupported.",
    outs: &[],
    ins: &[],
    fds: 0,
    group: Group::Misc,
    written: false,
};

const fn add(t: &mut [Row; NR_COUNT], rows: &[Row]) {
    let mut i = 0;
    while i < rows.len() {
        let r = rows[i];
        assert!(!t[r.nr as usize].written, "two rows for one syscall");
        t[r.nr as usize] = r;
        i += 1;
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

/// The row for a syscall number. Unknown numbers map to a `Stop` row.
pub fn row(nr: u32) -> &'static Row {
    if (nr as usize) < NR_COUNT {
        &TABLE[nr as usize]
    } else {
        &UNKNOWN
    }
}

/// Every number the kernel headers know, in order.
pub fn known() -> impl Iterator<Item = &'static Row> {
    TABLE.iter().filter(|r| NAMES[r.nr as usize].is_some())
}

/// Name for a number (or "unknown").
pub fn name(nr: u64) -> &'static str {
    if (nr as usize) < NR_COUNT {
        NAMES[nr as usize].unwrap_or("unknown")
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
