//! The IPC rows: System V shared memory, semaphores and message queues, and
//! POSIX message queues — all within one process (and its threads), the
//! semantics the owner decision models (docs/arcs/syscall-conformance.md §2).
//!
//! Identifiers the kernel allocates (`shmid`, `semid`, `msqid`) are recorded
//! by relation (`Norm::Relative`), keys by the scenario's label, and the
//! `IPC_STAT` members that are kernel facts rather than host facts: sizes,
//! counts, permission bits, the creator's and last operator's identities by
//! relation. Timestamps are not recorded: a clock's absolute reading is the
//! host's business, and a virtual realtime clock that starts at the epoch
//! legitimately stamps 0. A scenario relates each stamp to [`Window`]s it
//! reads through its own door.

use super::{Probe, printable};
use crate::observe::{Id, Norm};
use crate::record::EventBuilder;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

/// A System V IPC key and the label a stream records for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    pub raw: i32,
    pub label: &'static str,
}

impl Key {
    pub const PRIVATE: Key = Key {
        raw: libc::IPC_PRIVATE,
        label: "IPC_PRIVATE",
    };
}

/// The fourth argument of `semctl` as a scenario means it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemArg {
    /// No argument (`IPC_RMID`, `GETVAL`, `GETPID`, …, an unknown command).
    None,
    /// `SETVAL`'s value.
    Val(i32),
    /// `GETALL` into a vector of this many values.
    GetAll(usize),
    /// `SETALL` from these values.
    SetAll(Vec<u16>),
    /// `IPC_STAT` into a `semid_ds`.
    Stat,
    /// `IPC_SET` of the caller's own owner with this mode.
    SetMode(u32),
}

/// The argument of `shmctl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShmArg {
    /// A NULL buffer (`IPC_RMID`, an unknown command).
    None,
    /// `IPC_STAT` into a `shmid_ds`.
    Stat,
    /// `IPC_SET` of the caller's own owner with this mode.
    SetMode(u32),
}

/// The argument of `msgctl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgArg {
    None,
    /// `IPC_STAT` into a `msqid_ds`.
    Stat,
    /// `IPC_SET` of the caller's own owner with this mode and `msg_qbytes`.
    Set {
        mode: u32,
        qbytes: u64,
    },
}

/// An absolute `CLOCK_REALTIME` deadline of the `mq_timed*` rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deadline {
    /// A NULL timeout: block without limit.
    Forever,
    /// The epoch: long past.
    Epoch,
    /// `tv_nsec` of one second: invalid.
    BadNsec,
    /// This many nanoseconds after the current `CLOCK_REALTIME`.
    After(i64),
}

impl Deadline {
    fn label(self) -> String {
        match self {
            Deadline::Forever => "NULL".to_string(),
            Deadline::Epoch => "epoch".to_string(),
            Deadline::BadNsec => "tv_nsec=1e9".to_string(),
            Deadline::After(ns) => format!("now+{ns}ns"),
        }
    }

    /// The absolute timespec, reading `CLOCK_REALTIME` through the probe's
    /// own door (unrecorded), the clock the kernel (or patina) judges it by.
    fn timespec(self, p: &Probe) -> Option<libc::timespec> {
        const NANOS: i64 = 1_000_000_000;
        match self {
            Deadline::Forever => None,
            Deadline::Epoch => Some(libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
            Deadline::BadNsec => Some(libc::timespec {
                tv_sec: 0,
                tv_nsec: NANOS,
            }),
            Deadline::After(ns) => {
                let (_, now) = p.rec.quiet(|| p.clock_gettime(libc::CLOCK_REALTIME));
                let at = now + i128::from(ns);
                Some(libc::timespec {
                    tv_sec: (at / i128::from(NANOS)) as i64,
                    tv_nsec: (at % i128::from(NANOS)) as i64,
                })
            }
        }
    }
}

/// Whole seconds of `CLOCK_REALTIME` read before and after an operation: the
/// kernel stamps IPC times with the realtime seconds at the moment it acts
/// (`ktime_get_real_seconds`), so a stamp the operation set lies within.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    pub from: i64,
    pub to: i64,
}

impl Window {
    /// Whether `stamp` (seconds) lies within the window.
    pub fn holds(self, stamp: i64) -> bool {
        self.from <= stamp && stamp <= self.to
    }
}

/// What `mq_notify` registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notify {
    /// A NULL `sigevent`: remove this process's registration.
    Remove,
    /// `SIGEV_NONE`: register without a notification.
    Quiet,
    /// `SIGEV_SIGNAL` with this signal.
    Signal(i32),
}

fn timeout_label(timeout: Option<(i64, i64)>) -> Value {
    match timeout {
        None => Value::from("NULL"),
        Some((sec, nsec)) => Value::from(format!("{sec}.{nsec:09}")),
    }
}

impl Probe {
    /// The `ftok(3)` key of the directory this run owns with `proj`
    /// ([`crate::owned::key`]): it names an object only this run creates, and
    /// the harness sweeps it after every native run.
    pub fn owned_key(&self, proj: u8, label: &'static str) -> Key {
        let dir = self.dir();
        let raw = self
            .rec
            .quiet(|| crate::owned::key(std::path::Path::new(&dir), proj))
            .unwrap_or_else(|error| panic!("{}: stat the run directory: {error}", self.name));
        Key { raw, label }
    }

    /// The whole seconds of `CLOCK_REALTIME`, read through this probe's own
    /// door (unrecorded): the clock the kernel, or patina, stamps IPC times
    /// with.
    pub fn realtime_seconds(&self) -> i64 {
        let (_, ns) = self.rec.quiet(|| self.clock_gettime(libc::CLOCK_REALTIME));
        ns.div_euclid(1_000_000_000) as i64
    }

    /// Run `operation` between two realtime readings; answer its result and
    /// the window a stamp it sets must lie within.
    pub fn stamped<T>(&self, operation: impl FnOnce() -> T) -> (T, Window) {
        let from = self.realtime_seconds();
        let value = operation();
        let to = self.realtime_seconds();
        (value, Window { from, to })
    }

    fn ipc_id_arg<'a>(
        builder: EventBuilder<'a>,
        namespace: &'static str,
        id: i32,
    ) -> EventBuilder<'a> {
        builder
            .arg(namespace, id)
            .norm(&format!("args.{namespace}"), Norm::Relative(namespace))
    }

    fn perm_fields<'a>(builder: EventBuilder<'a>, perm: &libc::ipc_perm) -> EventBuilder<'a> {
        builder
            .field("mode", perm.mode & 0o7777)
            .field("keyed", perm.__key != libc::IPC_PRIVATE)
            .field("uid", perm.uid)
            .norm("fields.uid", Norm::Identity(Id::User))
            .field("cuid", perm.cuid)
            .norm("fields.cuid", Norm::Identity(Id::User))
            .field("gid", perm.gid)
            .norm("fields.gid", Norm::Identity(Id::Group))
            .field("cgid", perm.cgid)
            .norm("fields.cgid", Norm::Identity(Id::Group))
    }

    /// An `IPC_SET` permission block: the caller's own owner, `mode`.
    fn own_perm(mode: u32) -> libc::ipc_perm {
        // SAFETY: ipc_perm is plain data; zero is a valid starting value.
        let mut perm: libc::ipc_perm = unsafe { std::mem::zeroed() };
        // SAFETY: identity reads.
        perm.uid = unsafe { libc::getuid() };
        perm.gid = unsafe { libc::getgid() };
        perm.mode = mode as _;
        perm
    }

    // ---- System V shared memory ----------------------------------------------

    pub fn shmget(&self, key: Key, size: usize, flags: i32) -> i32 {
        let result = self.call(
            Syscall::N_shmget,
            [key.raw as i64, size as i64, flags as i64, 0, 0, 0],
        );
        self.event(Syscall::N_shmget, result)
            .arg("key", key.label)
            .arg("size", size)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("shmid"))
            .emit();
        result as i32
    }

    /// `shmat`; a success is the region `name` of `len` bytes (the segment's).
    pub fn shmat(
        &self,
        name: &'static str,
        id: i32,
        len: usize,
        at: &super::At,
        flags: i32,
    ) -> (i64, Option<super::Region>) {
        let result = self.call(
            Syscall::N_shmat,
            [id as i64, at.raw as i64, flags as i64, 0, 0, 0],
        );
        let builder = Self::ipc_id_arg(self.event(Syscall::N_shmat, result.min(0)), "shmid", id)
            .arg("addr", at.label.as_str())
            .arg("flags", flags)
            .arg("region", name);
        let builder = if result >= 0 {
            let builder = builder.field("aligned", result as usize % super::page_size() == 0);
            if at.raw != 0 {
                builder.field("at_addr", result as usize == at.raw)
            } else {
                builder
            }
        } else {
            builder
        };
        builder.emit();
        (
            result,
            (result >= 0).then_some(super::Region {
                base: result as usize,
                len,
                name,
            }),
        )
    }

    pub fn shmdt(&self, at: &super::At) -> i64 {
        let result = self.call(Syscall::N_shmdt, [at.raw as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_shmdt, result)
            .arg("addr", at.label.as_str())
            .emit();
        result
    }

    /// `shmctl(id, cmd, buf)`: `Stat` records the `shmid_ds` members, `SetMode`
    /// passes the caller's own owner with a mode, `None` a NULL buffer.
    pub fn shmctl(&self, id: i32, cmd: i32, arg: ShmArg) -> (i64, Option<libc::shmid_ds>) {
        // SAFETY: shmid_ds is plain data; zero is a valid starting value.
        let mut ds: libc::shmid_ds = unsafe { std::mem::zeroed() };
        let buffer = match arg {
            ShmArg::Stat => &mut ds as *mut libc::shmid_ds as i64,
            ShmArg::SetMode(mode) => {
                ds.shm_perm = Self::own_perm(mode);
                &mut ds as *mut libc::shmid_ds as i64
            }
            ShmArg::None => 0,
        };
        let result = self.call(Syscall::N_shmctl, [id as i64, cmd as i64, buffer, 0, 0, 0]);
        let builder =
            Self::ipc_id_arg(self.event(Syscall::N_shmctl, result), "shmid", id).arg("cmd", cmd);
        let builder = match arg {
            ShmArg::SetMode(mode) => builder.arg("mode", mode),
            _ => builder,
        };
        let builder = if result >= 0 && arg == ShmArg::Stat {
            Self::perm_fields(builder, &ds.shm_perm)
                .field("segsz", ds.shm_segsz)
                .field("nattch", ds.shm_nattch)
                .field("cpid", ds.shm_cpid)
                .norm("fields.cpid", Norm::Identity(Id::Process))
                .field("lpid", ds.shm_lpid)
                .norm("fields.lpid", Norm::Identity(Id::Process))
        } else {
            builder
        };
        builder.emit();
        (result, (result >= 0).then_some(ds))
    }

    // ---- System V semaphores -------------------------------------------------

    pub fn semget(&self, key: Key, nsems: i32, flags: i32) -> i32 {
        let result = self.call(
            Syscall::N_semget,
            [key.raw as i64, nsems as i64, flags as i64, 0, 0, 0],
        );
        self.event(Syscall::N_semget, result)
            .arg("key", key.label)
            .arg("nsems", nsems)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("semid"))
            .emit();
        result as i32
    }

    fn sembufs(ops: &[(u16, i16, i16)]) -> (Vec<libc::sembuf>, Value) {
        let bufs = ops
            .iter()
            .map(|&(num, op, flags)| libc::sembuf {
                sem_num: num,
                sem_op: op,
                sem_flg: flags,
            })
            .collect();
        let shown = ops
            .iter()
            .map(|&(num, op, flags)| Value::from(format!("{num}:{op}:{flags:#x}")))
            .collect::<Vec<_>>();
        (bufs, Value::from(shown))
    }

    /// `semop(id, ops, nsops)` with each op `(sem_num, sem_op, sem_flg)`;
    /// `nsops` overrides the count for a refusal the kernel reaches before it
    /// reads the vector (a NULL vector when `ops` is empty).
    pub fn semop(&self, id: i32, ops: &[(u16, i16, i16)], nsops: Option<usize>) -> i64 {
        let (bufs, shown) = Self::sembufs(ops);
        let pointer = if ops.is_empty() {
            0
        } else {
            bufs.as_ptr() as i64
        };
        let count = nsops.unwrap_or(ops.len());
        let result = self.call(
            Syscall::N_semop,
            [id as i64, pointer, count as i64, 0, 0, 0],
        );
        Self::ipc_id_arg(self.event(Syscall::N_semop, result), "semid", id)
            .arg("ops", shown)
            .arg("nsops", count)
            .emit();
        result
    }

    /// `semtimedop` with a relative `(sec, nsec)` timeout (`None`: NULL).
    pub fn semtimedop(&self, id: i32, ops: &[(u16, i16, i16)], timeout: Option<(i64, i64)>) -> i64 {
        let (bufs, shown) = Self::sembufs(ops);
        let spec = timeout.map(|(sec, nsec)| libc::timespec {
            tv_sec: sec,
            tv_nsec: nsec,
        });
        let result = self.call(
            Syscall::N_semtimedop,
            [
                id as i64,
                bufs.as_ptr() as i64,
                ops.len() as i64,
                spec.as_ref()
                    .map_or(0, |spec| spec as *const libc::timespec as i64),
                0,
                0,
            ],
        );
        Self::ipc_id_arg(self.event(Syscall::N_semtimedop, result), "semid", id)
            .arg("ops", shown)
            .arg("timeout", timeout_label(timeout))
            .emit();
        result
    }

    /// `semctl(id, num, cmd, arg)`. `GETPID`'s answer is a pid (compared by
    /// relation); `GetAll` records and returns the values; `Stat` records the
    /// `semid_ds` members.
    pub fn semctl(&self, id: i32, num: i32, cmd: i32, arg: &SemArg) -> (i64, Vec<u16>) {
        let (result, values, _) = self.semctl_full(id, num, cmd, arg);
        (result, values)
    }

    /// `semctl(id, 0, IPC_STAT, &ds)`, returning the `semid_ds`.
    pub fn semctl_stat(&self, id: i32) -> (i64, Option<libc::semid_ds>) {
        let (result, _, ds) = self.semctl_full(id, 0, libc::IPC_STAT, &SemArg::Stat);
        (result, (result >= 0).then_some(ds))
    }

    fn semctl_full(
        &self,
        id: i32,
        num: i32,
        cmd: i32,
        arg: &SemArg,
    ) -> (i64, Vec<u16>, libc::semid_ds) {
        // SAFETY: semid_ds is plain data; zero is a valid starting value.
        let mut ds: libc::semid_ds = unsafe { std::mem::zeroed() };
        let mut values: Vec<u16> = match arg {
            SemArg::GetAll(count) => vec![u16::MAX; *count],
            SemArg::SetAll(values) => values.clone(),
            _ => Vec::new(),
        };
        let fourth = match arg {
            SemArg::None => 0,
            SemArg::Val(value) => *value as i64,
            SemArg::GetAll(_) | SemArg::SetAll(_) => values.as_mut_ptr() as i64,
            SemArg::Stat => &mut ds as *mut libc::semid_ds as i64,
            SemArg::SetMode(mode) => {
                ds.sem_perm = Self::own_perm(*mode);
                &mut ds as *mut libc::semid_ds as i64
            }
        };
        let result = self.call(
            Syscall::N_semctl,
            [id as i64, num as i64, cmd as i64, fourth, 0, 0],
        );
        let builder = Self::ipc_id_arg(self.event(Syscall::N_semctl, result), "semid", id)
            .arg("semnum", num)
            .arg("cmd", cmd);
        let builder = match arg {
            SemArg::Val(value) => builder.arg("val", *value),
            SemArg::SetAll(values) => builder.arg("values", values.clone()),
            SemArg::SetMode(mode) => builder.arg("mode", *mode),
            _ => builder,
        };
        let builder = if cmd == libc::GETPID && result > 0 {
            builder.norm("ret", Norm::Identity(Id::Process))
        } else {
            builder
        };
        let builder = match arg {
            SemArg::GetAll(_) if result >= 0 => builder.field("values", values.clone()),
            SemArg::Stat if result >= 0 => {
                Self::perm_fields(builder, &ds.sem_perm).field("nsems", ds.sem_nsems)
            }
            _ => builder,
        };
        builder.emit();
        (result, values, ds)
    }

    // ---- System V message queues ---------------------------------------------

    pub fn msgget(&self, key: Key, flags: i32) -> i32 {
        let result = self.call(
            Syscall::N_msgget,
            [key.raw as i64, flags as i64, 0, 0, 0, 0],
        );
        self.event(Syscall::N_msgget, result)
            .arg("key", key.label)
            .arg("flags", flags)
            .norm("ret", Norm::Relative("msqid"))
            .emit();
        result as i32
    }

    /// A `struct msgbuf` (`long mtype; char mtext[]`) of `size` text bytes.
    fn msgbuf(mtype: i64, text: &[u8], size: usize) -> Vec<u64> {
        let mut words = vec![0u64; 1 + size.div_ceil(8)];
        words[0] = mtype as u64;
        // SAFETY: `words` holds 8 + size bytes and `text` fits in `size`.
        unsafe {
            std::ptr::copy_nonoverlapping(
                text.as_ptr(),
                (words.as_mut_ptr() as *mut u8).add(8),
                text.len().min(size),
            );
        }
        words
    }

    /// `msgsnd(id, {mtype, text}, len(text), flags)`.
    pub fn msgsnd(&self, id: i32, mtype: i64, text: &[u8], flags: i32) -> i64 {
        let buffer = Self::msgbuf(mtype, text, text.len());
        let result = self.call(
            Syscall::N_msgsnd,
            [
                id as i64,
                buffer.as_ptr() as i64,
                text.len() as i64,
                flags as i64,
                0,
                0,
            ],
        );
        Self::ipc_id_arg(self.event(Syscall::N_msgsnd, result), "msqid", id)
            .arg("mtype", mtype)
            .arg("text", printable(text))
            .arg("flags", flags)
            .emit();
        result
    }

    /// `msgsnd` declaring `size` text bytes: of a message `{mtype, text}`
    /// (`size` may exceed the text only for a refusal the kernel reaches
    /// before it copies the text), or of a NULL message (`None`).
    pub fn msgsnd_declared(
        &self,
        id: i32,
        message: Option<(i64, &[u8])>,
        size: usize,
        flags: i32,
    ) -> i64 {
        let buffer = message.map(|(mtype, text)| Self::msgbuf(mtype, text, text.len()));
        let result = self.call(
            Syscall::N_msgsnd,
            [
                id as i64,
                buffer.as_ref().map_or(0, |buffer| buffer.as_ptr() as i64),
                size as i64,
                flags as i64,
                0,
                0,
            ],
        );
        let builder = Self::ipc_id_arg(self.event(Syscall::N_msgsnd, result), "msqid", id);
        let builder = match message {
            Some((mtype, text)) => builder.arg("mtype", mtype).arg("text", printable(text)),
            None => builder.arg("msgp", "NULL"),
        };
        builder.arg("msgsz", size).arg("flags", flags).emit();
        result
    }

    /// `msgrcv(id, buf, size, mtype, flags)`; a success records and returns
    /// the message's type and text.
    pub fn msgrcv(
        &self,
        id: i32,
        size: usize,
        mtype: i64,
        flags: i32,
    ) -> (i64, Option<(i64, Vec<u8>)>) {
        let mut buffer = Self::msgbuf(0, &[], size);
        let result = self.call(
            Syscall::N_msgrcv,
            [
                id as i64,
                buffer.as_mut_ptr() as i64,
                size as i64,
                mtype,
                flags as i64,
                0,
            ],
        );
        let message = (result >= 0).then(|| {
            // SAFETY: the kernel wrote `result` text bytes after the type.
            let text = unsafe {
                std::slice::from_raw_parts((buffer.as_ptr() as *const u8).add(8), result as usize)
            }
            .to_vec();
            (buffer[0] as i64, text)
        });
        let builder = Self::ipc_id_arg(self.event(Syscall::N_msgrcv, result), "msqid", id)
            .arg("msgsz", size)
            .arg("msgtyp", mtype)
            .arg("flags", flags);
        let builder = match &message {
            Some((kind, text)) => builder.field("mtype", *kind).field("text", printable(text)),
            None => builder,
        };
        builder.emit();
        (result, message)
    }

    pub fn msgctl(&self, id: i32, cmd: i32, arg: MsgArg) -> (i64, Option<libc::msqid_ds>) {
        // SAFETY: msqid_ds is plain data; zero is a valid starting value.
        let mut ds: libc::msqid_ds = unsafe { std::mem::zeroed() };
        let buffer = match arg {
            MsgArg::None => 0,
            MsgArg::Stat => &mut ds as *mut libc::msqid_ds as i64,
            MsgArg::Set { mode, qbytes } => {
                ds.msg_perm = Self::own_perm(mode);
                ds.msg_qbytes = qbytes as _;
                &mut ds as *mut libc::msqid_ds as i64
            }
        };
        let result = self.call(Syscall::N_msgctl, [id as i64, cmd as i64, buffer, 0, 0, 0]);
        let builder =
            Self::ipc_id_arg(self.event(Syscall::N_msgctl, result), "msqid", id).arg("cmd", cmd);
        let builder = match arg {
            MsgArg::Set { mode, qbytes } => builder.arg("mode", mode).arg("qbytes", qbytes),
            _ => builder,
        };
        let builder = if result >= 0 && arg == MsgArg::Stat {
            Self::perm_fields(builder, &ds.msg_perm)
                .field("qnum", ds.msg_qnum)
                .field("cbytes", ds.__msg_cbytes)
                // A new queue's limit is the host's `kernel.msgmnb`: compared
                // by relation (unchanged, or the value `IPC_SET` gave it,
                // which the scenario checks exactly).
                .field("qbytes", ds.msg_qbytes)
                .norm("fields.qbytes", Norm::Relative("qbytes"))
                .field("lspid", ds.msg_lspid)
                .norm("fields.lspid", Norm::Identity(Id::Process))
                .field("lrpid", ds.msg_lrpid)
                .norm("fields.lrpid", Norm::Identity(Id::Process))
        } else {
            builder
        };
        builder.emit();
        (result, (result >= 0).then_some(ds))
    }

    // ---- POSIX message queues ------------------------------------------------

    /// `mq_open(name, oflag, mode, attr)`: the kernel row, whose name has no
    /// leading slash (glibc's `mq_open` strips it). `attr` is `(maxmsg,
    /// msgsize)`, `None` a NULL attribute block.
    pub fn mq_open(&self, name: &str, oflag: i32, mode: u32, attr: Option<(i64, i64)>) -> i32 {
        let c = super::cstr(name);
        // SAFETY: mq_attr is plain data; zero is a valid starting value.
        let mut block: libc::mq_attr = unsafe { std::mem::zeroed() };
        if let Some((maxmsg, msgsize)) = attr {
            block.mq_maxmsg = maxmsg;
            block.mq_msgsize = msgsize;
        }
        let result = self.call(
            Syscall::N_mq_open,
            [
                c.as_ptr() as i64,
                oflag as i64,
                mode as i64,
                if attr.is_some() {
                    &block as *const libc::mq_attr as i64
                } else {
                    0
                },
                0,
                0,
            ],
        );
        let builder = self
            .event(Syscall::N_mq_open, result)
            .arg("name", name)
            .arg("oflag", oflag)
            .arg("mode", mode);
        let builder = match attr {
            Some((maxmsg, msgsize)) => builder.arg("maxmsg", maxmsg).arg("msgsize", msgsize),
            None => builder.arg("attr", "NULL"),
        };
        builder.norm("ret", Norm::Relative("fd")).emit();
        result as i32
    }

    pub fn mq_unlink(&self, name: &str) -> i64 {
        let c = super::cstr(name);
        let result = self.call(Syscall::N_mq_unlink, [c.as_ptr() as i64, 0, 0, 0, 0, 0]);
        self.event(Syscall::N_mq_unlink, result)
            .arg("name", name)
            .emit();
        result
    }

    pub fn mq_timedsend(&self, fd: i32, data: &[u8], prio: u32, deadline: Deadline) -> i64 {
        let spec = deadline.timespec(self);
        let result = self.call(
            Syscall::N_mq_timedsend,
            [
                fd as i64,
                data.as_ptr() as i64,
                data.len() as i64,
                prio as i64,
                spec.as_ref()
                    .map_or(0, |spec| spec as *const libc::timespec as i64),
                0,
            ],
        );
        let builder = self.event(Syscall::N_mq_timedsend, result);
        self.fd_arg(builder, "mqdes", fd)
            .arg("data", printable(data))
            .arg("prio", prio)
            .arg("deadline", deadline.label())
            .emit();
        result
    }

    /// `mq_timedreceive` into `capacity` bytes; a success records and returns
    /// the message and its priority.
    pub fn mq_timedreceive(
        &self,
        fd: i32,
        capacity: usize,
        deadline: Deadline,
    ) -> (i64, Vec<u8>, u32) {
        let spec = deadline.timespec(self);
        let mut buffer = vec![0u8; capacity];
        let mut prio: u32 = u32::MAX;
        let result = self.call(
            Syscall::N_mq_timedreceive,
            [
                fd as i64,
                buffer.as_mut_ptr() as i64,
                capacity as i64,
                &mut prio as *mut u32 as i64,
                spec.as_ref()
                    .map_or(0, |spec| spec as *const libc::timespec as i64),
                0,
            ],
        );
        buffer.truncate(result.max(0) as usize);
        let builder = self.event(Syscall::N_mq_timedreceive, result);
        let builder = self
            .fd_arg(builder, "mqdes", fd)
            .arg("len", capacity)
            .arg("deadline", deadline.label());
        let builder = if result >= 0 {
            builder
                .field("data", printable(&buffer))
                .field("prio", prio)
        } else {
            builder
        };
        builder.emit();
        (result, buffer, prio)
    }

    pub fn mq_notify(&self, fd: i32, notify: Notify) -> i64 {
        // SAFETY: sigevent is plain data; zero is a valid starting value.
        let mut event: libc::sigevent = unsafe { std::mem::zeroed() };
        let label = match notify {
            Notify::Remove => "NULL".to_string(),
            Notify::Quiet => {
                event.sigev_notify = libc::SIGEV_NONE;
                "SIGEV_NONE".to_string()
            }
            Notify::Signal(signal) => {
                event.sigev_notify = libc::SIGEV_SIGNAL;
                event.sigev_signo = signal;
                format!("SIGEV_SIGNAL:{signal}")
            }
        };
        let pointer = if notify == Notify::Remove {
            0
        } else {
            &event as *const libc::sigevent as i64
        };
        let result = self.call(Syscall::N_mq_notify, [fd as i64, pointer, 0, 0, 0, 0]);
        let builder = self.event(Syscall::N_mq_notify, result);
        self.fd_arg(builder, "mqdes", fd).arg("sevp", label).emit();
        result
    }

    /// `mq_getsetattr(fd, new, old)`: `new_flags` sets `mq_flags` (the only
    /// member the kernel takes), else a NULL `new`. Records the old attributes.
    pub fn mq_getsetattr(&self, fd: i32, new_flags: Option<i64>) -> (i64, libc::mq_attr) {
        // SAFETY: mq_attr is plain data; zero is a valid starting value.
        let mut new: libc::mq_attr = unsafe { std::mem::zeroed() };
        let mut old: libc::mq_attr = unsafe { std::mem::zeroed() };
        if let Some(flags) = new_flags {
            new.mq_flags = flags;
        }
        let result = self.call(
            Syscall::N_mq_getsetattr,
            [
                fd as i64,
                if new_flags.is_some() {
                    &new as *const libc::mq_attr as i64
                } else {
                    0
                },
                &mut old as *mut libc::mq_attr as i64,
                0,
                0,
                0,
            ],
        );
        let builder = self.event(Syscall::N_mq_getsetattr, result);
        let builder = self.fd_arg(builder, "mqdes", fd).arg(
            "new_flags",
            new_flags.map_or(Value::from("NULL"), Value::from),
        );
        let builder = if result >= 0 {
            builder
                .field("flags", old.mq_flags)
                .field("maxmsg", old.mq_maxmsg)
                .field("msgsize", old.mq_msgsize)
                .field("curmsgs", old.mq_curmsgs)
        } else {
            builder
        };
        builder.emit();
        (result, old)
    }
}
