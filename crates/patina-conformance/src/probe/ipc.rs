//! The IPC rows: System V shared memory, semaphores and message queues, and
//! POSIX message queues — all within one process (and its threads), the
//! semantics the owner decision models.
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

/// A command no System V `*ctl` row defines (the IPC commands end at 20,
/// `SEM_STAT_ANY`).
pub const UNKNOWN_IPC_CMD: i32 = 99;

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

/// The `ipc_perm` mode word, which glibc's ABI makes 16 bits wide on x86_64
/// and 32 bits wide on aarch64.
#[cfg(target_arch = "x86_64")]
pub fn perm_mode(perm: &libc::ipc_perm) -> u32 {
    u32::from(perm.mode)
}

/// The `ipc_perm` mode word, which glibc's ABI makes 16 bits wide on x86_64
/// and 32 bits wide on aarch64.
#[cfg(not(target_arch = "x86_64"))]
pub fn perm_mode(perm: &libc::ipc_perm) -> u32 {
    perm.mode
}

/// The whole seconds an IPC stamp set by an operation must lie within. The
/// kernel stamps IPC times with `ktime_get_real_seconds`, the timekeeper's
/// seconds as of its last tick, which trail the fine clock by up to a tick:
/// near a second boundary a fine reading before the operation can already
/// show second N while the stamp is still N-1. So `from` is the coarse
/// realtime second ([`Probe::stamp_floor_seconds`], never ahead of a later
/// stamp) and `to` the fine one ([`Probe::realtime_seconds`], never behind
/// one).
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
    /// door (unrecorded). No stamp set before this reading lies above it, so
    /// it closes a [`Window`].
    pub fn realtime_seconds(&self) -> i64 {
        self.seconds_of(libc::CLOCK_REALTIME)
    }

    /// The whole seconds of `CLOCK_REALTIME_COARSE`, read through this probe's
    /// own door (unrecorded): the timekeeper's seconds the kernel stamps IPC
    /// times with, which never run ahead of a stamp set after this reading, so
    /// it opens a [`Window`]. The fine clock can, across a second boundary.
    pub fn stamp_floor_seconds(&self) -> i64 {
        self.seconds_of(libc::CLOCK_REALTIME_COARSE)
    }

    fn seconds_of(&self, clock: i32) -> i64 {
        let (_, ns) = self.rec.quiet(|| self.clock_gettime(clock));
        ns.div_euclid(1_000_000_000) as i64
    }

    /// Run `operation` between two realtime readings; answer its result and
    /// the window a stamp it sets must lie within.
    pub fn stamped<T>(&self, operation: impl FnOnce() -> T) -> (T, Window) {
        let from = self.stamp_floor_seconds();
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
        let builder = if result >= 0 && at.raw != 0 {
            builder.field("at_addr", result as usize == at.raw)
        } else {
            builder
        };
        self.mapped(result, name, len, builder)
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
}
