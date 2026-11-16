//! Control region: the first page (`Ctl`) followed by `MAX_THREADS` slots.
//! Shared between every guest process (mapped at `CTL_ADDR`), the supervisor
//! and, after the run, the launcher. Written only by whoever holds the turn.

use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

pub const MAGIC: u64 = 0x7461_705f_6c74_6321; // "!ctl_pat"
pub const LAYOUT_VERSION: u64 = 6;
pub const MAX_THREADS: usize = 1024;

/// Seed, rates and limits. Read-only after start.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub seed: u64,
    /// Probability per trap, in thousandths, that the runtime yields to the supervisor.
    pub preempt_permille: u64,
    /// Virtual time charged to every trap.
    pub trap_charge_ns: u64,
    pub vtime_limit_ns: u64,
    /// Wall-clock limit without a trap before the run ends as `stall`.
    pub stall_ms: u64,
    pub tmpfs_bytes: u64,
    /// CPU count the guest is told it has.
    pub cpu_count: u64,
    /// Counter preemption (`PMU_*` bits; 0 = off, and then nothing below is used).
    /// Set by the launcher only when it could open the counters.
    pub pmu: u64,
    /// Long slices: N log-uniform in `[pmu_slice_min, pmu_slice_max]` branches.
    pub pmu_slice_min: u64,
    pub pmu_slice_max: u64,
    /// Short slices: probability in thousandths (low 16 bits) and the largest N (bits 16..).
    pub pmu_short: u64,
    /// Virtual time charged per branch of a preempted slice, in picoseconds.
    pub pmu_charge_ps: u64,
    /// Branches before N at which the hardware alarm is aimed (above the largest skid).
    pub pmu_margin: u64,
}

/// `Config::pmu`: counter preemption is on.
pub const PMU_ON: u64 = 1;

impl Config {
    pub const fn default_with_seed(seed: u64) -> Config {
        Config {
            seed,
            preempt_permille: 100,
            trap_charge_ns: 1_000,
            vtime_limit_ns: 3_600 * 1_000_000_000,
            stall_ms: 10_000,
            tmpfs_bytes: 256 << 20,
            cpu_count: 1,
            pmu: 0,
            pmu_slice_min: 0,
            pmu_slice_max: 0,
            pmu_short: 0,
            pmu_charge_ps: 0,
            pmu_margin: 0,
        }
    }
}

/// Counters, written by whoever holds the turn.
#[repr(C)]
pub struct Stats {
    pub traps: AtomicU64,
    pub switches: AtomicU64,
    pub faults_injected: AtomicU64,
    pub refusals: AtomicU64,
    pub decisions: AtomicU64,
    pub insn_emulations: AtomicU64,
    /// `AF_UNIX` sockets sent in `SCM_RIGHTS` messages: the only way to build a reference
    /// cycle of in-flight descriptors, which the kernel releases from its garbage-collector worker
    /// at a time of its choosing (bucket D). A run with a non-zero count is labelled.
    pub unix_sockets_sent: AtomicU64,
}

/// First page of the control region.
#[repr(C)]
pub struct Ctl {
    pub magic: AtomicU64,
    pub layout_version: AtomicU64,
    pub config: Config,
    /// Global boundary sequence number: +1 per trap and per supervisor decision.
    pub seq: AtomicU64,
    pub vclock_ns: AtomicU64,
    pub next_deadline_ns: AtomicU64,
    /// Boundary log write offset, running hash and current file size.
    pub log_len: AtomicU64,
    pub log_hash: AtomicU64,
    pub log_cap: AtomicU64,
    pub oplog_len: AtomicU64,
    pub opdata_len: AtomicU64,
    /// Futex word the supervisor sleeps on (1 = a request is pending).
    pub sup_word: AtomicU32,
    /// Which slot holds the current request.
    pub pending_slot: AtomicU32,
    pub stats: Stats,
    /// Nonzero once the first guest process of this incarnation has installed the
    /// runtime's seccomp filter. Every later guest process descends from it and inherits the
    /// filter, so the runtime's entry after an `execve` must not stack a second one; an
    /// inherited filter from outside the sandbox (a container's profile) is not a reason to
    /// skip it, which is why `PR_GET_SECCOMP` cannot be the test.
    pub filter_installed: AtomicU64,
    pub _spare: [AtomicU64; 5],
    /// One bit per syscall number answered `Deny` at least once (`refused` in the outcome).
    pub denied: [AtomicU64; 8],
    /// Syscall number that ended the run with `Stop` (or u64::MAX).
    pub stop_nr: AtomicU64,
    /// Blocking I/O: see `IoCtl`.
    pub io: IoCtl,
    /// Fault injection and crash configuration and counters.
    pub faults: crate::faults::FaultCtl,
    /// Instruction channels: patched sites, emulations, unscanned code.
    pub insn: InsnCtl,
    /// Host `CLOCK_MONOTONIC` ns at supervisor milestones, for the start-up breakdown
    /// (`PATINA_TIMING=1` makes the launcher print them). Indexes `TM_*`. Never logged.
    pub timing: [AtomicU64; 8],
    /// Counter preemption counters, summed over every thread of the run.
    pub pmu: PmuStats,
}

/// Counter preemption counters (`PMU_NAMES` order in the outcome).
#[repr(C)]
pub struct PmuStats {
    /// Counters opened (one per thread image).
    pub opened: AtomicU64,
    /// Preemptions (stops), of which reached by hops from the segment start (short slices).
    pub preempts: AtomicU64,
    pub preempts_short: AtomicU64,
    /// Overflow interrupts taken in guest code, and period reprogrammings.
    pub alarms: AtomicU64,
    pub rearms: AtomicU64,
    /// Conditional branches counted by hops, other transfers emulated, single steps.
    pub hops: AtomicU64,
    pub emulated: AtomicU64,
    pub steps: AtomicU64,
    /// Counter reads at segment starts (`rdpmc`).
    pub reads: AtomicU64,
    /// Segments started.
    pub segments: AtomicU64,
    /// Long segments that reached the margin and finished by hops (landings).
    pub landings: AtomicU64,
    /// A synchronous signal that arrived on top of the overflow signal (handled, see `rt::pmu`).
    pub races: AtomicU64,
    /// Largest overflow skid seen (branches past the programmed point, at a landing).
    pub max_skid: AtomicU64,
}
pub const PMU_FIELDS: usize = 13;
pub const PMU_NAMES: [&str; PMU_FIELDS] = [
    "opened",
    "preempts",
    "preempts_short",
    "alarms",
    "rearms",
    "hops",
    "emulated",
    "steps",
    "reads",
    "segments",
    "landings",
    "races",
    "max_skid",
];

impl PmuStats {
    pub fn read(&self) -> [u64; PMU_FIELDS] {
        let r = |a: &AtomicU64| a.load(Ordering::Relaxed);
        [
            r(&self.opened),
            r(&self.preempts),
            r(&self.preempts_short),
            r(&self.alarms),
            r(&self.rearms),
            r(&self.hops),
            r(&self.emulated),
            r(&self.steps),
            r(&self.reads),
            r(&self.segments),
            r(&self.landings),
            r(&self.races),
            r(&self.max_skid),
        ]
    }
}

/// Indexes of `Ctl::timing`.
pub const TM_SUP_START: usize = 0;
pub const TM_COPIED: usize = 1;
pub const TM_FIRST_HELLO: usize = 2;
pub const TM_MAIN_EXIT: usize = 3;
pub const TM_FINISH: usize = 4;
pub const TM_EXPORTED: usize = 5;

/// Instruction-channel counters, summed over every process of the run.
#[repr(C)]
pub struct InsnCtl {
    /// Sites patched to `ud2`, by `proto::insn::SiteKind` (index 1 rdrand, 2 rdseed, 3 rdpid).
    pub patched: [AtomicU64; 4],
    /// Emulated executions, by `INSN_*` index.
    pub emulated: [AtomicU64; 8],
    /// Executable mappings whose code the scanner could not see or vouch for: anonymous
    /// memory made executable (JIT) and shared file mappings (their bytes can change later).
    pub unscanned_exec_mappings: AtomicU64,
    /// Candidates the scanner refused (bytes inside another instruction, or skipped by the
    /// sweep), and candidates beyond the per-mapping limit. A refused real site would run
    /// unpatched; the count makes that visible.
    pub rejected_sites: AtomicU64,
    /// `rdpid` sites seen and left alone (it reads the pinned core: no system ELF file seen has one).
    pub rdpid_sites: AtomicU64,
    /// Executable file mappings scanned, and their bytes.
    pub scanned_mappings: AtomicU64,
    pub scanned_bytes: AtomicU64,
    /// Sites that could not be recorded because the side table was full (also rejected).
    pub table_full: AtomicU64,
}

/// Indexes of `InsnCtl::emulated`.
pub const INSN_RDTSC: usize = 0;
pub const INSN_RDTSCP: usize = 1;
pub const INSN_RDRAND: usize = 2;
pub const INSN_RDSEED: usize = 3;
pub const INSN_RDPID: usize = 4;
pub const INSN_NAMES: [&str; 5] = ["rdtsc", "rdtscp", "rdrand", "rdseed", "rdpid"];

/// Blocking I/O state shared by the runtime and the supervisor.
/// Written only by whoever holds the turn.
#[repr(C)]
pub struct IoCtl {
    /// The global I/O generation: incremented after every call that can change readiness
    /// (by the runtime of the calling thread) and at every timerfd expiry (by the supervisor).
    pub gen: AtomicU64,
    /// Threads parked on I/O (maintained by the supervisor). A thread that moves the
    /// generation while this is non-zero yields at the end of its call so they can re-attempt.
    pub waiters: AtomicU64,
    /// Parks sent (`Op::Park`).
    pub parks: AtomicU64,
    /// Attempts repeated after a park.
    pub reattempts: AtomicU64,
    /// Repeated attempts that would still have blocked.
    pub spurious: AtomicU64,
    /// Attempt-class calls on descriptors that can block, in blocking mode, that completed
    /// (not counting would-block answers to non-blocking descriptors).
    pub blocking_done: AtomicU64,
    /// Of those, calls that parked at least once.
    pub blocking_parked: AtomicU64,
    /// Next deterministic `AF_UNIX` autobind name.
    pub autobind_next: AtomicU64,
}

const _: () = assert!(core::mem::size_of::<Ctl>() <= 4096);

pub const CTL_HEADER_SIZE: usize = 4096;
/// Header, slots, the shared filesystem state (`vfs`), the durability state (`oplog::Dur`),
/// the network wire's table (`wire::WireTab`), then the SDK's site table (`sdk::SdkTab`).
pub const CTL_SIZE: usize = crate::sdk::SDK_OFFSET + crate::sdk::SDK_SIZE;

/// Slot states.
pub const SLOT_FREE: u32 = 0;
/// Reserved by the supervisor for a task it is about to create (tid not known yet).
pub const SLOT_RESERVED: u32 = 1;
pub const SLOT_LIVE: u32 = 2;
pub const SLOT_EXITING: u32 = 3;

/// Request from a guest thread: op + 6 arguments.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Request {
    pub op: u32,
    pub _pad: u32,
    pub args: [u64; 6],
}

/// Reply from the supervisor. `flags` carries delivery instructions: the low byte
/// (`REP_DELIVER_MASK`) is the signal to deliver before returning to guest code
/// (`deliver`): set in the reply to `SigTake`, with the signal's `siginfo` in the slot.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Reply {
    pub ret: i64,
    pub flags: u64,
}

#[repr(C)]
pub struct Slot {
    /// Futex word this thread sleeps on while it does not hold the turn.
    pub go: AtomicU32,
    /// `SLOT_FREE`, `SLOT_RESERVED`, `SLOT_LIVE`, `SLOT_EXITING`.
    pub state: AtomicU32,
    /// Kernel tid inside the PID namespace.
    pub tid: AtomicI32,
    pub pid: AtomicI32,
    pub req: Request,
    pub rep: Reply,
    /// The thread's virtual signal mask. Written by the runtime under the turn,
    /// read by the supervisor to choose a receiving thread and to decide wake-ups.
    pub vmask: AtomicU64,
    /// Signals pending for this thread: its private set or'ed with its process's set.
    /// Written by the supervisor; the runtime tests `sigpend & !vmask` at every trap exit.
    pub sigpend: AtomicU64,
    /// A kernel `siginfo_t` (128 bytes): written by a sender before `SigSend`, by the
    /// supervisor in the reply to `SigTake`/`SigWait`, and the old timer by `TimerSet`.
    pub siginfo: [u64; 16],
}

/// Reply flag: signal number to deliver before returning (0: none).
pub const REP_DELIVER_MASK: u64 = 0xff;

/// Decision codes of supervisor records that answer no request (`Rec::nr` of a `SupDecision`).
/// Idle jump: nothing runnable, the clock moved to the earliest event (args: [old ns, new ns]).
pub const DEC_IDLE_JUMP: u32 = 0x100;
/// An interval timer expired and raised its signal (args: [pid, expiry ns, interval ns]).
pub const DEC_SIGNAL_TIMER: u32 = 0x120;

/// "No deadline" in request arguments.
pub const NO_DEADLINE: u64 = u64::MAX;

/// Requests. Served so far: `Hello`, `Yield`, `Sleep`, `FutexWait`,
/// `FutexWake`, `FutexRequeue`, `ThreadExit`, `Forked` (threads), `ProcExit`, `Stop`, `HostError`;
/// the supervisor answers any other op with `infra`.
///
/// Arguments:
/// - `Hello`: [pid, tid, 1 if a thread created by `clone`]
/// - `Sleep`: [deadline ns of the virtual monotonic clock]
/// - `FutexWait`: [address, value seen, deadline or `NO_DEADLINE`, bitset]; reply 0 or -ETIMEDOUT
/// - `FutexWake`: [address, n, bitset, address2 or 0, n2]; reply: threads woken
/// - `FutexRequeue`: [address, address2, n wake, n requeue, 1 if CMP_REQUEUE]; reply: woken
///   (plus requeued for CMP_REQUEUE)
/// - `ThreadExit`: [status, emulated clear-tid address or 0]; never answered
/// - `Forked`: [child slot, child tid, child pid] (thread: same address space as the caller)
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Hello = 1,
    Yield = 2,
    Sleep = 3,
    FutexWait = 4,
    FutexWake = 5,
    FutexRequeue = 6,
    Park = 7,
    ThreadExit = 8,
    /// args: [exit status, terminating signal or 0]
    ProcExit = 9,
    Forked = 10,
    VforkStart = 11,
    Exec = 12,
    WaitPark = 13,
    SigSend = 14,
    SigWait = 15,
    SigSuspend = 16,
    TimerSet = 17,
    CrashPoint = 18,
    /// args: [syscall number, first argument]
    Stop = 19,
    /// args: [errno, syscall number, code]
    HostError = 20,
    /// signals: dequeue one deliverable signal for the caller. args: [the caller's virtual mask].
    /// Reply: `flags & REP_DELIVER_MASK` = the signal (0: none), its siginfo in the slot.
    SigTake = 21,
    /// signals: a disposition changed its kind. args: [signal, kind (`SIGK_*`)].
    SigAction = 22,
    /// timerfd. args[0] = sub-operation: `TFD_CREATE` [_, key, guest fd, clock],
    /// `TFD_ARM` [_, key, first expiry ns (vclock) or 0 to disarm, interval ns],
    /// `TFD_RELEASE` [_, key]. Reply 0 or -errno.
    TimerFdSet = 40,
    /// timerfd. args: [key, 0 = next expiry (vclock ns, 0 if disarmed) | 1 = interval ns].
    TimerFdGet = 41,
    /// Wire, see `WIRE_*` below.
    WireSocket = 50,
    WireBind = 51,
    WireConnect = 52,
    WireAccepted = 53,
    WireSent = 54,
    WireQuery = 55,
    /// A failed `always` (`sdk`): the run ends as `violation`; the message is in the SDK table.
    /// args: [op, payload pointer, length] of the trap. Never answered.
    SdkViolation = 60,
}

/// Network wire requests. Socket indexes are `vino - VINO_BASE`.
///
/// - `WireSocket`: [index, family]: a new `AF_INET`/`AF_INET6` stream socket. Reply 0.
/// - `WireBind`: [index, port (0: allocate), address kind, `WIRE_BIND`|`WIRE_LISTEN`]. Reply the
///   port or -errno. The runtime then binds the real socket to `@patina-l-<port>` (and listens).
/// - `WireConnect`: [index, port, address kind, padding bytes, 1 if non-blocking]: the runtime has
///   connected the real socket to `@patina-wire` and written the preamble (and the padding). Reply 0
///   or -errno; the outcome arrives in the socket's table entry.
/// - `WireAccepted`: [connection id, index of the accepted socket, family]: reply 0 or -errno.
/// - `WireSent`: [] the supervisor reads the marked hidden ends now (a step of its own).
/// - `WireQuery`: [index]: the connection's state (debugging). Reply the state.
pub const WIRE_BIND: u64 = 0;
pub const WIRE_LISTEN: u64 = 1;
/// Decision codes of the wire (args documented in `patina/src/sup/wire.rs`).
pub const DEC_WIRE_READ: u32 = 0x140;
pub const DEC_WIRE_DELIVER: u32 = 0x141;
pub const DEC_WIRE_ESTABLISH: u32 = 0x142;
pub const DEC_WIRE_FIN: u32 = 0x143;
pub const DEC_WIRE_RST: u32 = 0x144;
pub const DEC_WIRE_FAIL: u32 = 0x145;
pub const DEC_WIRE_CLOSE: u32 = 0x146;

/// `TimerFdSet` sub-operations.
pub const TFD_CREATE: u64 = 0;
pub const TFD_ARM: u64 = 1;
pub const TFD_RELEASE: u64 = 2;

/// `Park` args: [I/O generation seen before the attempt, deadline or `NO_DEADLINE`,
/// descriptor or -1, `PARK_IN`/`PARK_OUT`/`PARK_LOCK`/`PARK_OPEN`, syscall number, descriptor count].
/// Reply 0 (re-attempt) or -EINTR.
pub const PARK_IN: u64 = 1;
pub const PARK_OUT: u64 = 2;
pub const PARK_LOCK: u64 = 3;
pub const PARK_OPEN: u64 = 4;

/// Decision code: timerfd expiry (args: [key, expirations added]).
pub const DEC_TIMERFD: u32 = 0x101;

impl Op {
    pub fn from_u32(v: u32) -> Option<Op> {
        use Op::*;
        const ALL: [Op; 31] = [
            Hello,
            Yield,
            Sleep,
            FutexWait,
            FutexWake,
            FutexRequeue,
            Park,
            ThreadExit,
            ProcExit,
            Forked,
            VforkStart,
            Exec,
            WaitPark,
            SigSend,
            SigWait,
            SigSuspend,
            TimerSet,
            CrashPoint,
            Stop,
            HostError,
            SigTake,
            SigAction,
            TimerFdSet,
            TimerFdGet,
            WireSocket,
            WireBind,
            WireConnect,
            WireAccepted,
            WireSent,
            WireQuery,
            SdkViolation,
        ];
        ALL.iter().copied().find(|o| *o as u32 == v)
    }
    pub fn name(self) -> &'static str {
        use Op::*;
        match self {
            Hello => "Hello",
            Yield => "Yield",
            Sleep => "Sleep",
            FutexWait => "FutexWait",
            FutexWake => "FutexWake",
            FutexRequeue => "FutexRequeue",
            Park => "Park",
            ThreadExit => "ThreadExit",
            ProcExit => "ProcExit",
            Forked => "Forked",
            VforkStart => "VforkStart",
            Exec => "Exec",
            WaitPark => "WaitPark",
            SigSend => "SigSend",
            SigWait => "SigWait",
            SigSuspend => "SigSuspend",
            TimerSet => "TimerSet",
            CrashPoint => "CrashPoint",
            Stop => "Stop",
            HostError => "HostError",
            SigTake => "SigTake",
            SigAction => "SigAction",
            TimerFdSet => "TimerFdSet",
            TimerFdGet => "TimerFdGet",
            WireSocket => "WireSocket",
            WireBind => "WireBind",
            WireConnect => "WireConnect",
            WireAccepted => "WireAccepted",
            WireSent => "WireSent",
            WireQuery => "WireQuery",
            SdkViolation => "SdkViolation",
        }
    }
}

/// Host-error codes carried in `HostError` args[2].
pub const HE_SYSCALL: u64 = 0;
pub const HE_RUNTIME_ASSERT: u64 = 1;
pub const HE_LOADER: u64 = 2;
pub const HE_GUEST_FAULT_IN_RUNTIME: u64 = 3;
/// A real signal from outside the sandbox is pending (args[0] = the signal number).
pub const HE_OUTSIDE_SIGNAL: u64 = 4;
/// The trap frame's real signal mask changed (runtime invariant).
pub const HE_REAL_MASK: u64 = 5;
/// A limit that belongs to the host, not the sandbox, was reached by a passed call:
/// the launcher's own `RLIMIT_FSIZE` (inherited by the sandbox and enforced by the kernel), or
/// the kernel's per-host-user pipe page accounting (`pipe-user-pages-soft`), which every
/// process of the launching user shares. args[0] = errno, args[1] = syscall.
pub const HE_HOST_LIMIT: u64 = 6;
/// Counter preemption could not keep its guarantee: args[0] = `PMU_E_*`, args[1] a value.
pub const HE_PMU: u64 = 7;
pub const PMU_E_OVERSHOOT: u64 = 1;
pub const PMU_E_MISSED: u64 = 2;
pub const PMU_E_DECODE: u64 = 3;
pub const PMU_E_OPEN: u64 = 4;
pub const PMU_E_PAGE: u64 = 5;

/// Signal requests.
///
/// - `SigSend`: [mode, pid, tid, signal, 0, 0], the siginfo in the caller's slot. Modes:
///   `SIGSEND_PROC` (kill: process `pid`), `SIGSEND_TGKILL` (thread `tid` of `pid`),
///   `SIGSEND_TKILL` (thread `tid`). Signal 0 checks existence only. Reply 0 or -errno.
/// - `SigWait`: [set, deadline or `NO_DEADLINE`]: `rt_sigtimedwait`. Reply: the signal (siginfo
///   in the slot), 0 on timeout, -EINTR if another signal interrupted.
/// - `SigSuspend`: []: park until a signal is deliverable (the caller installed its temporary
///   mask first). Reply -EINTR.
/// - `TimerSet`: [which, value ns, interval ns, 1 to only read]: `setitimer`/`getitimer`/`alarm`
///   for `ITIMER_REAL`. The old [value ns, interval ns] are written to the slot's siginfo words.
pub const SIGSEND_PROC: u64 = 0;
pub const SIGSEND_TGKILL: u64 = 1;
pub const SIGSEND_TKILL: u64 = 2;
/// Every process of the group `pid` (`kill(-pgid)`, `kill(0)` with the caller's group).
pub const SIGSEND_PGRP: u64 = 3;
/// Every process except PID 1 and the caller (`kill(-1)`).
pub const SIGSEND_ALL: u64 = 4;

/// Processes.
///
/// - `Hello`: [pid, tid, `HELLO_*`, vfork parent slot]. For `HELLO_IMAGE` the reply's `ret` is
///   the set of signals whose disposition is `SIG_IGN` (bit `sig - 1`), carried across `execve`;
///   the thread's mask is in its slot.
/// - `Forked`: [child slot, child tid, child pid, `FORKED_*`, exit signal].
/// - `VforkStart`: [child slot, 0 = start | 1 = the clone failed]: start parks the caller (it keeps
///   the turn until it blocks in the kernel); the child's `Hello` (`HELLO_VFORK`) follows.
/// - `Exec`: [`SIG_IGN` set]: the caller is about to re-execute the runtime. The supervisor retires
///   the process's other threads, gives the image a new address space and records the dispositions.
/// - `WaitPark`: [`WAIT_PARK`]: park until a child of the caller's process passes its exit barrier;
///   reply 0 or -EINTR. [`WAIT_REAPED`, pid, 1 if the child was really reaped (not `WNOWAIT`)]:
///   reply the status word to report (the real one unless the death was by a virtual signal),
///   or -1 if the supervisor has no record.
/// - `SigAction` [0, `SIGACT_PDEATHSIG`, signal]: `PR_SET_PDEATHSIG`.
///   [17, kind, 1 if `SA_NOCLDWAIT` or `SIG_IGN`]: SIGCHLD's kind and whether children are auto-reaped.
pub const HELLO_IMAGE: u64 = 0;
pub const HELLO_THREAD: u64 = 1;
pub const HELLO_FORK: u64 = 2;
pub const HELLO_VFORK: u64 = 3;
pub const FORKED_THREAD: u64 = 0;
pub const FORKED_PROCESS: u64 = 1;
pub const WAIT_PARK: u64 = 0;
pub const WAIT_REAPED: u64 = 1;
pub const SIGACT_PDEATHSIG: u64 = 100;
/// Futex addresses with this bit set name memory shared across processes (`MAP_SHARED`):
/// the runtime encodes (mapping id, offset) and the supervisor keys them globally.
pub const FUTEX_SHARED_BIT: u64 = 1 << 63;
/// Decision code: a process passed its exit barrier (args: [pid, status word, virtual signal, parent]).
pub const DEC_PROC_GONE: u32 = 0x130;

/// Signals whose default action is "ignore" (SIGCHLD, SIGCONT, SIGURG, SIGWINCH).
pub const fn sig_default_ignored(sig: u64) -> bool {
    matches!(sig, 17 | 18 | 23 | 28)
}

/// Disposition kinds the supervisor needs (per process, per signal).
pub const SIGK_DEFAULT: u64 = 0;
pub const SIGK_IGNORE: u64 = 1;
pub const SIGK_HANDLER: u64 = 2;

impl Ctl {
    /// # Safety
    /// `base` must point at a mapped control region of `CTL_SIZE` bytes.
    pub unsafe fn at<'a>(base: *mut u8) -> &'a Ctl {
        &*(base as *const Ctl)
    }
    /// # Safety
    /// `self` must be the header of a full control region.
    pub unsafe fn slot(&self, i: usize) -> *mut Slot {
        let base = self as *const Ctl as *mut u8;
        base.add(CTL_HEADER_SIZE + i * core::mem::size_of::<Slot>()) as *mut Slot
    }
    pub fn note_denied(&self, nr: u64) {
        if nr < 512 {
            self.denied[(nr / 64) as usize].fetch_or(1 << (nr % 64), Ordering::Relaxed);
        }
    }
    pub fn denied_nrs(&self) -> impl Iterator<Item = u64> + '_ {
        (0..512u64).filter(move |nr| {
            self.denied[(*nr / 64) as usize].load(Ordering::Relaxed) & (1 << (nr % 64)) != 0
        })
    }
    /// Initialise a zeroed region (launcher).
    ///
    /// # Safety
    /// `this` must point at a mapped, writable, zeroed control region nobody else uses yet.
    pub unsafe fn init(this: *mut Ctl, cfg: Config) {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*this).config), cfg);
        let s = &*this;
        s.init_rest();
    }
    fn init_rest(&self) {
        self.vclock_ns
            .store(crate::layout::VCLOCK_BOOT_NS, Ordering::Relaxed);
        self.next_deadline_ns.store(u64::MAX, Ordering::Relaxed);
        self.stop_nr.store(u64::MAX, Ordering::Relaxed);
        self.layout_version.store(LAYOUT_VERSION, Ordering::Relaxed);
        self.magic.store(MAGIC, Ordering::Release);
    }
    pub fn check(&self) -> bool {
        self.magic.load(Ordering::Acquire) == MAGIC
            && self.layout_version.load(Ordering::Relaxed) == LAYOUT_VERSION
    }
}
