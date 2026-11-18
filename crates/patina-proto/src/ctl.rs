//! Control region: the first page (`Ctl`) followed by `MAX_THREADS` slots.
//! Shared between every guest process (mapped where `rt::state::map_shared` draws), the supervisor
//! and, after the run, the launcher. Written only by whoever holds the turn.

use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

pub const MAGIC: u64 = 0x7461_705f_6c74_6321; // "!ctl_pat"
pub const LAYOUT_VERSION: u64 = 13;
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
    /// Scheduling points beyond traps (`SCHED_*` bits).
    pub sched: u64,
    /// Instruction channels (`INSN_*` bits).
    pub insn: u64,
    /// Virtual time charged to a pause point or a spin yield.
    pub spin_charge_ns: u64,
    /// Compute points (`crate::compute`): the run's mean gap in events (0: no seeded switches;
    /// time is still charged, deadlines still cut, and the cell still yields every `REFILL`), and the virtual time one event costs.
    pub compute_gap: u64,
    pub compute_charge_ns: u64,
    /// The most bytes this incarnation's logs (the boundary log and the operation log) may
    /// hold (`--log-limit`, less what earlier incarnations wrote). The append that would pass
    /// it ends the run `log-limit` instead: a count of records, never of wall time, so a seed
    /// ends at the same record in every run.
    pub log_limit: u64,
    /// The guest path of the work tree, the crash-modelled tmpfs (`--work DIR:GUEST`),
    /// NUL-padded; all zero is `/work`.
    pub work: [u8; WORK_PATH_MAX],
}

/// The longest work tree path, with its NUL.
pub const WORK_PATH_MAX: usize = 64;

impl Config {
    /// The work tree's guest path.
    pub fn work_path(&self) -> &[u8] {
        let n = self
            .work
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(WORK_PATH_MAX);
        if n == 0 {
            b"/work"
        } else {
            &self.work[..n]
        }
    }
    /// Is `p` the work tree or under it?
    pub fn on_work(&self, p: &[u8]) -> bool {
        crate::vfs::under(p, self.work_path())
    }
}

/// `Config::sched`: `pause` sites are patched and each executed `pause` yields.
pub const SCHED_PAUSE_POINTS: u64 = 1;
/// `Config::sched`: the supervisor may probe a thread that computes without a boundary event
/// for a spin-wait whose iterations leave its state unchanged (`rt::spin`).
pub const SCHED_SPIN_PROBE: u64 = 2;
/// `Config::sched`: spin probes were asked for and this host cannot make them work
/// (`patina doctor`'s "spin probes"): they are off, and a `compute-stall` says why.
pub const SCHED_SPIN_HOST_OFF: u64 = 4;

/// `SchedStats::spin_host`: what a probe found this host refusing, as `SPIN_HOST_* << 32 |
/// errno` (the first one; 0: nothing).
pub const SPIN_HOST_MEM: u64 = 1;
pub const SPIN_HOST_TRACK: u64 = 2;
pub const SPIN_HOST_POKE: u64 = 3;
pub const SPIN_HOST_EXTRA: u64 = 4;

/// What a `SchedStats::spin_host` value names, for a `compute-stall` message.
pub fn spin_host_text(v: u64) -> Option<&'static str> {
    Some(match v >> 32 {
        0 => return None,
        SPIN_HOST_MEM => "/proc/self/mem or /proc/self/pagemap could not be opened",
        SPIN_HOST_TRACK => "written pages could not be tracked (soft-dirty bits on x86_64, userfaultfd write protection on arm64)",
        SPIN_HOST_POKE => "the kernel refused a write to code through /proc/self/mem (proc_mem.force_override)",
        SPIN_HOST_EXTRA => "the thread's register state is larger than a probe compares (arm64: SME's ZA storage in use; x86_64: an XSAVE area over 8 KiB)",
        _ => "an unknown host refusal",
    })
}

/// `Config::insn` (arm64): answer `RNDR`/`RNDRRS` from the seed and advertise them
/// (`HWCAP2_RNG`) even on a host without them: the test of that path on such hosts
/// (`[run] emulate-rndr`).
pub const INSN_EMULATE_RNDR: u64 = 1;

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
            sched: 0,
            insn: 0,
            spin_charge_ns: 0,
            compute_gap: 0,
            compute_charge_ns: 0,
            log_limit: crate::layout::LOG_MAX,
            work: [0; WORK_PATH_MAX],
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
    /// Operation-log bytes that do not count against `Config::log_limit`: the base records of
    /// the incarnation's starting work tree, written by the supervisor before the program runs.
    pub log_exempt: AtomicU64,
    pub _spare: [AtomicU64; 4],
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
    /// Pause points and spin probes, summed over every process of the run.
    pub sched: SchedStats,
    /// Compute points, summed over every process of the run.
    pub compute: ComputeStats,
}

/// Compute points (`crate::compute`).
#[repr(C)]
pub struct ComputeStats {
    /// `COMPUTE_HELLO` calls answered with the cell, and the event kinds they named (or'ed).
    pub hellos: AtomicU64,
    pub kinds: AtomicU64,
    /// Events charged; points that consulted the supervisor because the gap or the longest
    /// run (`compute::REFILL`) ran out (`switches`), or a deadline fell due (`deadline_stops`).
    pub events: AtomicU64,
    pub switches: AtomicU64,
    pub deadline_stops: AtomicU64,
}

impl ComputeStats {
    /// [hellos, kinds, events, switches, deadline_stops].
    pub fn read(&self) -> [u64; 5] {
        let r = |a: &AtomicU64| a.load(Ordering::Relaxed);
        [
            r(&self.hellos),
            r(&self.kinds),
            r(&self.events),
            r(&self.switches),
            r(&self.deadline_stops),
        ]
    }
}

/// Pause points and spin probes (`SCHED_NAMES` order in the outcome).
#[repr(C)]
pub struct SchedStats {
    /// Executed `pause` instructions at patched sites (each a scheduling point; the sites
    /// are `InsnCtl::patched[4]`).
    pub pause_points: AtomicU64,
    /// Probes the supervisor sent that reached guest code; of them, the ones that found a
    /// spin-wait whose iteration is a fixed point.
    pub spin_probes: AtomicU64,
    pub spin_found: AtomicU64,
    /// Yields at a found spin point (the first at each find, then one per arrival).
    pub spin_yields: AtomicU64,
    /// Single steps taken by probes.
    pub spin_steps: AtomicU64,
    /// What a probe found the host refusing (`SPIN_HOST_*`); not in the outcome's `sched`.
    pub spin_host: AtomicU64,
}
pub const SCHED_FIELDS: usize = 5;
pub const SCHED_NAMES: [&str; SCHED_FIELDS] = [
    "pause_points",
    "spin_probes",
    "spin_found",
    "spin_yields",
    "spin_steps",
];

impl SchedStats {
    pub fn read(&self) -> [u64; SCHED_FIELDS] {
        let r = |a: &AtomicU64| a.load(Ordering::Relaxed);
        [
            r(&self.pause_points),
            r(&self.spin_probes),
            r(&self.spin_found),
            r(&self.spin_yields),
            r(&self.spin_steps),
        ]
    }
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
    /// Sites patched, by `proto::insn::SiteKind` (x86_64: 1 rdrand, 2 rdseed, 4 pause; arm64:
    /// 1 rndr, 2 rndrrs, 4 pause).
    pub patched: [AtomicU64; 5],
    /// Emulated executions, by `INSN_*` index.
    pub emulated: [AtomicU64; 8],
    /// Executable mappings whose code the scanner could not see or vouch for: anonymous
    /// memory made executable (JIT) and shared file mappings (their bytes can change later).
    pub unscanned_exec_mappings: AtomicU64,
    /// Candidates the scanner refused (bytes inside another instruction, or skipped by the
    /// sweep), and candidates beyond the per-mapping limit. A refused real site would run
    /// unpatched; the count makes that visible.
    pub rejected_sites: AtomicU64,
    /// Sites seen and left alone, counted: `rdpid` on x86_64 (it reads the pinned core: no
    /// system ELF file seen has one), `pacga` on arm64 (its key cannot be disabled).
    pub counted_sites: AtomicU64,
    /// Executable file mappings scanned, and their bytes.
    pub scanned_mappings: AtomicU64,
    pub scanned_bytes: AtomicU64,
    /// Sites that could not be recorded because the side table was full (also rejected).
    pub table_full: AtomicU64,
}

/// Indexes of `InsnCtl::emulated`, and their names in `result.json`.
#[cfg(target_arch = "x86_64")]
pub const INSN_RDTSC: usize = 0;
#[cfg(target_arch = "x86_64")]
pub const INSN_RDTSCP: usize = 1;
#[cfg(target_arch = "x86_64")]
pub const INSN_RDRAND: usize = 2;
#[cfg(target_arch = "x86_64")]
pub const INSN_RDSEED: usize = 3;
#[cfg(target_arch = "x86_64")]
pub const INSN_RDPID: usize = 4;
#[cfg(target_arch = "x86_64")]
pub const INSN_NAMES: &[&str] = &["rdtsc", "rdtscp", "rdrand", "rdseed", "rdpid"];
/// arm64: reads of the counter (`CNTVCT_EL0`, `CNTVCTSS_EL0`) and of its frequency, and the
/// random-number reads.
#[cfg(target_arch = "aarch64")]
pub const INSN_CNTVCT: usize = 0;
#[cfg(target_arch = "aarch64")]
pub const INSN_CNTFRQ: usize = 1;
#[cfg(target_arch = "aarch64")]
pub const INSN_RNDR: usize = 2;
#[cfg(target_arch = "aarch64")]
pub const INSN_RNDRRS: usize = 3;
#[cfg(target_arch = "aarch64")]
pub const INSN_NAMES: &[&str] = &["cntvct", "cntfrq", "rndr", "rndrrs"];

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
/// the network wire's table (`wire::WireTab`), the SDK's site table (`sdk::SdkTab`), then the
/// compute-point image table (`ComputeTab`).
pub const CTL_SIZE: usize = COMPUTE_TAB_OFFSET + COMPUTE_TAB_SIZE;

/// Images listed in `ComputeTab`, and the bytes of each one's path kept (its end).
pub const IMAGES_MAX: usize = 32;
pub const IMAGE_TAIL: usize = 96;

/// One program image that said `COMPUTE_HELLO` (`crate::compute`), keyed by its guest path.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ComputeImage {
    /// A hash of the whole path, never 0 (0: the entry is free).
    pub key: u64,
    /// The whole path's length; `tail` holds its last `IMAGE_TAIL` bytes at most.
    pub path_len: u64,
    /// Event kinds its hook copies named (`sdk::COMPUTE_*`, or'ed).
    pub kinds: u64,
    /// Processes that started this image and said hello (a fork child inherits its parent's
    /// hello and is not another start).
    pub starts: u64,
    pub tail: [u8; IMAGE_TAIL],
}

impl ComputeImage {
    pub fn tail(&self) -> &[u8] {
        &self.tail[..(self.path_len as usize).min(IMAGE_TAIL)]
    }
    /// The path was longer than the tail kept.
    pub fn cut(&self) -> bool {
        self.path_len as usize > IMAGE_TAIL
    }
}

/// The run's compute-point images, after the SDK's site table in the control region. Written
/// by the runtime under the turn at `COMPUTE_HELLO`, read by the launcher after the run.
#[repr(C)]
pub struct ComputeTab {
    pub n: u64,
    /// Starts of images that did not fit.
    pub dropped: u64,
    pub images: [ComputeImage; IMAGES_MAX],
}

pub const COMPUTE_TAB_OFFSET: usize =
    (crate::sdk::SDK_OFFSET + crate::sdk::SDK_SIZE + 0xFFF) & !0xFFF;
pub const COMPUTE_TAB_SIZE: usize = core::mem::size_of::<ComputeTab>();

impl ComputeTab {
    /// # Safety
    /// `ctl_base` must point at a full control region of `CTL_SIZE` bytes.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn at<'a>(ctl_base: *mut u8) -> &'a mut ComputeTab {
        &mut *(ctl_base.add(COMPUTE_TAB_OFFSET) as *mut ComputeTab)
    }

    /// A hello from an image at `path` naming `kinds`; `start` for the first hello of its
    /// address space. A new path when the table is full counts in `dropped`.
    pub fn note(&mut self, path: &[u8], kinds: u64, start: bool) {
        let key = crate::rec::hash_bytes(0x696d_6167_6573, path) | 1;
        let t = &path[path.len().saturating_sub(IMAGE_TAIL)..];
        let n = (self.n as usize).min(IMAGES_MAX);
        let i = match self.images[..n]
            .iter()
            .position(|e| e.key == key && e.path_len == path.len() as u64 && e.tail() == t)
        {
            Some(i) => i,
            None if n < IMAGES_MAX => {
                let e = &mut self.images[n];
                e.key = key;
                e.path_len = path.len() as u64;
                e.tail[..t.len()].copy_from_slice(t);
                self.n += 1;
                n
            }
            None => {
                self.dropped += start as u64;
                return;
            }
        };
        let e = &mut self.images[i];
        e.kinds |= kinds;
        e.starts += start as u64;
    }

    pub fn used(&self) -> &[ComputeImage] {
        &self.images[..(self.n as usize).min(IMAGES_MAX)]
    }
}

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
    /// Datagram sockets, see `UDP_*` below.
    UdpSocket = 56,
    UdpBind = 57,
    UdpConnect = 58,
    UdpSend = 59,
    /// A failed `always` (`sdk`): the run ends as `violation`; the message is in the SDK table.
    /// args: [op, payload pointer, length] of the trap. Never answered.
    SdkViolation = 60,
    /// The virtual time table is 3/4 full: drop the entries of inodes nothing can reach any
    /// more (`vfs::VtEntry::gone_dev`). Reply 0.
    VtReclaim = 61,
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

/// Datagram-socket requests (`patina/src/sup/udp.rs`). Socket indexes as for the wire.
///
/// - `UdpSocket`: [index, family]: the runtime connected the real `SOCK_SEQPACKET` socket to
///   `@patina-udp` and sent the preamble. Reply 0.
/// - `UdpBind`: [index, port (0: allocate), address kind, `UDP_REUSEADDR`|`UDP_REUSEPORT`|`UDP_V6ONLY`].
///   Reply the port or -errno (`EADDRINUSE`, `EADDRNOTAVAIL`).
/// - `UdpConnect`: [index, port, address kind, 1: connect | 0: disconnect | 2: the read side
///   was shut down (queue a wake marker)]. Reply 0.
/// - `UdpSend`: [index, destination port, destination address kind, payload bytes]: the
///   runtime has written the payload as one packet; the supervisor reads it now. Reply 0.
pub const UDP_REUSEADDR: u64 = 1;
pub const UDP_REUSEPORT: u64 = 2;
pub const UDP_V6ONLY: u64 = 4;
/// Decision codes of datagrams: `DEC_UDP_SEND` [id, source port, destination port, bytes,
/// delivery time (0: lost), fate (`UF_*` bits)]; `DEC_UDP_DELIVER` [id, receiving socket
/// index + 1 (0: none), bytes, outcome (`UD_*`), 1 for a duplicate]; `DEC_UDP_CLOSE` [index, port].
pub const DEC_UDP_SEND: u32 = 0x147;
pub const DEC_UDP_DELIVER: u32 = 0x148;
pub const DEC_UDP_CLOSE: u32 = 0x149;

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
        const ALL: [Op; 36] = [
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
            UdpSocket,
            UdpBind,
            UdpConnect,
            UdpSend,
            SdkViolation,
            VtReclaim,
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
            UdpSocket => "UdpSocket",
            UdpBind => "UdpBind",
            UdpConnect => "UdpConnect",
            UdpSend => "UdpSend",
            SdkViolation => "SdkViolation",
            VtReclaim => "VtReclaim",
        }
    }
}

/// Host-error codes carried in `HostError` args[2].
pub const HE_SYSCALL: u64 = 0;
pub const HE_RUNTIME_ASSERT: u64 = 1;
/// The runtime gave up setting up a process: args[1] = the `Setup` step, args[0] = the errno
/// of the call that failed (0 when the step failed a check rather than a call).
pub const HE_LOADER: u64 = 2;
/// A fault inside the runtime: args[0] = the signal, args[1] = the faulting instruction or
/// address.
pub const HE_GUEST_FAULT_IN_RUNTIME: u64 = 3;

macro_rules! setup_steps {
    ($($v:ident = $s:literal),* $(,)?) => {
        /// The step at which the runtime gave up setting up a process (`HE_LOADER`).
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        #[repr(u64)]
        pub enum Setup {
            Unknown = 0,
            $($v,)*
        }
        impl Setup {
            pub fn name(self) -> &'static str {
                match self {
                    Setup::Unknown => "an unknown step",
                    $(Setup::$v => $s,)*
                }
            }
            pub fn from_code(c: u64) -> Self {
                $(if c == Setup::$v as u64 {
                    return Setup::$v;
                })*
                Setup::Unknown
            }
        }
    };
}

setup_steps! {
    Usage = "usage: rt <path> <argv0> [args...]",
    PathTooLong = "guest path too long",
    OpenImage = "cannot open guest image",
    NotElf = "not a 64-bit ELF image of this architecture",
    ElfType = "ELF image is neither ET_EXEC nor ET_DYN",
    PhdrTable = "unsupported program header table",
    PhdrRead = "short program header read",
    NoLoad = "no loadable segments",
    ImageInRuntime = "guest image overlaps the runtime",
    ReserveImage = "cannot reserve the guest image range",
    MapSegment = "cannot map a segment",
    MapBss = "cannot map .bss",
    PhdrNotLoaded = "program headers are not inside a loaded segment",
    Brk = "cannot reserve brk",
    Stack = "cannot map the guest stack",
    TooManyArgs = "too many arguments or environment strings",
    AltStack = "cannot map alternate stack",
    CtlMap = "cannot map control region (descriptor 3000)",
    CtlCheck = "control region magic or layout mismatch",
    SigAltStack = "sigaltstack",
    SigactionSys = "sigaction SIGSYS",
    SigactionFault = "sigaction fault",
    SigactionIgnore = "sigaction ignore",
    NoNewPrivs = "no_new_privs",
    Seccomp = "seccomp",
    NoSlot = "no slot reserved for this task",
    SetTsc = "PR_SET_TSC",
    Panic = "runtime panic",
    PacKeys = "PR_PAC_SET_ENABLED_KEYS",
    RestorerPage = "cannot map the signal restorer page",
    Counters = "branch counters are not supported on this architecture",
}
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
/// Program code reached into the runtime: args[0] = `CONTAIN_*`, args[1] = the address,
/// args[3] = the program's instruction pointer, args[4] = 1 for a store.
pub const HE_CONTAINMENT: u64 = 8;
/// A load or store at an address of the runtime's region (the control region's or the
/// boundary log's published address, or any other part).
pub const CONTAIN_ACCESS: u64 = 0;
/// Program code ran runtime code (a jump into the runtime's text) at the address.
pub const CONTAIN_EXEC: u64 = 1;
/// A jump to the runtime's one permitted `syscall` instruction: the call reached the kernel
/// at most once, and the run ends when it returns, before any program code sees its result.
pub const CONTAIN_STUB: u64 = 2;
/// Any other `syscall` instruction in the runtime's text: trapped, never made.
pub const CONTAIN_SYSCALL: u64 = 3;
/// Compute points: the cell page could not be mapped, read or written (the program mapped
/// over it, unmapped or protected it). args[0] = the errno, args[1] = 1 for the mapping.
pub const HE_COMPUTE_CELL: u64 = 9;
/// The run's logs reached `Config::log_limit` (the append that would pass it was not made).
pub const HE_LOG_LIMIT: u64 = 10;
/// A fixed-capacity table of the runtime filled with entries the program still uses:
/// args[0] = `LIMIT_*`, args[1] = the capacity. The run ends `unsupported`, stop `capacity`.
pub const HE_CAPACITY: u64 = 11;
/// The host filesystem holding the run directory is full: args[0] = errno, args[1] = syscall.
pub const HE_DISK_FULL: u64 = 12;

/// A signal frame the runtime does not build: the trap frame (or, at `rt_sigreturn`, the
/// program's frame) holds a context record outside those the runtime normalises (arm64:
/// streaming SVE mode, the SME ZA array or ZT0 in use, GCS, an extra-context
/// record, or a magic it does not know). args[0] = the record's magic. The run ends
/// `unsupported`, stop `signal-context`.
pub const HE_SIGNAL_CONTEXT: u64 = 14;

/// The name of an arm64 signal context record (`HE_SIGNAL_CONTEXT`), for its message.
pub fn signal_context_name(magic: u64) -> &'static str {
    match magic {
        0x5356_4501 => "the SVE record in streaming mode",
        0x5436_6345 => "the SME ZA array in use",
        0x5a54_4e01 => "the SME2 ZT0 register",
        0x4743_5300 => "the guarded control stack",
        0x4558_5401 => "an extra-context record (a frame larger than 4096 bytes of records)",
        _ => "a record of unknown kind",
    }
}

macro_rules! limits {
    ($($v:ident = $n:literal: $s:literal),* $(,)?) => {
        $(pub const $v: u64 = $n;)*
        /// What the table of a `HE_CAPACITY` stop holds, for its message.
        pub fn limit_name(l: u64) -> &'static str {
            match l {
                $($n => $s,)*
                _ => "an unknown table",
            }
        }
    };
}

limits! {
    LIMIT_VTIME = 1: "files and directories changed in this run and still reachable (the virtual time table)",
    LIMIT_VINO = 2: "pipes, sockets, timers and other anonymous objects seen in this run (the virtual inode table)",
    LIMIT_SHARED_MAPS = 3: "shared, writable mappings of work-tree files open at once in one process",
    LIMIT_FSYNC_FAILURES = 4: "files given an injected fsync failure",
    LIMIT_DESCRIPTORS = 5: "open file descriptors (the runtime needs a few of its own)",
    LIMIT_SHARED = 6: "shared mappings in one process, a writable one among them (the runtime keys process-shared futexes by them)",
    LIMIT_RUNTIME_MEMORY = 7: "bytes of runtime memory used over one process's life (a copy of each shared, writable work-tree mapping, and the threads' stacks)",
}

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
    /// Bytes of this incarnation's logs that count against `Config::log_limit`.
    pub fn log_used(&self) -> u64 {
        let r = |a: &AtomicU64| a.load(Ordering::Relaxed);
        (r(&self.log_len) + r(&self.oplog_len) + r(&self.opdata_len))
            .saturating_sub(r(&self.log_exempt))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn images_are_keyed_by_path_and_overflow_is_counted() {
        // SAFETY: every field is an integer or an array of them.
        let mut t: ComputeTab = unsafe { core::mem::zeroed() };
        for _ in 0..3 {
            t.note(b"/guest/a", 1, true);
        }
        t.note(b"/guest/a", 2, false);
        assert_eq!(t.used().len(), 1);
        let a = &t.used()[0];
        assert_eq!(
            (a.tail(), a.kinds, a.starts, a.cut()),
            (&b"/guest/a"[..], 3, 3, false)
        );
        // Two long paths with one tail are two images.
        let long = |c: u8| {
            let mut p = [b'x'; IMAGE_TAIL + 20];
            p[0] = c;
            p
        };
        t.note(&long(b'/'), 1, true);
        t.note(&long(b'.'), 1, true);
        assert_eq!(t.used().len(), 3);
        assert!(t.used()[1].cut() && t.used()[1].tail().len() == IMAGE_TAIL);
        let total = IMAGES_MAX + 5;
        for i in 0..total as u8 {
            let p = [b'/', b'p', b'/', i];
            t.note(&p, 1, true);
            t.note(&p, 1, false);
        }
        let listed = IMAGES_MAX - 3;
        assert_eq!(t.used().len(), IMAGES_MAX);
        assert_eq!(t.dropped as usize, total - listed);
        assert!(t.used()[3..].iter().all(|e| e.starts == 1));
    }
}
