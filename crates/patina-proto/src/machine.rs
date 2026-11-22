//! Machines: several machines in one run. Machine 0 is main (the command after `--`); the
//! machines a run declares (`[machine.NAME]`) are 1 upward, in declaration order. Every machine has its
//! own view of the sandbox (disk, `/tmp`, `/dev/shm`, hostname, IPC), its own port space
//! and the address `10.0.0.(machine + 1)`; one supervisor, clock, log and seed serve them all.
//!
//! The machine table sits in the control region after the instruction scans: the launcher writes
//! it before the run, the runtime reads it to parse a control call's words and to know which
//! addresses exist. A run without machines has `n == 0` and nothing here is consulted.
//!
//! A control call (`sdk::OP_CONTROL`) carries words, named as the fault classes are; the
//! grammar (also in `sdk/c/patina.h`):
//!
//! ```text
//! partition A B                both directions between the sets A and B are cut
//! partition --from A --to B    one direction: what A sends to B is held
//! heal                         every scripted cut
//! heal A B                     both directions between A and B
//! heal --from A --to B         one direction
//! crash NAME                   crash the machine: its unsynced writes may be lost, it
//!                              stays down, silent (EALREADY: down)
//! kill NAME                    kill every process of the machine; it stays down (EALREADY: down)
//! start NAME                   start a machine that is down, as at a restart (EALREADY: up or
//!                              starting; EAGAIN: past 64 boots)
//! pause NAME                   freeze every thread of the machine until `resume` (EALREADY:
//!                              paused; EAGAIN: down or starting)
//! resume NAME                  end its pause (EALREADY: not paused)
//! clock NAME +90s              move the machine's realtime clock (+Ns, -Ns, +Nms, -Nms; at most
//!                              a year): its absolute realtime timers move with it
//! settle [SECONDS]             end the seed's faults and wait until every machine is ready
//!                              again (the run ends `liveness`, stop `settle`, past SECONDS
//!                              of virtual time, default 60); also in a run without machines
//! ```
//!
//! A set is machine names joined by commas, or `rest`: every machine not in the other set. Only the
//! main may make a control call (elsewhere `EPERM`); an unknown name is `ENOENT`,
//! other words `EINVAL`, and so is any call but `settle` in a run without machines.

/// Main and at most 15 machines.
pub const MAX_MACHINES: usize = 16;
/// The longest machine name.
pub const NAME_MAX: usize = 32;
/// Main's name, and its hostname, whether or not other machines are declared.
pub const MAIN: &[u8] = b"main";
/// Names a machine cannot have besides `MAIN`, and why.
pub const RESERVED: &[(&[u8], &str)] = &[
    (b"rest", "a control call's word for every other machine"),
    (b"localhost", "the loopback name in /etc/hosts"),
];

#[repr(C)]
pub struct MachineTab {
    /// Machines, main included (0: a run without machines).
    pub n: u64,
    pub name_len: [u64; MAX_MACHINES],
    pub names: [[u8; NAME_MAX]; MAX_MACHINES],
    /// Written by the supervisor: each machine's first process (0: not started), and how it
    /// ended: `RUNNING`, or the status word (`(code & 0xff) << 8`, or the signal).
    pub first_pid: [u64; MAX_MACHINES],
    pub status: [u64; MAX_MACHINES],
    /// Scripted `partition` and `heal` calls served, and the links cut at the end (bit
    /// `to` of `cut_at_end[from]`).
    pub cuts: u64,
    pub heals: u64,
    pub cut_at_end: [u64; MAX_MACHINES],
    /// Connection directions a cut held (each counted once per hold).
    pub held: u64,
    /// The seed's partitions (`partition-*`), in order: how many were drawn, and the first
    /// `PARTS_MAX` of them.
    pub parts_n: u64,
    pub parts: [Part; PARTS_MAX],
    /// Partitions that acted on traffic, listed or not.
    pub parts_acted: u64,
    /// The link faults' chances on the links they act on (`NetCfg::links`), by `ELIG_*`: what a
    /// run with machines reports as their eligible counts.
    pub elig: [u64; ELIG_N],
    /// Written by the launcher: each machine's restart policy, boots and ok-exit statuses, and the
    /// run's machine kill and down-time settings.
    pub conf: [MachineConf; MAX_MACHINES],
    /// `crash-gap-ms` and `down-ms` (ns).
    pub crash_gap_min_ns: u64,
    pub crash_gap_max_ns: u64,
    pub down_min_ns: u64,
    pub down_max_ns: u64,
    /// Each machine's boots so far, and the first `BOOTS_MAX` of them.
    pub boots: [u64; MAX_MACHINES],
    pub boot: [[Boot; BOOTS_MAX]; MAX_MACHINES],
    /// The machine (plus 1) whose end ended the run (0: none did).
    pub ended_by: u64,
    /// Written by the launcher: each machine's disk, NUL-padded (main's is
    /// `Config::work`).
    pub work: [[u8; crate::ctl::WORK_PATH_MAX]; MAX_MACHINES],
    /// Written by the launcher: the file system model of a machine crash (`fs-model`; 0
    /// `ext4-ordered`, 1 `posix-strict`).
    pub fs_model: u64,
    /// Written by the supervisor: each machine's crashes so far.
    pub crashes: [u64; MAX_MACHINES],
    /// Each machine's disk and memory faults: its settings (written by the launcher) and its
    /// counters. Main's are the run's (`Ctl::faults`); entry 0 is unused.
    pub faults: [crate::faults::FaultCtl; MAX_MACHINES],
    /// Each machine's fault-point settings (`buggify`; written by the launcher). Main's are
    /// the run's (`sdk::SdkTab::cfg`); entry 0 is unused.
    pub sdk: [crate::sdk::SdkCfg; MAX_MACHINES],
    /// Written by the supervisor: each machine's pauses so far, the first `PAUSES_MAX` of them,
    /// and the virtual time it spent paused.
    pub pauses: [u64; MAX_MACHINES],
    pub pause: [[Pause; PAUSES_MAX]; MAX_MACHINES],
    pub paused_ns: [u64; MAX_MACHINES],
    /// Written by the supervisor: each machine's realtime clock offset (ns, two's complement):
    /// its boot's skew (`clock-skew-ms`) plus the script's steps (`clock NAME DELTA`) so far; the
    /// runtime adds it to every realtime time the machine reads or sets. Main's is 0.
    pub clock_off: [u64; MAX_MACHINES],
    /// The script's steps of each machine's clock: how many, and their sum (ns, two's
    /// complement). A timerfd with `TFD_TIMER_CANCEL_ON_SET` compares the count.
    pub clock_sets: [u64; MAX_MACHINES],
    pub clock_stepped: [u64; MAX_MACHINES],
    /// Written by the runtime, on a machine with `clock-skew-ms`: its realtime clock reads, and
    /// those under an offset other than 0 (the `clock` class's eligible and injected counts).
    pub clock_reads: [core::sync::atomic::AtomicU64; MAX_MACHINES],
    pub clock_reads_off: [core::sync::atomic::AtomicU64; MAX_MACHINES],
    /// Written by the supervisor in a run that declares a `ready` probe: the virtual time each
    /// machine (main included) was first ready, its probe's pass or, without one, its start
    /// (0: not yet).
    pub ready_ns: [u64; MAX_MACHINES],
}

impl MachineTab {
    /// Machine `k`'s realtime clock offset (ns).
    pub fn clock_offset(&self, k: usize) -> i64 {
        if k >= MAX_MACHINES {
            return 0;
        }
        // Written by the supervisor while no guest thread runs.
        unsafe { core::ptr::read_volatile(&self.clock_off[k]) as i64 }
    }
}

/// Pauses `MachineTab::pause` keeps per machine (later ones are counted, not listed).
pub const PAUSES_MAX: usize = 32;

/// One pause of a machine.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pause {
    /// Virtual time it began and ended (`to_ns` 0: in force when the run ended).
    pub from_ns: u64,
    pub to_ns: u64,
    /// Who paused it (`BY_SEED`, `BY_SCRIPT`), and how it ended (`PEND_*`).
    pub by: u64,
    pub end: u64,
}

/// Who acted (`Pause::by`, `DEC_MACHINE_PAUSE`).
pub const BY_SEED: u64 = 1;
pub const BY_SCRIPT: u64 = 2;
/// How a pause ended (`Pause::end`, `DEC_MACHINE_RESUME`): its drawn length ran out, the
/// script's `resume`, the machine went down (a kill or a machine crash of a paused machine), or
/// the faults ended (a `faults-done` mark ended the seed's pause, or the main command's end
/// before `--finally` ended every pause).
pub const PEND_SEED: u64 = 1;
pub const PEND_SCRIPT: u64 = 2;
pub const PEND_DOWN: u64 = 3;
pub const PEND_DONE: u64 = 4;

/// A pause's end as events and `result.json` name it (`in force`: the run ended first).
pub fn pause_end_name(end: u64) -> &'static str {
    match end {
        PEND_SEED => "seed",
        PEND_SCRIPT => "script",
        PEND_DOWN => "down",
        PEND_DONE => "faults-done",
        _ => "in force",
    }
}

/// Boots a machine may have at most (`max-boots` is capped by it, and so is `start`).
pub const BOOTS_MAX: usize = 64;

/// A machine's settings (`[machine.NAME]`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MachineConf {
    /// `RESTART_*`.
    pub restart: u64,
    /// `max-boots`: boots the seed's kills and `restart` may give it; the last has no
    /// seed-drawn kill.
    pub max_boots: u64,
    /// The seed's kills (scoped by `@MACHINE`): `SEED_KILL` kills its processes
    /// (`--faults kill`), `SEED_CRASH` crashes its machine (`--faults crash`); 0:
    /// none.
    pub crash: u64,
    /// Exit statuses of its command that stop the machine without a finding: bit `s` of
    /// `ok_exit[s / 64]`.
    pub ok_exit: [u64; 4],
    /// The seed's pauses (`pause-gap-ms`, `pause-ms`, ns; gap 0: none): the time from the
    /// run's start, and from each pause's end, to the next pause, and each pause's length.
    pub pause_gap_min_ns: u64,
    pub pause_gap_max_ns: u64,
    pub pause_min_ns: u64,
    pub pause_max_ns: u64,
    /// `clock-skew-ms` (ns; max 0: none): each boot's realtime clock offset is a draw in
    /// min..max, ahead or behind.
    pub skew_min_ns: u64,
    pub skew_max_ns: u64,
}

impl MachineConf {
    pub fn ok(&self, status: u64) -> bool {
        status < 256 && self.ok_exit[(status / 64) as usize] & (1 << (status % 64)) != 0
    }
}

/// `MachineConf::crash`.
pub const SEED_KILL: u64 = 1;
pub const SEED_CRASH: u64 = 2;

/// `restart`: start the machine again after the seed killed it (`crash`, the default), also
/// after its command exits with a status of its `ok-exit` (`always`), or never.
pub const RESTART_CRASH: u64 = 0;
pub const RESTART_ALWAYS: u64 = 1;
pub const RESTART_NEVER: u64 = 2;

/// One boot of a machine.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Boot {
    /// Its first process, and the virtual time it started and went down (0: still up).
    pub pid: u64,
    pub start_ns: u64,
    pub end_ns: u64,
    /// How it went down (`DOWN_*`), and the exit status or signal.
    pub how: u64,
    pub value: u64,
    /// The down time drawn for its restart (0: none queued).
    pub down_ns: u64,
    /// Where its output starts in the machine's stdout and stderr.
    pub out_off: u64,
    pub err_off: u64,
    /// With crashes at its crash points (`crash-permille`, `crash-at`): the points it
    /// passed (its `FaultCtl::crash_points` when it went down or the run ended), and the
    /// point its machine crashed at (0: it did not crash at one).
    pub points: u64,
    pub point: u64,
    /// The skew drawn for it (ns, two's complement; `clock-skew-ms`).
    pub skew_ns: u64,
}

/// How a boot of a machine ended (`Boot::how`, `DEC_MACHINE_DOWN`): its processes killed by the
/// seed or by a control call, its command exited with a status of its `ok-exit` or another,
/// or died on a signal Patina did not send.
pub const DOWN_KILL_SEED: u64 = 1;
pub const DOWN_KILL_SCRIPT: u64 = 2;
pub const DOWN_EXIT: u64 = 3;
pub const DOWN_FAILED: u64 = 4;
pub const DOWN_SIGNAL: u64 = 5;
/// Its machine crashed, by the seed (`--faults crash`) or by a control call (`crash NAME`).
pub const DOWN_CRASH_SEED: u64 = 6;
pub const DOWN_CRASH_SCRIPT: u64 = 7;

pub fn down_name(how: u64) -> &'static str {
    match how {
        DOWN_KILL_SEED => "killed",
        DOWN_KILL_SCRIPT => "killed by script",
        DOWN_EXIT => "exited",
        DOWN_FAILED => "failed",
        DOWN_SIGNAL => "crashed",
        DOWN_CRASH_SEED => "machine crash",
        DOWN_CRASH_SCRIPT => "machine crash by script",
        _ => "running",
    }
}

/// The `Injected` record of a seed-drawn machine kill: [`INJ_MACHINE_KILL`, machine, boot, machine,
/// point, 0] (`machine` 1 for a machine crash; `point` the crash point it came at, 0 for one
/// at a drawn time; class `crash`).
pub const INJ_MACHINE_KILL: u64 = 40;

/// Sub-keys of `draw(Stream::Machine, machine << 24 | boot << 16 | try << 8 | sub)`: the time from a
/// boot to the seed's kill (`try` counts kills that came while faults were off, each drawn
/// again), and a down time.
pub const NSUB_KILL: u64 = 1;
pub const NSUB_DOWN: u64 = 2;
/// Sub-keys of `draw(Stream::Machine, machine << 24 | n << 8 | sub)` for the machine's `n`-th pause (`n`
/// from 1, below 2^16): the gap before it and its length.
pub const NSUB_PAUSE_GAP: u64 = 3;
pub const NSUB_PAUSE_LEN: u64 = 4;
/// A boot's clock skew: keyed `machine << 24 | boot << 8 | MSUB_SKEW`.
pub const MSUB_SKEW: u64 = 7;

/// The `Injected` record of a seed-drawn pause: [`INJ_MACHINE_PAUSE`, machine, boot, ordinal, length
/// ns, 0] (class `pause`).
pub const INJ_MACHINE_PAUSE: u64 = 41;

/// `MachineTab::elig`: connections, deliveries, FINs, reads of sent data, datagrams.
pub const ELIG_CONNECTIONS: usize = 0;
pub const ELIG_CHUNKS: usize = 1;
pub const ELIG_FINS: usize = 2;
pub const ELIG_SENDS: usize = 3;
pub const ELIG_DATAGRAMS: usize = 4;
pub const ELIG_N: usize = 5;

/// Partitions `MachineTab::parts` keeps (later ones are counted, not listed).
pub const PARTS_MAX: usize = 64;

/// One partition the seed drew.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Part {
    /// Its ordinal (1 upward), its shape (`SHAPE_*`), and its two sides (machine bits).
    pub n: u64,
    pub shape: u64,
    pub a: u64,
    pub b: u64,
    /// Virtual time it started and ended (`to_ns` 0: in force when the run ended).
    pub from_ns: u64,
    pub to_ns: u64,
    /// Whether a cut link of it held or lost traffic, or kept a connect from completing.
    pub acted: u64,
    /// A bridge's machine, which keeps its links to both sides.
    pub bridge: u64,
}

/// Partition shapes, each drawn for a partition when the machines fit it. Each cuts the links
/// between two sides A and B of the faultable machines: `split` both ways, `isolate` one machine (A)
/// from all the others both ways, `oneway` only from A to B, and `bridge` both ways but for
/// one machine of B that still reaches both sides.
pub const SHAPE_SPLIT: u64 = 1;
pub const SHAPE_ISOLATE: u64 = 2;
pub const SHAPE_ONEWAY: u64 = 3;
pub const SHAPE_BRIDGE: u64 = 4;
pub const SHAPES: [(u64, &str); 4] = [
    (SHAPE_SPLIT, "split"),
    (SHAPE_ISOLATE, "isolate"),
    (SHAPE_ONEWAY, "oneway"),
    (SHAPE_BRIDGE, "bridge"),
];

pub fn shape_name(s: u64) -> &'static str {
    SHAPES.iter().find(|x| x.0 == s).map_or("unknown", |x| x.1)
}

/// The fewest faultable machines a shape needs (a bridge needs one machine besides two sides).
pub const fn shape_min_machines(s: u64) -> usize {
    if s == SHAPE_BRIDGE {
        3
    } else {
        2
    }
}

/// Sub-keys of `draw(Stream::Partition, ordinal << 16 | sub << 8 | i)`.
pub const PSUB_GAP: u64 = 1;
pub const PSUB_LEN: u64 = 2;
pub const PSUB_SHAPE: u64 = 3;
/// The shuffle of the faultable machines that makes the sides (`i`: the position).
pub const PSUB_ORDER: u64 = 4;
/// How many machines side A gets.
pub const PSUB_SIZE: u64 = 5;

/// The sides of a partition: from `machines` (the faultable ones, in order) and a draw function
/// `d(sub, i)`, the shape's (A, B, bridge) machine bit sets; `None` when the machines are too few.
/// `isolate` puts one machine in A; `bridge` takes one machine out of B, which keeps both sides.
pub fn sides(
    shape: u64,
    machines: &[usize],
    d: impl Fn(u64, u64) -> u64,
) -> Option<(u64, u64, u64)> {
    let n = machines.len();
    if n < shape_min_machines(shape) || n > MAX_MACHINES {
        return None;
    }
    // A keyed Fisher-Yates shuffle: position i draws among the ones not yet placed.
    let mut order = [0usize; MAX_MACHINES];
    order[..n].copy_from_slice(machines);
    for i in (1..n).rev() {
        let j = (d(PSUB_ORDER, i as u64) % (i as u64 + 1)) as usize;
        order.swap(i, j);
    }
    let order = &order[..n];
    let (bridge, rest) = if shape == SHAPE_BRIDGE {
        (Some(order[n - 1]), &order[..n - 1])
    } else {
        (None, order)
    };
    let m = rest.len();
    let size = if shape == SHAPE_ISOLATE {
        1
    } else {
        1 + (d(PSUB_SIZE, 0) % (m as u64 - 1)) as usize
    };
    let bits = |s: &[usize]| s.iter().fold(0u64, |b, &k| b | 1 << k);
    Some((
        bits(&rest[..size]),
        bits(&rest[size..]),
        bridge.map_or(0, |k| 1 << k),
    ))
}

/// `MachineTab::status` of a machine whose first process had not ended when the run did.
pub const RUNNING: u64 = u64::MAX;

pub const MACHINE_TAB_OFFSET: usize =
    (crate::ctl::SCAN_TAB_OFFSET + crate::ctl::SCAN_TAB_SIZE + 0xFFF) & !0xFFF;
pub const MACHINE_TAB_SIZE: usize = core::mem::size_of::<MachineTab>();

impl MachineTab {
    /// # Safety
    /// `ctl_base` must point at a full control region of `CTL_SIZE` bytes.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn at<'a>(ctl_base: *mut u8) -> &'a mut MachineTab {
        &mut *(ctl_base.add(MACHINE_TAB_OFFSET) as *mut MachineTab)
    }

    pub fn count(&self) -> usize {
        (self.n as usize).min(MAX_MACHINES)
    }

    /// Machine `i`'s disk (`i` > 0; the launcher leaves room for a NUL).
    pub fn work_path(&self, i: usize) -> &[u8] {
        let w = &self.work[i.min(MAX_MACHINES - 1)];
        match &w[..w.iter().position(|&c| c == 0).unwrap_or(w.len())] {
            // Never empty: an empty work path would put every path on the disk.
            b"" => b"/work",
            p => p,
        }
    }

    pub fn name(&self, i: usize) -> &[u8] {
        &self.names[i][..(self.name_len[i] as usize).min(NAME_MAX)]
    }

    /// Set the table (the launcher): `names[0]` is main's.
    pub fn set<'a>(&mut self, names: impl Iterator<Item = &'a [u8]>) {
        let mut n = 0;
        for (i, nm) in names.take(MAX_MACHINES).enumerate() {
            let k = nm.len().min(NAME_MAX);
            self.names[i] = [0; NAME_MAX];
            self.names[i][..k].copy_from_slice(&nm[..k]);
            self.name_len[i] = k as u64;
            n = i + 1;
        }
        self.n = n as u64;
    }

    fn find(&self, name: &[u8]) -> Option<usize> {
        (0..self.count()).find(|&i| self.name(i) == name)
    }
}

/// Is `s` a machine name: 1 to `NAME_MAX` letters, digits and `-`, starting with a letter.
pub fn valid_name(s: &[u8]) -> bool {
    (1..=NAME_MAX).contains(&s.len())
        && s[0].is_ascii_alphabetic()
        && s.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
}

/// `Op::Net` verbs.
pub const NET_CUT: u64 = 1;
pub const NET_HEAL: u64 = 2;
/// `Op::Machine` verbs.
pub const MACHINE_KILL: u64 = 1;
pub const MACHINE_START: u64 = 2;
/// A crash of the machine.
pub const MACHINE_CRASH: u64 = 3;
/// Freeze every thread of the machine, and end that.
pub const MACHINE_PAUSE: u64 = 4;
pub const MACHINE_RESUME: u64 = 5;
/// `clock NAME DELTA`: `Op::Machine` [`CLOCK_STEP`, machine, delta ns (two's complement)].
pub const CLOCK_STEP: u64 = 6;
/// `DEC_MACHINE_CLOCK`'s how: a boot's skew, or the script's step.
pub const CLK_SKEW: u64 = 1;
pub const CLK_STEP: u64 = 2;
/// A step's limit either way (one year).
pub const CLOCK_STEP_MAX_NS: u64 = 366 * 86_400 * 1_000_000_000;

const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const EINVAL: i64 = 22;

/// A parsed control call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    /// `NET_CUT` or `NET_HEAL` from the machines of `from` to those of `to` (bit sets), and
    /// back when `both`. A heal with both sets empty heals every scripted cut.
    Net {
        verb: u64,
        from: u64,
        to: u64,
        both: bool,
    },
    /// `MACHINE_KILL` (its processes), `MACHINE_CRASH` (its machine), `MACHINE_START`, `MACHINE_PAUSE` or
    /// `MACHINE_RESUME`, of machine `machine`.
    Machine { verb: u64, machine: usize },
    /// `clock`: machine `machine`'s realtime clock moves by `delta` ns.
    Clock { machine: usize, delta: i64 },
    /// `settle`: the seed's faults end; the call returns once every machine is ready, or the
    /// run ends `liveness` after `limit_ns` of virtual time (`ctl::LIFE_SETTLE`).
    Settle { limit_ns: u64 },
}

/// `settle`'s default limit (ns of virtual time).
pub const SETTLE_LIMIT_NS: u64 = 60_000_000_000;

/// Why a control call is refused: the errno (positive) and a reason for `patina ctl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub errno: i64,
    pub why: &'static str,
}

const fn no(errno: i64, why: &'static str) -> Refusal {
    Refusal { errno, why }
}

/// The words of a control call, from a process of machine `machine`.
pub fn parse(text: &[u8], tab: &MachineTab, machine: usize) -> Result<Control, Refusal> {
    let mut w = [&[][..]; 8];
    let mut n = 0;
    for x in text
        .split(|c| c.is_ascii_whitespace())
        .filter(|x| !x.is_empty())
    {
        if n == w.len() {
            return Err(no(EINVAL, "too many words"));
        }
        w[n] = x;
        n += 1;
    }
    let w = &w[..n];
    let verb = match w.first() {
        Some(v) => *v,
        None => return Err(no(EINVAL, USAGE)),
    };
    if !matches!(
        verb,
        b"partition"
            | b"heal"
            | b"crash"
            | b"kill"
            | b"start"
            | b"pause"
            | b"resume"
            | b"clock"
            | b"settle"
    ) {
        return Err(no(EINVAL, USAGE));
    }
    if verb == b"settle" {
        if machine != 0 {
            return Err(no(EPERM, "only main may call"));
        }
        let limit_ns = match w {
            [_] => SETTLE_LIMIT_NS,
            [_, s] => secs(s).ok_or(no(
                EINVAL,
                "settle: the limit is a whole number of seconds, at most a year",
            ))?,
            _ => return Err(no(EINVAL, USAGE)),
        };
        return Ok(Control::Settle { limit_ns });
    }
    if tab.count() == 0 {
        return Err(no(EINVAL, "the run has no machines to act on"));
    }
    if machine != 0 {
        return Err(no(EPERM, "only main may call"));
    }
    let target = |name: &[u8]| match tab.find(name) {
        Some(0) => Err(no(
            EINVAL,
            "main is not a machine to act on (its clock is the run's virtual time)",
        )),
        Some(k) => Ok(k),
        None if valid_name(name) => Err(no(ENOENT, "no machine of that name")),
        None => Err(no(EINVAL, "not a machine name")),
    };
    match w {
        [b"partition" | b"heal", rest @ ..] => {
            let verb = if verb == b"heal" { NET_HEAL } else { NET_CUT };
            let (a, b, both) = match rest {
                [] if verb == NET_HEAL => {
                    return Ok(Control::Net {
                        verb,
                        from: 0,
                        to: 0,
                        both: true,
                    })
                }
                [b"--from", a, b"--to", b] => (*a, *b, false),
                [a, b] if !a.starts_with(b"-") && !b.starts_with(b"-") => (*a, *b, true),
                _ => {
                    return Err(no(
                        EINVAL,
                        "expected: partition|heal A B, or partition|heal --from A --to B",
                    ))
                }
            };
            let from = set(a, tab, None)?;
            let to = set(b, tab, Some(from))?;
            let from = if a == b"rest" {
                set(a, tab, Some(to))?
            } else {
                from
            };
            if from == 0 || to == 0 {
                return Err(no(EINVAL, "a set names no machine"));
            }
            Ok(Control::Net {
                verb,
                from,
                to,
                both,
            })
        }
        [b"clock", name, d] => {
            let delta = step(d).ok_or(no(
                EINVAL,
                "clock: the change is a whole number of s or ms, signed, at most a year",
            ))?;
            Ok(Control::Clock {
                machine: target(name)?,
                delta,
            })
        }
        [v, name] if *v != b"clock" => {
            let verb = match *v {
                b"crash" => MACHINE_CRASH,
                b"kill" => MACHINE_KILL,
                b"start" => MACHINE_START,
                b"pause" => MACHINE_PAUSE,
                _ => MACHINE_RESUME,
            };
            Ok(Control::Machine {
                verb,
                machine: target(name)?,
            })
        }
        _ => Err(no(EINVAL, USAGE)),
    }
}

/// What a control call may say.
const USAGE: &str = "expected: partition A B, partition --from A --to B, heal [A B], crash MACHINE, \
                     kill MACHINE, start MACHINE, pause MACHINE, resume MACHINE, clock MACHINE +Ns|-Ns|+Nms|-Nms, \
                     or settle [SECONDS]";

/// `settle`'s limit: whole seconds, at most `CLOCK_STEP_MAX_NS`, in ns.
fn secs(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 9 || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = s.iter().fold(0u64, |a, c| a * 10 + (c - b'0') as u64);
    Some(n * 1_000_000_000).filter(|&v| v <= CLOCK_STEP_MAX_NS)
}

/// A clock step's change: `+90s`, `-5s`, `250ms` (no sign: ahead), in ns, at most
/// `CLOCK_STEP_MAX_NS` either way.
fn step(d: &[u8]) -> Option<i64> {
    let (neg, d) = match d.split_first()? {
        (b'-', r) => (true, r),
        (b'+', r) => (false, r),
        _ => (false, d),
    };
    let (num, unit) = if let Some(n) = d.strip_suffix(b"ms") {
        (n, 1_000_000u64)
    } else {
        (d.strip_suffix(b"s")?, 1_000_000_000)
    };
    if num.is_empty() || num.len() > 15 || !num.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = num.iter().fold(0u64, |a, c| a * 10 + (c - b'0') as u64);
    let ns = n.checked_mul(unit).filter(|&v| v <= CLOCK_STEP_MAX_NS)? as i64;
    Some(if neg { -ns } else { ns })
}

/// A set of machines: names joined by commas, or `rest` (every machine not in `other`; `None` while
/// the other side is not known yet, which answers 0).
fn set(s: &[u8], tab: &MachineTab, other: Option<u64>) -> Result<u64, Refusal> {
    let all = (1u64 << tab.count()) - 1;
    if s == b"rest" {
        return Ok(other.map_or(0, |o| all & !o));
    }
    let mut m = 0u64;
    for name in s.split(|&c| c == b',') {
        if name == b"rest" {
            return Err(no(EINVAL, "net: rest stands alone"));
        }
        match tab.find(name) {
            Some(i) => m |= 1 << i,
            None if valid_name(name) => return Err(no(ENOENT, "net: no machine of that name")),
            None => return Err(no(EINVAL, "net: not a machine name")),
        }
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tab(names: &[&str]) -> MachineTab {
        // Every field is plain data or an atomic: all zeros is an empty table.
        let mut t: MachineTab = unsafe { core::mem::zeroed() };
        t.set(names.iter().map(|n| n.as_bytes()));
        t
    }

    #[test]
    fn words_name_sets_of_machines() {
        let t = tab(&["main", "a", "b", "c"]);
        let net = |verb, from, to, both| {
            Ok(Control::Net {
                verb,
                from,
                to,
                both,
            })
        };
        assert_eq!(
            parse(b"partition a b", &t, 0),
            net(NET_CUT, 0b10, 0b100, true)
        );
        assert_eq!(
            parse(b"  partition --from a,b --to main\n", &t, 0),
            net(NET_CUT, 0b110, 0b1, false)
        );
        // `rest` is every machine the other side does not name, on either side.
        assert_eq!(
            parse(b"partition a rest", &t, 0),
            net(NET_CUT, 0b10, 0b1101, true)
        );
        assert_eq!(
            parse(b"partition rest a", &t, 0),
            net(NET_CUT, 0b1101, 0b10, true)
        );
        assert_eq!(parse(b"heal", &t, 0), net(NET_HEAL, 0, 0, true));
        assert_eq!(
            parse(b"heal c b", &t, 0),
            net(NET_HEAL, 0b1000, 0b100, true)
        );
    }

    #[test]
    fn refusals_name_their_errno() {
        let t = tab(&["main", "a", "b"]);
        let errno = |w: &[u8], machine| parse(w, &t, machine).unwrap_err().errno;
        assert_eq!(errno(b"partition a b", 1), EPERM);
        assert_eq!(errno(b"partition a zed", 0), ENOENT);
        for bad in [
            &b"partition a"[..],
            b"partition a,,b main",
            b"partition rest rest",
            b"partition --to a --from b",
            b"partition a b c",
            b"partition",
            b"cut a b",
            b"",
            b"partition a_b main",
            b"partition rest,a b",
            // The words before the fault classes named them are not calls any more.
            b"net cut a b",
            b"net heal",
            b"machine kill a",
            b"clock step a +90s",
            b"mark setup-complete",
        ] {
            assert_eq!(errno(bad, 0), EINVAL, "{bad:?}");
        }
        assert_eq!(errno(b"crash a", 1), EPERM);
        assert_eq!(errno(b"pause main", 0), EINVAL);
        assert_eq!(errno(b"resume a", 1), EPERM);
        assert_eq!(
            parse(b"pause a", &t, 0),
            Ok(Control::Machine {
                verb: MACHINE_PAUSE,
                machine: 1
            })
        );
        assert_eq!(
            parse(b"resume b", &t, 0),
            Ok(Control::Machine {
                verb: MACHINE_RESUME,
                machine: 2
            })
        );
        assert_eq!(errno(b"kill a", 1), EPERM);
        assert_eq!(errno(b"start zed", 0), ENOENT);
        assert_eq!(errno(b"start main", 0), EINVAL);
        assert_eq!(errno(b"stop a", 0), EINVAL);
        assert_eq!(
            parse(b"kill b", &t, 0),
            Ok(Control::Machine {
                verb: MACHINE_KILL,
                machine: 2
            })
        );
        assert_eq!(
            parse(b"crash b", &t, 0),
            Ok(Control::Machine {
                verb: MACHINE_CRASH,
                machine: 2
            })
        );
        assert_eq!(
            parse(b"start a", &t, 0),
            Ok(Control::Machine {
                verb: MACHINE_START,
                machine: 1
            })
        );
        assert_eq!(errno(b"clock main +90s", 0), EINVAL);
        assert_eq!(errno(b"clock a +90s", 1), EPERM);
        assert_eq!(errno(b"clock a 1.5s", 0), EINVAL);
        assert_eq!(errno(b"clock a +9999999d", 0), EINVAL);
        assert_eq!(errno(b"clock a", 0), EINVAL);
        assert_eq!(
            parse(b"clock a -5s", &t, 0),
            Ok(Control::Clock {
                machine: 1,
                delta: -5_000_000_000
            })
        );
        assert_eq!(
            parse(b"clock b 250ms", &t, 0),
            Ok(Control::Clock {
                machine: 2,
                delta: 250_000_000
            })
        );
        // Without machines there is nothing to act on, but the faults can still settle.
        let none = tab(&[]);
        assert_eq!(parse(b"heal", &none, 0).unwrap_err().errno, EINVAL);
        assert_eq!(
            parse(b"settle", &none, 0),
            Ok(Control::Settle {
                limit_ns: SETTLE_LIMIT_NS
            })
        );
        assert_eq!(
            parse(b"settle 5", &t, 0),
            Ok(Control::Settle {
                limit_ns: 5_000_000_000
            })
        );
        assert_eq!(errno(b"settle", 1), EPERM);
        for bad in [
            &b"settle 1.5"[..],
            b"settle -1",
            b"settle 5 5",
            b"settle 99999999",
        ] {
            assert_eq!(errno(bad, 0), EINVAL, "{bad:?}");
        }
    }

    #[test]
    fn sides_are_never_empty_and_follow_the_draws() {
        let machines = [1, 2, 3, 4];
        for shape in [SHAPE_SPLIT, SHAPE_ISOLATE, SHAPE_ONEWAY, SHAPE_BRIDGE] {
            let (mut seen, mut ns) = ([(0u64, 0u64); 64], 0);
            for seed in 0..64u64 {
                let d = |sub: u64, i: u64| crate::draw::mix64(seed << 16 | sub << 8 | i);
                let (a, b, x) = sides(shape, &machines, d).unwrap();
                assert!(
                    a != 0 && b != 0 && a & b == 0 && (a | b) & x == 0,
                    "{shape} {seed}"
                );
                assert_eq!(a | b | x, 0b11110);
                if shape == SHAPE_ISOLATE {
                    assert_eq!(a.count_ones(), 1);
                }
                assert_eq!((x != 0), shape == SHAPE_BRIDGE);
                assert_eq!(sides(shape, &machines, d), Some((a, b, x)));
                if !seen[..ns].contains(&(a, b)) {
                    seen[ns] = (a, b);
                    ns += 1;
                }
            }
            assert!(ns > 3, "{shape}: {ns}");
        }
        let d = |_: u64, _: u64| 0;
        assert_eq!(sides(SHAPE_BRIDGE, &[1, 2], d), None);
        assert_eq!(sides(SHAPE_SPLIT, &[1], d), None);
        assert!(sides(SHAPE_SPLIT, &[0, 1], d).is_some());
    }

    #[test]
    fn names_are_letters_digits_and_dashes() {
        for ok in ["a", "db-1", "Primary"] {
            assert!(valid_name(ok.as_bytes()), "{ok}");
        }
        for bad in ["", "1a", "-a", "a_b", "a.b", &"x".repeat(NAME_MAX + 1)] {
            assert!(!valid_name(bad.as_bytes()), "{bad}");
        }
    }
}
