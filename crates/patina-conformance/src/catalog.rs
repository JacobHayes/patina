//! Every scenario, what it covers, and how patina is known to fail it.
//!
//! A [`Scenario`] declares the registry rows it exercises (`covers`), the rows
//! it asserts `ENOSYS` for because they are newer than the virtual ABI level
//! (`asserts_absent`), and the libc symbols its `libc` vehicle goes through.
//! The host must implement every covered row and lack every asserted-absent
//! one for its native run to be an oracle (see [`crate::host`]). A [`Gap`] is
//! a strict expected failure: the patina run must fail exactly as declared,
//! and a gap that stops matching fails its test until it is removed.
//! [`EXCLUSIONS`] are registry entries deliberately left without a scenario,
//! each with its reason; [`crate::coverage`] reports the rest.

use crate::compare::{Expected, Failure};
use crate::probe::Probe;
use crate::scenarios::{
    abi, cred, entropy, fd, fs, ipc, mem, net, proc, readiness, sched, signal, sys, thread, time,
};
use crate::vehicle::Vehicle;
use patina_dst_syscalls::Syscall;
use serde_json::Value;

/// A scenario body.
pub type Run = fn(&Probe);

pub struct Scenario {
    /// `family/name`, the probe binary's first argument.
    pub name: &'static str,
    pub run: Run,
    /// The vehicles the scenario has a shape through.
    pub vehicles: &'static [Vehicle],
    /// Rows the scenario exercises and host-checks.
    pub covers: &'static [Syscall],
    /// Rows past the virtual ABI level the scenario asserts `ENOSYS` for.
    pub asserts_absent: &'static [Syscall],
    /// libc symbols the `libc` vehicle goes through.
    pub symbols: &'static [&'static str],
    /// Those of `symbols` the scenario reaches through `dlsym`
    /// (`Probe::resolve`) rather than importing: exactly the registry's
    /// `Absent` ones, which the pre-run audit would refuse as imports.
    pub resolves: &'static [&'static str],
    /// Host capabilities beyond the covered rows the native oracle needs
    /// (detected live on the run directory; see [`crate::host::need_unmet`]).
    pub needs: &'static [Need],
    /// The oldest host kernel whose answers every check asserts, when a
    /// behaviour is newer than the rows' own `since` (an older host is no
    /// oracle and the scenario is not run).
    pub kernel_floor: Option<KernelFloor>,
    pub gaps: &'static [Gap],
    /// Facts the patina run's recorded trace must show.
    pub trace: Option<TraceFacts>,
}

impl Scenario {
    /// The gaps that apply to `vehicle`.
    pub fn gaps_for(&self, vehicle: Vehicle) -> impl Iterator<Item = &Gap> {
        self.gaps
            .iter()
            .filter(move |gap| gap.vehicles.contains(&vehicle))
    }
}

/// The defaults a scenario declaration spreads (`..DEFAULTS`).
pub const DEFAULTS: Scenario = Scenario {
    name: "",
    run: |_| {},
    vehicles: Vehicle::ALL,
    covers: &[],
    asserts_absent: &[],
    symbols: &[],
    resolves: &[],
    needs: &[],
    kernel_floor: None,
    gaps: &[],
    trace: None,
};

/// A kernel release a scenario's checks need, and the behaviour that needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelFloor {
    pub release: &'static str,
    pub why: &'static str,
}

/// A host capability a scenario's native oracle needs that a kernel
/// implementing the covered rows can still lack: a filesystem feature of the
/// run directory, or a per-user limit. Unmet, the scenario is not run (with
/// the detected reason), never passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    /// IPv6 on the loopback interface: an AF_INET6 datagram socket binds
    /// `[::1]:0` (a kernel without IPv6 answers `EAFNOSUPPORT`, IPv6 disabled
    /// on `lo` answers `EADDRNOTAVAIL`). Both are configuration a runner is
    /// set up with — every distribution kernel builds IPv6, and `lo` carries
    /// `::1` unless a sysctl disabled it — so, as with `Membarrier` and
    /// `PosixMqueue`, a prerequisite, not a machine fact.
    Ipv6Loopback,
    /// An unprivileged fanotify group with file-handle events on the run
    /// directory (Linux 5.13's unprivileged fanotify, `CONFIG_FANOTIFY`,
    /// within the caller's `max_user_groups`): the run directory's
    /// filesystem must export file handles with a non-zero fsid
    /// (`fanotify_test_fsid`).
    Fanotify,
    /// Binding to an address no interface has is refused: the host's
    /// `net.ipv4.ip_nonlocal_bind` and `net.ipv6.ip_nonlocal_bind` are 0
    /// (their default), so the `EADDRNOTAVAIL` scenarios assert is the answer.
    LocalBindOnly,
    /// `user.*` extended attributes on the run directory's filesystem, and a
    /// fresh file there listing no attribute at all (no security label the
    /// listing would carry).
    UserXattrs,
    /// One more inotify instance and one watch within the caller's
    /// `max_user_instances`/`max_user_watches`.
    Inotify,
    /// File handles (`name_to_handle_at`) on the run directory's filesystem.
    FileHandles,
    /// Whiteouts (`renameat2(RENAME_WHITEOUT)`) on the run directory's
    /// filesystem; overlayfs refuses them.
    Whiteouts,
    /// An unprivileged caller (euid ≠ 0; empty effective, permitted,
    /// inheritable and ambient capability sets): the EPERM and EACCES a
    /// scenario asserts are what capabilities bypass, and its own capability
    /// sets read back empty.
    Unprivileged,
    /// A System V shared memory segment can be created and removed
    /// (`CONFIG_SYSVIPC`; the IPC namespace's `shmmni`/`shmall`).
    SysvShm,
    /// A System V semaphore set can be created and removed (`semmni`,
    /// `semmns`).
    SysvSem,
    /// A System V message queue can be created and removed (`msgmni`).
    SysvMsg,
    /// A POSIX message queue can be created and unlinked
    /// (`CONFIG_POSIX_MQUEUE`; `RLIMIT_MSGQUEUE`, `queues_max`).
    PosixMqueue,
    /// This many pages can be locked (`RLIMIT_MEMLOCK`, or `CAP_IPC_LOCK`).
    LockedPages(usize),
    /// `MEMBARRIER_CMD_QUERY` answers (`CONFIG_MEMBARRIER`) and offers the
    /// private and global expedited commands.
    Membarrier,
    /// A memory protection key allocates (`pkey_alloc`: the CPU's keys and
    /// the kernel's support for them).
    ProtectionKeys,
    /// A shadow stack maps (`map_shadow_stack`: the CPU's user shadow
    /// stacks and the kernel's support for them).
    ShadowStack,
    /// A secret-memory page can be created and mapped (`memfd_secret`
    /// enabled, and one lockable page).
    SecretMemory,
    /// The NUMA policy rows answer (`CONFIG_NUMA`) and this task may
    /// allocate from exactly one memory node.
    OneNumaNode,
    /// The native run starts at nice 0, as the virtual kernel's process
    /// does (the harness cannot raise a priority it inherited lowered).
    NiceZero,
    /// The native run starts in the default execution domain (`PER_LINUX`,
    /// no persona flag: no `setarch` launcher).
    DefaultPersona,
    /// The legacy `sysfs(2)` row answers (`CONFIG_SYSFS_SYSCALL`).
    SysfsSyscall,
    /// The clocks resolve to 1 ns (`CONFIG_HIGH_RES_TIMERS` with a
    /// oneshot-capable clock event device), not to a tick.
    HighResTimers,
}

impl Need {
    /// A fact of the machine — its CPU, its memory topology, its kernel's
    /// build configuration — rather than a prerequisite a test host is set up
    /// to meet. Found absent, it leaves the scenario not run even where a
    /// host oracle is required (`PATINA_REQUIRE_HOST_ORACLE=1`): a runner
    /// without protection keys is no misconfigured runner. Every other need,
    /// and a hardware need that fails any other way (a limit, a permission,
    /// a broken detection), still fails there.
    pub fn hardware(self) -> bool {
        match self {
            Need::ProtectionKeys
            | Need::ShadowStack
            | Need::SecretMemory
            | Need::OneNumaNode
            | Need::SysfsSyscall
            | Need::HighResTimers => true,
            Need::UserXattrs
            | Need::Inotify
            | Need::FileHandles
            | Need::Whiteouts
            | Need::Unprivileged
            | Need::SysvShm
            | Need::SysvSem
            | Need::SysvMsg
            | Need::PosixMqueue
            | Need::LockedPages(_)
            | Need::Membarrier
            | Need::NiceZero
            | Need::DefaultPersona
            | Need::Ipv6Loopback
            | Need::Fanotify
            | Need::LocalBindOnly => false,
        }
    }
}

/// The longest a declared hang (`Failure::Hangs`) may let its patina leg run
/// before the harness starts confirming it: a quarter of the harness's 60 s
/// run deadline, so a hang gap's cost stays visible where it is declared.
pub const MAX_HANG_WITHIN: std::time::Duration = std::time::Duration::from_secs(15);

/// The family arc (docs/arcs/syscall-conformance.md §6) that models a
/// pending gap away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arc {
    Fs,
    MemoryIpc,
    TimeTimersSchedIdentity,
    SignalsThreadsProcess,
    NetworkReadiness,
}

impl Arc {
    /// The arc's name as §6 spells it.
    pub fn name(self) -> &'static str {
        match self {
            Arc::Fs => "fs",
            Arc::MemoryIpc => "memory+ipc",
            Arc::TimeTimersSchedIdentity => "time+timers+sched+identity",
            Arc::SignalsThreadsProcess => "signals+threads+process",
            Arc::NetworkReadiness => "network+readiness",
        }
    }
}

/// Why a gap exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Not modeled yet; the arc closes it.
    Pending(Arc),
    /// A permanent difference the design makes: the scenario's native oracle
    /// needs something patina refuses by design.
    ByDesign,
}

/// A strict expected failure of the patina run through `vehicles`.
pub struct Gap {
    pub status: Status,
    pub vehicles: &'static [Vehicle],
    /// What differs and the responsible code.
    pub what: &'static str,
    pub failure: Failure,
}

impl Gap {
    pub fn reason(&self) -> String {
        match self.status {
            Status::Pending(arc) => format!("pending: {} — {}", arc.name(), self.what),
            Status::ByDesign => format!("by design: {}", self.what),
        }
    }

    /// The gap as [`crate::compare::judge`] takes it, with `reason` from
    /// [`Gap::reason`].
    pub fn expected<'a>(&'a self, reason: &'a str) -> Expected<'a> {
        Expected {
            reason,
            failure: &self.failure,
        }
    }
}

/// A signal generation a recorded trace carries (`signal_generated`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Generation {
    pub signal: i32,
    pub target: Target,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Process,
    Thread,
}

impl Generation {
    /// A process-directed generation of `signal`.
    pub const fn process(signal: i32) -> Self {
        Generation {
            signal,
            target: Target::Process,
        }
    }

    /// A thread-directed generation of `signal`.
    pub const fn thread(signal: i32) -> Self {
        Generation {
            signal,
            target: Target::Thread,
        }
    }
}

/// What a scenario's recorded patina trace must show beyond its event stream:
/// a shallow model (a process-global signal state that fires a host signal at
/// generation time) can pass every behavioural check without these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceFacts {
    /// Exactly the scenario's generations, in order.
    pub generations: &'static [Generation],
    /// At most this many `task_wake` ops directly after one generation: only
    /// the chosen target is woken.
    pub max_wakes_per_generation: Option<usize>,
}

impl TraceFacts {
    /// Check `trace events --format json` records (one JSON value per op).
    pub fn check(&self, ops: &[Value]) -> Result<(), Vec<String>> {
        let mut unmet = Vec::new();
        let recorded: Vec<Generation> = ops.iter().filter_map(generation_of).collect();
        if recorded != self.generations {
            unmet.push(format!(
                "signal_generated ops recorded {recorded:?}, the scenario generates {:?}",
                self.generations
            ));
        }
        if let Some(max) = self.max_wakes_per_generation {
            for (index, op) in ops.iter().enumerate() {
                let wakes = ops[index + 1..]
                    .iter()
                    .take_while(|next| next["kind"] == "task_wake")
                    .count();
                if op["kind"] == "signal_generated" && wakes > max {
                    unmet.push(format!(
                        "a generation woke {wakes} tasks (at most {max}: only the chosen target is woken)"
                    ));
                }
            }
        }
        if unmet.is_empty() { Ok(()) } else { Err(unmet) }
    }
}

/// A `signal_generated` op: process-directed when its `target` is the string
/// `process`, thread-directed otherwise (`{"task": N}`).
fn generation_of(op: &Value) -> Option<Generation> {
    if op["kind"] != "signal_generated" {
        return None;
    }
    let signal = i32::try_from(op["operation"]["sig"].as_u64()?).ok()?;
    let process = op["operation"]["target"]
        .as_str()
        .is_some_and(|target| target.eq_ignore_ascii_case("process"));
    Some(Generation {
        signal,
        target: if process {
            Target::Process
        } else {
            Target::Thread
        },
    })
}

/// A registry entry with no scenario, deliberately.
pub struct Exclusion {
    pub entry: Entry,
    pub reason: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    Syscall(Syscall),
    Symbol(&'static str),
}

/// Registry entries excluded from conformance coverage, with their reasons.
pub const EXCLUSIONS: &[Exclusion] = &[Exclusion {
    entry: Entry::Syscall(Syscall::N_open_by_handle_at),
    reason: "privileged: opening by handle bypasses path permission checks, so it needs CAP_DAC_READ_SEARCH in the mount's user namespace (fs/fhandle.c may_decode_fh); an unprivileged native oracle observes only the EPERM refusal. Its unprivileged half, name_to_handle_at, is covered by fs/handles",
}];

pub const SCENARIOS: &[&Scenario] = &[
    &abi::newer_than_virtual::SCENARIO,
    &cred::caps::SCENARIO,
    &cred::groups::SCENARIO,
    &cred::ids::SCENARIO,
    &entropy::getrandom::SCENARIO,
    &fd::pipes::SCENARIO,
    &fd::table::SCENARIO,
    &fs::cache::SCENARIO,
    &fs::chmod::SCENARIO,
    &fs::copy::SCENARIO,
    &fs::copy_libc::SCENARIO,
    &fs::dirent::SCENARIO,
    &fs::dirs::SCENARIO,
    &fs::fifo::SCENARIO,
    &fs::fortify::SCENARIO,
    &fs::getdents::SCENARIO,
    #[cfg(target_arch = "x86_64")]
    &fs::getdents_legacy::SCENARIO,
    &fs::handles::SCENARIO,
    &fs::inotify::SCENARIO,
    &fs::ioctl::SCENARIO,
    &fs::legacy_paths::SCENARIO,
    &fs::lfs64::SCENARIO,
    &fs::libc_io::SCENARIO,
    &fs::libc_times::SCENARIO,
    &fs::links::SCENARIO,
    &fs::metadata::SCENARIO,
    &fs::newer_than_virtual::SCENARIO,
    &fs::open_rw::SCENARIO,
    &fs::openat2::SCENARIO,
    &fs::owner::SCENARIO,
    &fs::paths::SCENARIO,
    &fs::positional_io::SCENARIO,
    &fs::posix_fadvise::SCENARIO,
    &fs::realpath::SCENARIO,
    &fs::renameat2::SCENARIO,
    &fs::size::SCENARIO,
    &fs::splice::SCENARIO,
    &fs::statfs::SCENARIO,
    &fs::statfs_fault::SCENARIO,
    &fs::statvfs::SCENARIO,
    &fs::sync::SCENARIO,
    &fs::times::SCENARIO,
    &fs::vectored_io::SCENARIO,
    &fs::xattr::SCENARIO,
    &fs::xattr_libc::SCENARIO,
    &ipc::mqueue::SCENARIO,
    &ipc::sysv_msg::SCENARIO,
    &ipc::sysv_sem::SCENARIO,
    &ipc::sysv_shm::SCENARIO,
    &mem::brk::SCENARIO,
    &mem::membarrier::SCENARIO,
    &mem::memfd::SCENARIO,
    &mem::mincore::SCENARIO,
    &mem::mlock::SCENARIO,
    &mem::mmap::SCENARIO,
    &mem::mmap_file::SCENARIO,
    &mem::mremap::SCENARIO,
    &mem::mseal::SCENARIO,
    &mem::msync::SCENARIO,
    &mem::numa::SCENARIO,
    &mem::pkeys::SCENARIO,
    &mem::process_madvise::SCENARIO,
    &mem::process_madvise_self::SCENARIO,
    &mem::protect::SCENARIO,
    &mem::remap_file_pages::SCENARIO,
    &mem::secret::SCENARIO,
    &mem::shadow_stack::SCENARIO,
    &net::fortify::SCENARIO,
    &net::getaddrinfo::SCENARIO,
    &net::getifaddrs::SCENARIO,
    &net::ifconfig::SCENARIO,
    &net::inet6::SCENARIO,
    &net::ipctl::SCENARIO,
    &net::ipopts::SCENARIO,
    &net::mmsg::SCENARIO,
    &net::msg::SCENARIO,
    &net::netlink::SCENARIO,
    &net::pending::SCENARIO,
    &net::privileged::SCENARIO,
    &net::scm::SCENARIO,
    &net::sockopt::SCENARIO,
    &net::sockopt_fault::SCENARIO,
    &net::tcp::SCENARIO,
    &net::udp::SCENARIO,
    &net::unix_dgram::SCENARIO,
    &net::unix_edges::SCENARIO,
    &net::unix_seqpacket::SCENARIO,
    &net::unix_stream::SCENARIO,
    &proc::absent::SCENARIO,
    &proc::ids::SCENARIO,
    &proc::pgrp::SCENARIO,
    &proc::prctl::SCENARIO,
    &proc::traps::SCENARIO,
    &proc::wait::SCENARIO,
    &readiness::epoll::SCENARIO,
    &readiness::epoll_edges::SCENARIO,
    &readiness::fanotify::SCENARIO,
    &readiness::inotify::SCENARIO,
    &readiness::poll::SCENARIO,
    &readiness::poll_fault::SCENARIO,
    &readiness::ppoll::SCENARIO,
    &readiness::select::SCENARIO,
    &sched::affinity::SCENARIO,
    &sched::attr::SCENARIO,
    &sched::ioprio::SCENARIO,
    &sched::policy::SCENARIO,
    &sched::priority::SCENARIO,
    &signal::altstack::SCENARIO,
    &signal::basic::SCENARIO,
    &signal::block::SCENARIO,
    &signal::core_term::SCENARIO,
    &signal::default::SCENARIO,
    &signal::default_term::SCENARIO,
    &signal::eintr::SCENARIO,
    &signal::mask::SCENARIO,
    &signal::nested::SCENARIO,
    &signal::one_wake::SCENARIO,
    &signal::per_thread::SCENARIO,
    &signal::pipe::SCENARIO,
    &signal::pipe_term::SCENARIO,
    &signal::queue::SCENARIO,
    &signal::raw_action::SCENARIO,
    &signal::resethand_term::SCENARIO,
    &signal::rt_order::SCENARIO,
    &signal::unmask::SCENARIO,
    &signal::wait::SCENARIO,
    &sys::hostname::SCENARIO,
    &sys::personality::SCENARIO,
    &sys::rlimit::SCENARIO,
    &sys::rlimit64::SCENARIO,
    #[cfg(target_arch = "x86_64")]
    &sys::sysfs::SCENARIO,
    &sys::sysinfo::SCENARIO,
    &sys::uname::SCENARIO,
    &thread::futex::SCENARIO,
    &thread::kill::SCENARIO,
    &thread::lifecycle::SCENARIO,
    &thread::main_exit::SCENARIO,
    &thread::masks::SCENARIO,
    &thread::pthread_kill::SCENARIO,
    &thread::tid_clear::SCENARIO,
    &time::clock_res::SCENARIO,
    &time::clock_set::SCENARIO,
    &time::clocks::SCENARIO,
    &time::cputime::SCENARIO,
    &time::itimer::SCENARIO,
    &time::posix_timer::SCENARIO,
    &time::timerfd::SCENARIO,
    &time::timerfd_fault::SCENARIO,
];

/// The scenario named `name`.
pub fn scenario(name: &str) -> Option<&'static Scenario> {
    SCENARIOS
        .iter()
        .copied()
        .find(|scenario| scenario.name == name)
}

/// Scenarios that exist to prove a harness check can fail, never compared
/// with patina: `planted/escape` opens a host file through `syscall(2)` for the
/// leak filter to flag.
pub fn planted(name: &str) -> Option<(&'static str, Run)> {
    match name {
        "planted/escape" => Some(("planted/escape", planted_escape)),
        _ => None,
    }
}

fn planted_escape(p: &Probe) {
    let fd = p.openat(crate::probe::AT_FDCWD, "/etc/hostname", libc::O_RDONLY, 0);
    if fd >= 0 {
        p.close(fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use patina_dst_syscalls::{Disposition, Os, SYMBOLS, SYSCALLS, SymbolStatus};
    use std::collections::BTreeSet;

    fn disposition(row: Syscall) -> Disposition {
        SYSCALLS
            .iter()
            .find(|entry| entry.id == row)
            .map(|entry| entry.disposition)
            .unwrap_or_else(|| panic!("{} has no registry row", row.name()))
    }

    #[test]
    fn scenario_names_are_unique_family_slash_name() {
        let mut seen = BTreeSet::new();
        for scenario in SCENARIOS {
            assert!(seen.insert(scenario.name), "duplicate {}", scenario.name);
            let (family, name) = scenario.name.split_once('/').expect("family/name");
            assert!(!family.is_empty() && !name.is_empty(), "{}", scenario.name);
        }
    }

    #[test]
    fn every_scenario_exercises_a_row() {
        for scenario in SCENARIOS {
            assert!(
                !scenario.covers.is_empty() || !scenario.asserts_absent.is_empty(),
                "{} covers nothing",
                scenario.name
            );
        }
    }

    #[test]
    fn covered_rows_are_in_the_virtual_abi() {
        for scenario in SCENARIOS {
            for row in scenario.covers {
                assert_ne!(
                    disposition(*row),
                    Disposition::Absent,
                    "{} covers {}, which is past the virtual ABI level (assert it absent)",
                    scenario.name,
                    row.name()
                );
            }
        }
    }

    #[test]
    fn asserted_absent_rows_are_past_the_virtual_abi() {
        for scenario in SCENARIOS {
            for row in scenario.asserts_absent {
                assert_eq!(
                    disposition(*row),
                    Disposition::Absent,
                    "{} asserts {} absent",
                    scenario.name,
                    row.name()
                );
            }
        }
    }

    #[test]
    fn named_symbols_are_registry_rows_of_this_os() {
        for scenario in SCENARIOS {
            for symbol in scenario.symbols {
                assert!(
                    SYMBOLS
                        .iter()
                        .any(|row| row.name == *symbol && row.platform.defines_on(Os::host())),
                    "{} names symbol {symbol}, which has no registry row",
                    scenario.name
                );
            }
        }
    }

    fn symbol_status(symbol: &str) -> Option<SymbolStatus> {
        SYMBOLS
            .iter()
            .find(|row| row.name == symbol && row.platform.defines_on(Os::host()))
            .map(|row| row.status)
    }

    /// A symbol reached through `dlsym` is one the shim leaves `Absent`. Once
    /// the shim defines it (the registry row moves off `Absent`), the
    /// scenario imports it directly instead: under patina `dlsym` still
    /// answers NULL for it (`__wrap_dlsym` routes only its entropy names), so
    /// the scenario would keep stopping at the lookup and never judge the
    /// new definition.
    #[test]
    fn resolved_symbols_are_absent_from_the_shim() {
        for scenario in SCENARIOS {
            for symbol in scenario.resolves {
                assert!(
                    scenario.symbols.contains(symbol),
                    "{} resolves {symbol} without naming it in `symbols`",
                    scenario.name
                );
                assert_eq!(
                    symbol_status(symbol),
                    Some(SymbolStatus::Absent),
                    "{} reaches {symbol} through dlsym, but the shim now defines it: \
                     import it directly in the scenario and drop it from `resolves`",
                    scenario.name
                );
            }
        }
    }

    /// An `Absent` symbol a scenario names is one it resolves: imported, the
    /// pre-run audit would refuse the whole probe binary.
    #[test]
    fn absent_symbols_are_resolved() {
        for scenario in SCENARIOS {
            for symbol in scenario.symbols {
                if symbol_status(symbol) == Some(SymbolStatus::Absent) {
                    assert!(
                        scenario.resolves.contains(symbol),
                        "{} names {symbol}, which the shim leaves Absent, without resolving it",
                        scenario.name
                    );
                }
            }
        }
    }

    #[test]
    fn gaps_name_vehicles_the_scenario_has() {
        for scenario in SCENARIOS {
            for gap in scenario.gaps {
                assert!(
                    !gap.vehicles.is_empty(),
                    "{}: a gap with no vehicle",
                    scenario.name
                );
                for vehicle in gap.vehicles {
                    assert!(
                        scenario.vehicles.contains(vehicle),
                        "{}: gap for {} it has no shape through",
                        scenario.name,
                        vehicle.name()
                    );
                }
            }
        }
    }

    #[test]
    fn a_vehicle_has_at_most_one_stopping_gap() {
        for scenario in SCENARIOS {
            for vehicle in scenario.vehicles {
                let stops = scenario
                    .gaps_for(*vehicle)
                    .filter(|gap| gap.failure.ends_early())
                    .count();
                assert!(
                    stops <= 1,
                    "{}[{}]: {stops} stopping gaps",
                    scenario.name,
                    vehicle.name()
                );
            }
        }
    }

    #[test]
    fn a_declared_hang_is_watched_within_the_bound() {
        for scenario in SCENARIOS {
            for gap in scenario.gaps {
                if let Some(within) = gap.failure.hang_deadline() {
                    assert!(
                        !within.is_zero() && within <= MAX_HANG_WITHIN,
                        "{}: a hang watched from {within:?} (at most {MAX_HANG_WITHIN:?})",
                        scenario.name
                    );
                }
            }
        }
    }

    /// A stopped run records no complete trace, so trace facts beside a stop
    /// would go unchecked.
    #[test]
    fn trace_facts_never_share_a_vehicle_with_a_stop() {
        for scenario in SCENARIOS.iter().filter(|scenario| scenario.trace.is_some()) {
            for vehicle in scenario.vehicles {
                assert!(
                    !scenario
                        .gaps_for(*vehicle)
                        .any(|gap| gap.failure.ends_early()),
                    "{}[{}]: trace facts and a stopping gap",
                    scenario.name,
                    vehicle.name()
                );
            }
        }
    }

    #[test]
    fn a_differing_gap_names_its_differences() {
        for scenario in SCENARIOS {
            for gap in scenario.gaps {
                if let Failure::Differs(differences) = gap.failure {
                    assert!(!differences.is_empty(), "{}: {}", scenario.name, gap.what);
                }
            }
        }
    }

    #[test]
    fn exclusions_are_unique_and_uncovered() {
        let mut seen = Vec::new();
        for exclusion in EXCLUSIONS {
            assert!(!exclusion.reason.is_empty());
            assert!(!seen.contains(&exclusion.entry), "{:?}", exclusion.entry);
            seen.push(exclusion.entry);
            for scenario in SCENARIOS {
                let covered = match exclusion.entry {
                    Entry::Syscall(row) => {
                        scenario.covers.contains(&row) || scenario.asserts_absent.contains(&row)
                    }
                    Entry::Symbol(name) => scenario.symbols.contains(&name),
                };
                assert!(
                    !covered,
                    "{:?} is excluded and covered by {}",
                    exclusion.entry, scenario.name
                );
            }
        }
    }

    fn op(kind: &str, operation: Value) -> Value {
        serde_json::json!({ "kind": kind, "operation": operation })
    }

    const ONE_PROCESS_SIGUSR1: TraceFacts = TraceFacts {
        generations: &[Generation {
            signal: libc::SIGUSR1,
            target: Target::Process,
        }],
        max_wakes_per_generation: Some(1),
    };

    #[test]
    fn trace_facts_accept_the_declared_generations() {
        let ops = [
            op(
                "signal_generated",
                serde_json::json!({ "sig": 10, "target": "process" }),
            ),
            op("task_wake", serde_json::json!({})),
        ];
        assert_eq!(ONE_PROCESS_SIGUSR1.check(&ops), Ok(()));
    }

    #[test]
    fn trace_facts_refuse_a_missing_generation() {
        assert!(ONE_PROCESS_SIGUSR1.check(&[]).is_err());
    }

    #[test]
    fn trace_facts_refuse_a_thread_directed_generation_for_a_process_one() {
        let ops = [op(
            "signal_generated",
            serde_json::json!({ "sig": 10, "target": { "task": 1 } }),
        )];
        assert!(ONE_PROCESS_SIGUSR1.check(&ops).is_err());
    }

    #[test]
    fn trace_facts_with_no_generations_refuse_a_generation() {
        const NONE: TraceFacts = TraceFacts {
            generations: &[],
            max_wakes_per_generation: None,
        };
        let ops = [op(
            "signal_generated",
            serde_json::json!({ "sig": 10, "target": "process" }),
        )];
        assert_eq!(NONE.check(&[]), Ok(()));
        assert!(NONE.check(&ops).is_err());
    }

    #[test]
    fn trace_facts_refuse_a_wake_all() {
        let ops = [
            op(
                "signal_generated",
                serde_json::json!({ "sig": 10, "target": "process" }),
            ),
            op("task_wake", serde_json::json!({})),
            op("task_wake", serde_json::json!({})),
        ];
        assert!(ONE_PROCESS_SIGUSR1.check(&ops).is_err());
    }
}
